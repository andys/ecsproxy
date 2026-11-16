//! The Pingora proxy: hostname routing, backend selection, queueing and retries.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};

use crate::acme::Acme;
use crate::backend::{Lease, Table, normalize};

pub const MAX_RETRIES: u32 = 10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

/// Wait before retry `n` (1-based): 100ms doubling, capped at 5s; 26.3s over all ten.
pub fn backoff(n: u32) -> Duration {
    Duration::from_millis((100u64 << (n - 1).min(10)).min(5000))
}

pub struct Proxy {
    pub table: Arc<ArcSwap<Table>>,
    pub acme: Arc<Acme>,
    pub redirect: bool,
    pub timeout: Duration,
}

pub struct Ctx {
    host: String,
    deadline: Instant,
    retries: u32,
    failed: Option<SocketAddr>,
    lease: Option<Lease>,
    /// Set once response headers are on their way to the client; no retry after that.
    responded: bool,
}

fn status(code: u16, why: &'static str) -> Box<Error> {
    Error::explain(HTTPStatus(code), why)
}

async fn respond(
    session: &mut Session,
    code: u16,
    headers: &[(&'static str, &str)],
    body: &str,
) -> Result<bool> {
    let mut header = ResponseHeader::build(code, Some(headers.len() + 1))?;
    for (name, value) in headers {
        header.insert_header(*name, *value)?;
    }
    header.insert_header("Content-Length", body.len().to_string())?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true)
        .await?;
    Ok(true)
}

impl Proxy {
    /// Whether a failed attempt may still be replayed on another backend.
    /// Once a backend may have seen the request (`sent`), only idempotent methods are replayed.
    fn can_retry(&self, session: &Session, ctx: &Ctx, sent: bool) -> bool {
        let replayable = !sent || session.req_header().method.is_idempotent();
        replayable
            && !ctx.responded
            && ctx.retries < MAX_RETRIES
            && !session.as_ref().retry_buffer_truncated()
    }

    /// Decides on a retry for a failed attempt and counts it.
    fn retry(&self, session: &Session, ctx: &mut Ctx, sent: bool) -> bool {
        let retry = self.can_retry(session, ctx, sent);
        ctx.retries += retry as u32;
        retry
    }
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            host: String::new(),
            deadline: Instant::now() + self.timeout,
            retries: 0,
            failed: None,
            lease: None,
            responded: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        ctx.deadline = Instant::now() + self.timeout;
        let request = session.req_header();
        let host = request
            .uri
            .host()
            .or_else(|| request.headers.get("host")?.to_str().ok());
        ctx.host = normalize(host.unwrap_or_default());
        let tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());

        if !tls {
            if let Some(token) = request.uri.path().strip_prefix(CHALLENGE_PATH) {
                return match self.acme.http_challenge(token).await {
                    Some(auth) => {
                        respond(session, 200, &[("Content-Type", "text/plain")], &auth).await
                    }
                    None => respond(session, 404, &[], "").await,
                };
            }
            if self.redirect {
                let path = request.uri.path_and_query().map_or("/", |p| p.as_str());
                let location = format!("https://{}{path}", ctx.host);
                return respond(session, 307, &[("Location", &location)], "").await;
            }
        }
        if self.table.load().route(&ctx.host).is_none() {
            return respond(session, 404, &[], "").await;
        }
        Ok(false)
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        ctx.lease = None;
        if ctx.retries > 0 {
            let wait = backoff(ctx.retries);
            if Instant::now() + wait >= ctx.deadline {
                return Err(status(504, "request timeout while retrying"));
            }
            tokio::time::sleep(wait).await;
        }
        // Look the group up again on every attempt so retries see backends that just changed.
        let group = self
            .table
            .load()
            .route(&ctx.host)
            .cloned()
            .ok_or_else(|| status(503, "no such group"))?;
        let backend = group
            .pick(ctx.failed)
            .ok_or_else(|| status(503, "no healthy backend"))?;
        let lease = backend
            .acquire(ctx.deadline)
            .await
            .ok_or_else(|| status(504, "timed out queueing for backend"))?;
        ctx.lease = Some(lease);
        ctx.failed = Some(backend.addr);

        let remaining = ctx
            .deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_secs(1));
        let mut peer = HttpPeer::new(backend.addr, false, String::new());
        peer.options.connection_timeout = Some(CONNECT_TIMEOUT.min(remaining));
        peer.options.total_connection_timeout = Some(CONNECT_TIMEOUT.min(remaining));
        peer.options.read_timeout = Some(remaining);
        peer.options.write_timeout = Some(remaining);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream: &mut RequestHeader,
        _ctx: &mut Ctx,
    ) -> Result<()> {
        let tls = session.digest().is_some_and(|d| d.ssl_digest.is_some());
        upstream.insert_header("X-Forwarded-Proto", if tls { "https" } else { "http" })?;
        if let Some(ip) = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip().to_string())
        {
            let forwarded = match upstream
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            {
                Some(prior) => format!("{prior}, {ip}"),
                None => ip.clone(),
            };
            upstream.insert_header("X-Forwarded-For", forwarded)?;
            upstream.insert_header("X-Real-Ip", ip)?;
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let code = response.status.as_u16();
        // Turn a 5xx into an upstream error so the retry loop tries another backend; the last one passes through.
        if matches!(code, 500 | 502 | 503 | 504) && self.can_retry(session, ctx, true) {
            return Err(status(code, "retryable upstream status").into_up());
        }
        ctx.responded |= !response.status.is_informational();
        Ok(())
    }

    fn fail_to_connect(
        &self,
        session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        e.set_retry(self.retry(session, ctx, false));
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Ctx,
        _reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        let upstream = *e.esource() == ErrorSource::Upstream;
        e.set_retry(upstream && self.retry(session, ctx, true));
        e
    }

    async fn logging(&self, _session: &mut Session, _e: Option<&Error>, ctx: &mut Ctx) {
        ctx.lease = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_retries_back_off_within_thirty_seconds() {
        let waits: Vec<Duration> = (1..=MAX_RETRIES).map(backoff).collect();
        assert_eq!(waits[0], Duration::from_millis(100));
        assert!(waits.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(
            waits.iter().sum::<Duration>(),
            Duration::from_millis(26_300)
        );
    }
}
