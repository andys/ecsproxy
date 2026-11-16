//! Certificate lifecycle: load from S3, or issue via ACME under a cross-instance lock.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use instant_acme::{
    Account, AccountBuilder, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder,
    Order, OrderStatus, RetryPolicy,
};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use crate::dns::Dns;
use crate::store::Store;
use crate::tls::{CertResolver, parse_bundle};

/// Upper bound for one issuance; kept below the S3 lock TTL so a lock never expires mid-order.
const ISSUE_TIMEOUT: Duration = Duration::from_secs(480);
/// Extra wait after Route53 reports INSYNC before asking the CA to validate.
const DNS_SETTLE: Duration = Duration::from_secs(10);
/// How long the CA gets to validate all challenges; DNS-01 validation can take minutes.
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(300);
/// Recheck interval while another instance holds the lock.
const LOCKED_RETRY: Duration = Duration::from_secs(15);
const ACCOUNT_KEY: &str = "account.json";

pub struct Acme {
    pub directory: String,
    pub email: Option<String>,
    pub ca_cert: Option<String>,
    pub store: Store,
    pub dns: Dns,
    pub resolver: Arc<CertResolver>,
    owner: String,
    account: OnceCell<Account>,
    /// One order at a time per process keeps us well inside the CA's rate limits.
    issuing: tokio::sync::Mutex<()>,
    tokens: Mutex<HashMap<String, String>>,
    certs: Mutex<HashMap<String, CertState>>,
}

#[derive(Default)]
struct CertState {
    busy: bool,
    renew_at: Option<SystemTime>,
    retry_at: Option<Instant>,
    failures: u32,
}

enum Outcome {
    Installed(SystemTime),
    LockedElsewhere,
}

/// Stable S3 name for the certificate covering exactly this set of hostnames.
pub fn cert_id(hosts: &BTreeSet<String>) -> String {
    let joined = hosts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",");
    let hash: String = Sha256::digest(joined)
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect();
    let first = hosts
        .first()
        .map(String::as_str)
        .unwrap_or_default()
        .replace('*', "_");
    format!("{first}-{hash}")
}

/// Wait before retrying a failed issuance: 1 minute doubling up to 1 hour.
fn failure_backoff(failures: u32) -> Duration {
    Duration::from_secs(60 << failures.saturating_sub(1).min(6)).min(Duration::from_secs(3600))
}

impl Acme {
    pub fn new(
        directory: String,
        email: Option<String>,
        ca_cert: Option<String>,
        store: Store,
        dns: Dns,
        resolver: Arc<CertResolver>,
    ) -> Self {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "ecsproxy".into());
        Acme {
            directory,
            email,
            ca_cert,
            store,
            dns,
            resolver,
            owner: format!("{host}-{}-{nanos}", std::process::id()),
            account: OnceCell::new(),
            issuing: tokio::sync::Mutex::new(()),
            tokens: Mutex::new(HashMap::new()),
            certs: Mutex::new(HashMap::new()),
        }
    }

    /// Key authorization for an HTTP-01 token, whichever instance started the order.
    pub async fn http_challenge(&self, token: &str) -> Option<String> {
        if token.is_empty()
            || token.len() > 128
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        if let Some(auth) = self.tokens.lock().unwrap().get(token) {
            return Some(auth.clone());
        }
        let body = self
            .store
            .get(&format!("challenges/{token}"))
            .await
            .ok()??;
        String::from_utf8(body).ok()
    }

    /// Makes sure every hostname set has a current certificate; called after each discovery poll.
    pub fn reconcile(self: &Arc<Self>, wanted: impl Iterator<Item = BTreeSet<String>>) {
        let mut certs = self.certs.lock().unwrap();
        for hosts in wanted {
            let id = cert_id(&hosts);
            let state = certs.entry(id.clone()).or_default();
            let current = state.renew_at.is_some_and(|at| SystemTime::now() < at);
            let waiting = state.retry_at.is_some_and(|at| Instant::now() < at);
            if state.busy || current || waiting {
                continue;
            }
            state.busy = true;
            let acme = self.clone();
            tokio::spawn(async move {
                let outcome = acme.ensure(&id, &hosts).await;
                let mut certs = acme.certs.lock().unwrap();
                let state = certs.entry(id.clone()).or_default();
                state.busy = false;
                match outcome {
                    Ok(Outcome::Installed(renew_at)) => {
                        *state = CertState {
                            renew_at: Some(renew_at),
                            ..Default::default()
                        };
                    }
                    Ok(Outcome::LockedElsewhere) => {
                        state.retry_at = Some(Instant::now() + LOCKED_RETRY)
                    }
                    Err(e) => {
                        state.failures += 1;
                        let wait = failure_backoff(state.failures);
                        state.retry_at = Some(Instant::now() + wait);
                        error!("certificate {id} failed, retrying in {wait:?}: {e:#}");
                    }
                }
            });
        }
    }

    /// Loads a bundle from S3 into the resolver; returns its renewal time if it is still current.
    async fn load(&self, id: &str, hosts: &BTreeSet<String>) -> Result<Option<SystemTime>> {
        let Some(pem) = self.store.get(&format!("certs/{id}.pem")).await? else {
            return Ok(None);
        };
        let (key, renew_at) = parse_bundle(&pem)?;
        self.resolver.install(hosts.iter(), key);
        Ok((SystemTime::now() < renew_at).then_some(renew_at))
    }

    async fn ensure(&self, id: &str, hosts: &BTreeSet<String>) -> Result<Outcome> {
        if let Some(renew_at) = self.load(id, hosts).await? {
            info!("certificate {id} loaded from S3");
            return Ok(Outcome::Installed(renew_at));
        }
        if !self.store.lock(id, &self.owner).await? {
            return Ok(Outcome::LockedElsewhere);
        }
        let result = async {
            // Another instance may have finished between our first look and taking the lock.
            if let Some(renew_at) = self.load(id, hosts).await? {
                return Ok(renew_at);
            }
            info!("requesting certificate {id} for {hosts:?}");
            let pem = tokio::time::timeout(ISSUE_TIMEOUT, self.issue(hosts))
                .await
                .context("ACME order timed out")??;
            let (key, renew_at) = parse_bundle(&pem)?;
            self.store.put(&format!("certs/{id}.pem"), pem).await?;
            self.resolver.install(hosts.iter(), key);
            info!("certificate {id} issued");
            Ok(renew_at)
        }
        .await;
        self.store.unlock(id).await;
        result.map(Outcome::Installed)
    }

    fn account_builder(&self) -> Result<AccountBuilder> {
        Ok(match &self.ca_cert {
            Some(path) => Account::builder_with_root(path)?,
            None => Account::builder()?,
        })
    }

    /// The ACME account shared by all instances, created once and kept in S3.
    async fn account(&self) -> Result<&Account> {
        let load = async {
            loop {
                if let Some(json) = self.store.get(ACCOUNT_KEY).await? {
                    return Ok(self
                        .account_builder()?
                        .from_credentials(serde_json::from_slice(&json)?)
                        .await?);
                }
                let contact: Vec<String> =
                    self.email.iter().map(|e| format!("mailto:{e}")).collect();
                let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
                let new = NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                };
                let (account, credentials) = self
                    .account_builder()?
                    .create(&new, self.directory.clone(), None)
                    .await?;
                if self
                    .store
                    .put_new(ACCOUNT_KEY, serde_json::to_vec(&credentials)?)
                    .await?
                {
                    info!("created ACME account {}", account.id());
                    return anyhow::Ok(account);
                }
            }
        };
        self.account.get_or_try_init(|| load).await
    }

    async fn issue(&self, hosts: &BTreeSet<String>) -> Result<Vec<u8>> {
        let _serial = self.issuing.lock().await;
        let identifiers: Vec<Identifier> = hosts.iter().cloned().map(Identifier::Dns).collect();
        let mut order = self
            .account()
            .await?
            .new_order(&NewOrder::new(&identifiers))
            .await?;

        // Wildcards can only be validated over DNS-01; everything else uses HTTP-01.
        let mut txt: HashMap<String, Vec<String>> = HashMap::new();
        let mut tokens: Vec<(String, String)> = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            if authz.status != AuthorizationStatus::Pending {
                continue;
            }
            let Identifier::Dns(domain) = authz.identifier().identifier.clone() else {
                bail!("unexpected ACME identifier");
            };
            let kind = challenge_type(authz.wildcard);
            let challenge = authz
                .challenge(kind.clone())
                .with_context(|| format!("no {kind:?} challenge for {domain}"))?;
            let auth = challenge.key_authorization();
            if kind == ChallengeType::Dns01 {
                txt.entry(format!("_acme-challenge.{domain}"))
                    .or_default()
                    .push(auth.dns_value());
            } else {
                tokens.push((challenge.token.clone(), auth.as_str().to_string()));
            }
        }

        let result = self.complete(&mut order, &txt, &tokens).await;

        for (name, values) in &txt {
            if let Err(e) = self.dns.delete_txt(name, values).await {
                warn!("failed to remove {name}: {e:#}");
            }
        }
        for (token, _) in &tokens {
            self.tokens.lock().unwrap().remove(token);
            let _ = self.store.delete(&format!("challenges/{token}")).await;
        }
        result
    }

    /// Publishes the challenge responses, has the CA validate them and downloads the certificate.
    async fn complete(
        &self,
        order: &mut Order,
        txt: &HashMap<String, Vec<String>>,
        tokens: &[(String, String)],
    ) -> Result<Vec<u8>> {
        for (token, auth) in tokens {
            // In S3 so that whichever instance the CA's request lands on can answer it.
            self.store
                .put(&format!("challenges/{token}"), auth.clone().into_bytes())
                .await?;
            self.tokens
                .lock()
                .unwrap()
                .insert(token.clone(), auth.clone());
        }
        for (name, values) in txt {
            info!("publishing DNS-01 record {name}");
            self.dns.set_txt(name, values).await?;
        }
        if !txt.is_empty() {
            tokio::time::sleep(DNS_SETTLE).await;
        }

        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            if authz.status == AuthorizationStatus::Pending {
                let kind = challenge_type(authz.wildcard);
                authz
                    .challenge(kind)
                    .context("challenge disappeared")?
                    .set_ready()
                    .await?;
            }
        }

        let patience = RetryPolicy::new()
            .initial_delay(Duration::from_secs(2))
            .backoff(1.5);
        let status = order
            .poll_ready(&patience.timeout(VALIDATION_TIMEOUT))
            .await?;
        if status != OrderStatus::Ready {
            bail!("ACME order ended as {status:?}; check DNS and that port 80 reaches this proxy");
        }
        let key_pem = order.finalize().await?;
        let chain_pem = order
            .poll_certificate(&patience.timeout(Duration::from_secs(60)))
            .await?;
        Ok(format!("{key_pem}\n{chain_pem}").into_bytes())
    }
}

fn challenge_type(wildcard: bool) -> ChallengeType {
    if wildcard {
        ChallengeType::Dns01
    } else {
        ChallengeType::Http01
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_id_depends_on_the_whole_host_set() {
        let set = |hosts: &[&str]| hosts.iter().map(|h| h.to_string()).collect::<BTreeSet<_>>();
        let a = cert_id(&set(&["b.example.com", "a.example.com"]));
        assert_eq!(a, cert_id(&set(&["a.example.com", "b.example.com"])));
        assert_ne!(a, cert_id(&set(&["a.example.com"])));
        assert!(a.starts_with("a.example.com-"));
        assert!(cert_id(&set(&["*.example.com"])).starts_with("_.example.com-"));
    }

    #[test]
    fn failures_back_off_to_an_hour() {
        assert_eq!(failure_backoff(1), Duration::from_secs(60));
        assert_eq!(failure_backoff(2), Duration::from_secs(120));
        assert_eq!(failure_backoff(30), Duration::from_secs(3600));
    }
}
