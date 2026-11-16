//! Polls ECS for labelled containers, health checks them and publishes the routing table.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use aws_sdk_ecs::Client;
use aws_sdk_ecs::types::{DesiredStatus, HealthStatus};
use log::{info, warn};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::acme::Acme;
use crate::backend::{Backend, Group, Table};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_PORT: u16 = 8080;

/// What the proxy-* docker labels of one container definition ask for.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    pub group: String,
    pub hosts: BTreeSet<String>,
    pub port: u16,
    pub healthcheck: Option<String>,
    pub maxconns: Option<usize>,
}

/// Parses the labels; None when the container is not a proxy target or fails the constraint.
pub fn parse_labels(
    labels: &HashMap<String, String>,
    constraint: Option<&str>,
    default_group: &str,
) -> Option<Spec> {
    let label = |name: &str| labels.get(name).map(|v| v.trim()).filter(|v| !v.is_empty());
    if constraint.is_some() && label("proxy-constraint") != constraint {
        return None;
    }
    let hosts: BTreeSet<String> = label("proxy-hostname")?
        .split([',', ' '])
        .filter(|h| !h.is_empty())
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    Some(Spec {
        group: label("proxy-group").unwrap_or(default_group).to_string(),
        hosts,
        port: label("proxy-port")
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT),
        healthcheck: label("proxy-healthcheck").map(|p| format!("/{}", p.trim_start_matches('/'))),
        maxconns: label("proxy-maxconns")
            .and_then(|n| n.parse().ok())
            .filter(|n| *n > 0),
    })
}

/// A container definition we route to, and whether ECS health checks it.
struct Definition {
    container: String,
    spec: Spec,
    ecs_healthcheck: bool,
}

pub struct Discovery {
    pub ecs: Client,
    pub cluster: String,
    pub constraint: Option<String>,
    pub warmup: Duration,
    pub table: Arc<ArcSwap<Table>>,
    pub acme: Arc<Acme>,
}

#[derive(Default)]
struct State {
    /// Task definitions are immutable per revision, so each ARN is described once.
    definitions: HashMap<String, Arc<Vec<Definition>>>,
    /// Live backends by (group, address); kept across polls so counters and warmup survive.
    backends: HashMap<(String, SocketAddr), Arc<Backend>>,
    hosts: BTreeMap<String, BTreeSet<String>>,
    polled: bool,
}

#[async_trait]
impl BackgroundService for Discovery {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut state = State::default();
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = ticker.tick() => {}
            }
            // On an ECS API error keep routing to the last known backends.
            let polled = self.poll(&mut state).await;
            if let Err(e) = &polled {
                warn!("ECS poll failed: {e:#}");
            }
            self.healthcheck(&state).await;
            self.publish(&state);
            state.polled |= polled.is_ok();
        }
    }
}

impl Discovery {
    async fn definitions(&self, state: &mut State, arn: &str) -> Result<Arc<Vec<Definition>>> {
        if let Some(found) = state.definitions.get(arn) {
            return Ok(found.clone());
        }
        let out = self
            .ecs
            .describe_task_definition()
            .task_definition(arn)
            .send()
            .await?;
        let task_definition = out.task_definition().context("missing task definition")?;
        let family = task_definition.family().unwrap_or_default();
        let definitions = task_definition
            .container_definitions()
            .iter()
            .filter_map(|c| {
                Some(Definition {
                    container: c.name()?.to_string(),
                    spec: parse_labels(c.docker_labels()?, self.constraint.as_deref(), family)?,
                    ecs_healthcheck: c.health_check().is_some(),
                })
            });
        let definitions = Arc::new(definitions.collect::<Vec<_>>());
        state
            .definitions
            .insert(arn.to_string(), definitions.clone());
        Ok(definitions)
    }

    /// Lists running tasks and syncs `state.backends` with the containers ECS reports as ready.
    async fn poll(&self, state: &mut State) -> Result<()> {
        let listing = self
            .ecs
            .list_tasks()
            .cluster(&self.cluster)
            .desired_status(DesiredStatus::Running);
        let arns: Vec<String> = listing
            .into_paginator()
            .items()
            .send()
            .collect::<Result<_, _>>()
            .await?;

        let mut seen_definitions = BTreeSet::new();
        let mut found: HashMap<(String, SocketAddr), Spec> = HashMap::new();
        for chunk in arns.chunks(100) {
            let out = self
                .ecs
                .describe_tasks()
                .cluster(&self.cluster)
                .set_tasks(Some(chunk.to_vec()))
                .send()
                .await?;
            for task in out.tasks() {
                let Some(arn) = task
                    .task_definition_arn()
                    .filter(|_| task.last_status() == Some("RUNNING"))
                else {
                    continue;
                };
                seen_definitions.insert(arn.to_string());
                let definitions = self.definitions(state, arn).await?;
                for container in task.containers() {
                    let Some(def) = definitions
                        .iter()
                        .find(|d| Some(d.container.as_str()) == container.name())
                    else {
                        continue;
                    };
                    let healthy = !def.ecs_healthcheck
                        || container.health_status() == Some(&HealthStatus::Healthy);
                    let ip = container
                        .network_interfaces()
                        .iter()
                        .find_map(|n| n.private_ipv4_address()?.parse::<IpAddr>().ok());
                    if let (true, Some(ip)) = (healthy, ip) {
                        found.insert(
                            (def.spec.group.clone(), SocketAddr::new(ip, def.spec.port)),
                            def.spec.clone(),
                        );
                    }
                }
            }
        }
        state
            .definitions
            .retain(|arn, _| seen_definitions.contains(arn));

        state.backends.retain(|key, _| {
            let keep = found.contains_key(key);
            if !keep {
                info!("backend {} left group {}", key.1, key.0);
            }
            keep
        });
        state.hosts.clear();
        for (key, spec) in found {
            state
                .hosts
                .entry(key.0.clone())
                .or_default()
                .extend(spec.hosts);
            state
                .backends
                .entry(key)
                .or_insert_with_key(|(group, addr)| {
                    info!("backend {addr} joined group {group}");
                    Arc::new(Backend::new(*addr, spec.healthcheck, spec.maxconns))
                });
        }
        Ok(())
    }

    /// Runs the proxy-healthcheck probes concurrently and records each backend's availability.
    async fn healthcheck(&self, state: &State) {
        // Backends already running when the proxy starts skip the warmup, so a restart is not an outage.
        let warmup = if state.polled {
            self.warmup
        } else {
            Duration::ZERO
        };
        let mut probes = JoinSet::new();
        for backend in state.backends.values().cloned() {
            probes.spawn(async move {
                let ok = match &backend.healthcheck {
                    Some(path) => http_ok(backend.addr, path).await,
                    None => true,
                };
                (backend, ok)
            });
        }
        while let Some(Ok((backend, ok))) = probes.join_next().await {
            if backend.set_available(ok, warmup) {
                info!(
                    "backend {} is {}",
                    backend.addr,
                    if ok { "healthy" } else { "unhealthy" }
                );
            }
        }
    }

    fn publish(&self, state: &State) {
        let mut members: BTreeMap<&str, Vec<Arc<Backend>>> = BTreeMap::new();
        for ((group, _), backend) in &state.backends {
            members.entry(group).or_default().push(backend.clone());
        }
        let mut table = Table::default();
        for (name, mut backends) in members {
            backends.sort_by_key(|b| b.addr);
            let group = Arc::new(Group { backends });
            for host in state.hosts.get(name).into_iter().flatten() {
                table.hosts.insert(host.clone(), group.clone());
            }
        }
        self.table.store(Arc::new(table));
        self.acme.reconcile(
            state
                .hosts
                .values()
                .filter(|hosts| !hosts.is_empty())
                .cloned(),
        );
    }
}

/// GETs `path` and reports whether the backend answered 2xx in time.
async fn http_ok(addr: SocketAddr, path: &str) -> bool {
    let probe = async {
        let mut stream = TcpStream::connect(addr).await.ok()?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: ecsproxy\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut status = [0u8; 12];
        stream.read_exact(&mut status).await.ok()?;
        Some(status.starts_with(b"HTTP/1.") && status[8..10] == *b" 2")
    };
    tokio::time::timeout(HEALTHCHECK_TIMEOUT, probe)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_labels_with_defaults() {
        let spec = parse_labels(
            &labels(&[("proxy-hostname", "B.example.com, *.example.com")]),
            None,
            "web",
        )
        .unwrap();
        assert_eq!(spec.group, "web");
        assert_eq!(spec.port, 8080);
        assert_eq!(
            spec.hosts.iter().collect::<Vec<_>>(),
            ["*.example.com", "b.example.com"]
        );
        assert_eq!((spec.healthcheck, spec.maxconns), (None, None));

        let all = labels(&[
            ("proxy-hostname", "a.example.com"),
            ("proxy-group", "api"),
            ("proxy-port", "3000"),
            ("proxy-healthcheck", "up"),
            ("proxy-maxconns", "4"),
        ]);
        let spec = parse_labels(&all, None, "web").unwrap();
        assert_eq!(
            (spec.group.as_str(), spec.port, spec.maxconns),
            ("api", 3000, Some(4))
        );
        assert_eq!(spec.healthcheck.as_deref(), Some("/up"));
        assert!(parse_labels(&labels(&[("proxy-port", "3000")]), None, "web").is_none());
    }

    #[test]
    fn constraint_must_match_exactly() {
        let prod = labels(&[
            ("proxy-hostname", "a.example.com"),
            ("proxy-constraint", "prod"),
        ]);
        let bare = labels(&[("proxy-hostname", "a.example.com")]);
        assert!(parse_labels(&prod, Some("prod"), "g").is_some());
        assert!(parse_labels(&prod, Some("staging"), "g").is_none());
        assert!(parse_labels(&bare, Some("prod"), "g").is_none());
        assert!(parse_labels(&prod, None, "g").is_some());
    }

    #[tokio::test]
    async fn healthcheck_requires_2xx() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for status in ["204 No Content", "302 Found", "500 Internal Server Error"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                    .await;
            }
        });
        assert!(http_ok(addr, "/up").await);
        assert!(!http_ok(addr, "/up").await);
        assert!(!http_ok(addr, "/up").await);
        assert!(!http_ok(addr, "/up").await);
    }
}
