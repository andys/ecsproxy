//! Backends, target groups and the hostname routing table.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

static START: LazyLock<Instant> = LazyLock::new(Instant::now);
static ROTOR: AtomicUsize = AtomicUsize::new(0);
const UNAVAILABLE: u64 = u64::MAX;

fn now_ms() -> u64 {
    START.elapsed().as_millis() as u64
}

/// One container: an address plus live load counters and availability.
pub struct Backend {
    pub addr: SocketAddr,
    pub healthcheck: Option<String>,
    inflight: AtomicUsize,
    queued: AtomicUsize,
    slots: Option<Arc<Semaphore>>,
    /// Milliseconds since START when this backend becomes eligible.
    ready_at: AtomicU64,
}

impl Backend {
    pub fn new(addr: SocketAddr, healthcheck: Option<String>, maxconns: Option<usize>) -> Self {
        Backend {
            addr,
            healthcheck,
            inflight: AtomicUsize::new(0),
            queued: AtomicUsize::new(0),
            slots: maxconns.map(|n| Arc::new(Semaphore::new(n.max(1)))),
            ready_at: AtomicU64::new(UNAVAILABLE),
        }
    }

    /// Records health; a backend turning healthy becomes eligible after `warmup`. Returns true on change.
    pub fn set_available(&self, available: bool, warmup: Duration) -> bool {
        let was = self.ready_at.load(Relaxed) != UNAVAILABLE;
        if available && !was {
            self.ready_at
                .store(now_ms() + warmup.as_millis() as u64, Relaxed);
        } else if !available && was {
            self.ready_at.store(UNAVAILABLE, Relaxed);
        }
        available != was
    }

    fn eligible(&self, now: u64) -> bool {
        self.ready_at.load(Relaxed) <= now
    }

    fn load(&self) -> usize {
        self.inflight.load(Relaxed) + self.queued.load(Relaxed)
    }

    /// Takes a connection slot, queueing behind proxy-maxconns until `deadline`.
    pub async fn acquire(self: &Arc<Self>, deadline: Instant) -> Option<Lease> {
        let permit = match &self.slots {
            None => None,
            Some(slots) => match slots.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    let _queued = Counted::new(&self.queued);
                    let wait = slots.clone().acquire_owned();
                    Some(
                        tokio::time::timeout_at(deadline.into(), wait)
                            .await
                            .ok()?
                            .ok()?,
                    )
                }
            },
        };
        self.inflight.fetch_add(1, Relaxed);
        Some(Lease {
            backend: self.clone(),
            _permit: permit,
        })
    }
}

/// Increments a counter for as long as it lives, so cancelled waits are not leaked.
struct Counted<'a>(&'a AtomicUsize);

impl<'a> Counted<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Relaxed);
        Counted(counter)
    }
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

/// An in-flight request on a backend; dropping it frees the slot.
pub struct Lease {
    backend: Arc<Backend>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.backend.inflight.fetch_sub(1, Relaxed);
    }
}

/// The backends sharing one proxy-group label.
pub struct Group {
    pub backends: Vec<Arc<Backend>>,
}

impl Group {
    /// First attempt: least in-flight + queued. Retries: round-robin onwards from the backend that just failed.
    pub fn pick(&self, failed: Option<SocketAddr>) -> Option<Arc<Backend>> {
        let now = now_ms();
        let eligible: Vec<&Arc<Backend>> =
            self.backends.iter().filter(|b| b.eligible(now)).collect();
        let n = eligible.len();
        if n == 0 {
            return None;
        }
        let picked = match failed {
            // `backends` is sorted, so the first address after the failed one is the next in the ring.
            Some(failed) => eligible
                .iter()
                .find(|b| b.addr > failed)
                .unwrap_or(&eligible[0]),
            None => {
                // Rotate the starting point so ties do not always land on the first backend.
                let start = ROTOR.fetch_add(1, Relaxed);
                (0..n)
                    .map(|i| eligible[(start + i) % n])
                    .min_by_key(|b| b.load())?
            }
        };
        Some(Arc::clone(picked))
    }
}

/// Immutable hostname -> group snapshot, swapped atomically after each discovery poll.
#[derive(Default)]
pub struct Table {
    pub hosts: HashMap<String, Arc<Group>>,
}

impl Table {
    pub fn route(&self, host: &str) -> Option<&Arc<Group>> {
        lookup(&self.hosts, host)
    }
}

/// Finds `host` by exact name, then by a `*.parent` wildcard.
pub fn lookup<'a, V>(map: &'a HashMap<String, V>, host: &str) -> Option<&'a V> {
    let host = normalize(host);
    map.get(host.as_str()).or_else(|| {
        let (_, parent) = host.split_once('.')?;
        map.get(format!("*.{parent}").as_str())
    })
}

/// Lowercases and strips any port and trailing dot.
pub fn normalize(host: &str) -> String {
    let host = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(port: u16, maxconns: Option<usize>) -> Arc<Backend> {
        let b = Arc::new(Backend::new(([127, 0, 0, 1], port).into(), None, maxconns));
        b.set_available(true, Duration::ZERO);
        b
    }

    #[tokio::test]
    async fn least_connections_then_round_robin() {
        let group = Group {
            backends: vec![backend(1, None), backend(2, None), backend(3, None)],
        };
        let far = Instant::now() + Duration::from_secs(5);
        let _a = group.backends[0].acquire(far).await.unwrap();
        let _b = group.backends[0].acquire(far).await.unwrap();
        let _c = group.backends[2].acquire(far).await.unwrap();
        for _ in 0..6 {
            assert_eq!(group.pick(None).unwrap().addr.port(), 2);
        }
        let next = |port: u16| {
            group
                .pick(Some(([127, 0, 0, 1], port).into()))
                .unwrap()
                .addr
                .port()
        };
        assert_eq!([next(1), next(2), next(3)], [2, 3, 1]);
        group.backends[1].set_available(false, Duration::ZERO);
        assert_eq!([next(1), next(2), next(3)], [3, 3, 1]);
    }

    #[tokio::test]
    async fn warmup_and_health_gate_eligibility() {
        let warm = backend(1, None);
        let cold = Arc::new(Backend::new(([127, 0, 0, 1], 2).into(), None, None));
        let group = Group {
            backends: vec![cold.clone(), warm.clone()],
        };
        cold.set_available(true, Duration::from_millis(80));
        assert_eq!(group.pick(None).unwrap().addr.port(), 1);
        tokio::time::sleep(Duration::from_millis(120)).await;
        warm.set_available(false, Duration::ZERO);
        assert_eq!(group.pick(None).unwrap().addr.port(), 2);
        cold.set_available(false, Duration::ZERO);
        assert!(group.pick(None).is_none());
    }

    #[tokio::test]
    async fn maxconns_queues_until_a_slot_frees() {
        let b = backend(1, Some(1));
        let first = b
            .acquire(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(
            b.acquire(Instant::now() + Duration::from_millis(50))
                .await
                .is_none()
        );
        assert_eq!(b.load(), 1);
        let waiter = tokio::spawn({
            let b = b.clone();
            async move {
                b.acquire(Instant::now() + Duration::from_secs(5))
                    .await
                    .is_some()
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(b.load(), 2);
        drop(first);
        assert!(waiter.await.unwrap());
        assert_eq!(b.load(), 0);
    }

    #[test]
    fn routes_exact_before_wildcard() {
        let map: HashMap<String, u8> = [
            ("a.example.com".to_string(), 1),
            ("*.example.com".to_string(), 2),
        ]
        .into();
        assert_eq!(lookup(&map, "A.Example.com:443"), Some(&1));
        assert_eq!(lookup(&map, "b.example.com."), Some(&2));
        assert_eq!(lookup(&map, "x.b.example.com"), None);
        assert_eq!(lookup(&map, "example.com"), None);
    }
}
