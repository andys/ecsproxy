//! SNI certificate resolver fed by the ACME manager.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::backend::lookup;

/// Picks the certificate for a handshake by SNI hostname; no match fails the handshake.
#[derive(Debug, Default)]
pub struct CertResolver {
    certs: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertResolver {
    /// Serves `key` for every name in `hosts`.
    pub fn install<'a>(
        &self,
        hosts: impl Iterator<Item = &'a String> + Clone,
        key: Arc<CertifiedKey>,
    ) {
        self.certs.rcu(|current| {
            let mut next = HashMap::clone(current);
            next.extend(hosts.clone().map(|h| (h.clone(), key.clone())));
            next
        });
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        lookup(&self.certs.load(), hello.server_name()?).cloned()
    }
}

/// Parses a PEM bundle (private key + chain) and returns it with the time it should be renewed.
pub fn parse_bundle(pem: &[u8]) -> Result<(Arc<CertifiedKey>, SystemTime)> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .context("bad certificate PEM")?;
    let leaf = chain.first().context("no certificate in PEM bundle")?;
    let key = PrivateKeyDer::from_pem_slice(pem).context("bad private key PEM")?;
    let key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(key)?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf).context("bad certificate")?;
    let validity = cert.validity();
    let (from, to) = (
        validity.not_before.timestamp().max(0) as u64,
        validity.not_after.timestamp().max(0) as u64,
    );
    // Renew once two thirds of the lifetime has passed, whatever lifetime the CA issues.
    let renew_at =
        SystemTime::UNIX_EPOCH + Duration::from_secs(from + to.saturating_sub(from) * 2 / 3);
    Ok((Arc::new(CertifiedKey::new(chain, key)), renew_at))
}
