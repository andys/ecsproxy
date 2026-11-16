//! Route53 TXT records for ACME DNS-01 challenges.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use aws_sdk_route53::Client;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use tokio::sync::Mutex;

/// How long to wait for Route53 to report a change as INSYNC on all its name servers.
const SYNC_TIMEOUT: Duration = Duration::from_secs(180);
/// Minimum time between re-listing hosted zones after a lookup miss.
const ZONE_REFRESH: Duration = Duration::from_secs(60);

pub struct Dns {
    r53: Client,
    zones: Mutex<Zones>,
}

/// Public hosted zones as (name without trailing dot, zone id), cached for the process lifetime.
#[derive(Default)]
struct Zones {
    list: Vec<(String, String)>,
    listed_at: Option<Instant>,
}

/// The zone with the longest name that is `name` or a parent of it.
pub fn best_zone<'a>(zones: &'a [(String, String)], name: &str) -> Option<&'a (String, String)> {
    zones
        .iter()
        .filter(|(zone, _)| {
            name == zone
                || name
                    .strip_suffix(zone.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
        .max_by_key(|(zone, _)| zone.len())
}

impl Dns {
    pub fn new(r53: Client) -> Self {
        Dns {
            r53,
            zones: Mutex::default(),
        }
    }

    async fn list_zones(&self) -> Result<Vec<(String, String)>> {
        let mut zones = Vec::new();
        let mut pages = self.r53.list_hosted_zones().into_paginator().send();
        while let Some(page) = pages.next().await {
            for zone in page.context("route53 ListHostedZones")?.hosted_zones {
                if zone.config.as_ref().is_some_and(|c| c.private_zone) {
                    continue;
                }
                let id = zone.id.trim_start_matches("/hostedzone/").to_string();
                zones.push((zone.name.trim_end_matches('.').to_ascii_lowercase(), id));
            }
        }
        Ok(zones)
    }

    /// Finds the hosted zone for `name` from the cache, re-listing zones on a miss.
    async fn zone_id(&self, name: &str) -> Result<String> {
        let mut cache = self.zones.lock().await;
        if let Some((_, id)) = best_zone(&cache.list, name) {
            return Ok(id.clone());
        }
        if cache.listed_at.is_none_or(|at| at.elapsed() > ZONE_REFRESH) {
            *cache = Zones {
                list: self.list_zones().await?,
                listed_at: Some(Instant::now()),
            };
        }
        match best_zone(&cache.list, name) {
            Some((_, id)) => Ok(id.clone()),
            None => bail!("no public Route53 hosted zone found for {name}"),
        }
    }

    async fn change(
        &self,
        zone: &str,
        action: ChangeAction,
        name: &str,
        values: &[String],
    ) -> Result<String> {
        let records = values
            .iter()
            .map(|v| ResourceRecord::builder().value(format!("\"{v}\"")).build());
        let set = ResourceRecordSet::builder()
            .name(name)
            .r#type(RrType::Txt)
            .ttl(60)
            .set_resource_records(Some(records.collect::<Result<_, _>>()?))
            .build()?;
        let batch = ChangeBatch::builder().changes(
            Change::builder()
                .action(action)
                .resource_record_set(set)
                .build()?,
        );
        let out = self
            .r53
            .change_resource_record_sets()
            .hosted_zone_id(zone)
            .change_batch(batch.build()?)
            .send()
            .await;
        let info = out
            .with_context(|| format!("route53 change {name}"))?
            .change_info;
        Ok(info.context("route53 returned no change info")?.id)
    }

    /// Publishes the TXT record and waits until Route53 has it on all authoritative servers.
    pub async fn set_txt(&self, name: &str, values: &[String]) -> Result<()> {
        let zone = self.zone_id(name).await?;
        let change = self
            .change(&zone, ChangeAction::Upsert, name, values)
            .await?;
        let deadline = Instant::now() + SYNC_TIMEOUT;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let info = self.r53.get_change().id(&change).send().await?.change_info;
            if info.is_some_and(|i| i.status == ChangeStatus::Insync) {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("route53 change for {name} not in sync after {SYNC_TIMEOUT:?}");
            }
        }
    }

    pub async fn delete_txt(&self, name: &str, values: &[String]) -> Result<()> {
        let zone = self.zone_id(name).await?;
        self.change(&zone, ChangeAction::Delete, name, values)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::best_zone;

    #[test]
    fn picks_the_deepest_matching_zone() {
        let zones: Vec<(String, String)> = [
            ("example.com", "A"),
            ("dev.example.com", "B"),
            ("ample.com", "C"),
        ]
        .map(|(n, i)| (n.to_string(), i.to_string()))
        .into();
        let id = |name| best_zone(&zones, name).map(|(_, id)| id.as_str());
        assert_eq!(id("_acme-challenge.example.com"), Some("A"));
        assert_eq!(id("_acme-challenge.app.dev.example.com"), Some("B"));
        assert_eq!(id("dev.example.com"), Some("B"));
        assert_eq!(id("_acme-challenge.ample.com"), Some("C"));
        assert_eq!(id("_acme-challenge.example.org"), None);
    }
}
