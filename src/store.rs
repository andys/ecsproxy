//! S3 persistence: ACME account, certificates, HTTP-01 tokens and the HA lock.

use std::time::{Duration, SystemTime};

use anyhow::{Result, anyhow};
use aws_sdk_s3::Client;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use serde::{Deserialize, Serialize};

/// How long a crashed instance can hold a lock before another takes it over.
pub const LOCK_TTL: Duration = Duration::from_secs(600);

pub struct Store {
    s3: Client,
    bucket: String,
    prefix: String,
}

#[derive(Serialize, Deserialize)]
struct Lock {
    owner: String,
    expires: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// True when S3 rejected a conditional write because another writer won.
fn lost_race<E: ProvideErrorMetadata>(err: &SdkError<E>) -> bool {
    matches!(
        err.code(),
        Some("PreconditionFailed" | "ConditionalRequestConflict")
    ) || matches!(
        err.raw_response().map(|r| r.status().as_u16()),
        Some(409 | 412)
    )
}

impl Store {
    pub fn new(s3: Client, bucket: &str, path: &str) -> Self {
        let path = path.trim_matches('/');
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        Store {
            s3,
            bucket: bucket.to_string(),
            prefix,
        }
    }

    fn key(&self, name: &str) -> String {
        format!("{}{name}", self.prefix)
    }

    async fn get_with_etag(&self, name: &str) -> Result<Option<(Vec<u8>, Option<String>)>> {
        match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .send()
            .await
        {
            Ok(out) => {
                let etag = out.e_tag().map(str::to_string);
                Ok(Some((out.body.collect().await?.to_vec(), etag)))
            }
            Err(e) if e.as_service_error().is_some_and(|e| e.is_no_such_key()) => Ok(None),
            Err(e) => Err(anyhow!(
                "s3 get {name}: {}",
                aws_sdk_s3::error::DisplayErrorContext(e)
            )),
        }
    }

    pub async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.get_with_etag(name).await?.map(|(body, _)| body))
    }

    /// Writes `name`; `if_none_match`/`if_match` make it conditional. Returns false when the condition failed.
    async fn put_if(
        &self,
        name: &str,
        body: Vec<u8>,
        new_only: bool,
        etag: Option<String>,
    ) -> Result<bool> {
        let put = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .body(body.into());
        let put = if new_only {
            put.if_none_match("*")
        } else {
            put.set_if_match(etag)
        };
        match put.send().await {
            Ok(_) => Ok(true),
            Err(e) if lost_race(&e) => Ok(false),
            Err(e) => Err(anyhow!(
                "s3 put {name}: {}",
                aws_sdk_s3::error::DisplayErrorContext(e)
            )),
        }
    }

    pub async fn put(&self, name: &str, body: Vec<u8>) -> Result<()> {
        self.put_if(name, body, false, None).await.map(|_| ())
    }

    /// Creates `name` only if it does not exist yet; false means another instance created it first.
    pub async fn put_new(&self, name: &str, body: Vec<u8>) -> Result<bool> {
        self.put_if(name, body, true, None).await
    }

    pub async fn delete(&self, name: &str) -> Result<()> {
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .send()
            .await?;
        Ok(())
    }

    /// Takes the cross-instance lock `name` with a conditional write; false means another instance holds it.
    pub async fn lock(&self, name: &str, owner: &str) -> Result<bool> {
        let key = format!("locks/{name}.json");
        let body = serde_json::to_vec(&Lock {
            owner: owner.to_string(),
            expires: unix_now() + LOCK_TTL.as_secs(),
        })?;
        if self.put_new(&key, body.clone()).await? {
            return Ok(true);
        }
        // Held: take it over only if it expired, and only if nobody else has touched it since we read it.
        let Some((held, etag)) = self.get_with_etag(&key).await? else {
            return self.put_new(&key, body).await;
        };
        let expired =
            serde_json::from_slice::<Lock>(&held).map_or(true, |lock| lock.expires < unix_now());
        if !expired || etag.is_none() {
            return Ok(false);
        }
        self.put_if(&key, body, false, etag).await
    }

    pub async fn unlock(&self, name: &str) {
        if let Err(e) = self.delete(&format!("locks/{name}.json")).await {
            log::warn!("failed to release lock {name}: {e:#}");
        }
    }
}
