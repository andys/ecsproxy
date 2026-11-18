//! ecsproxy: a reverse HTTP proxy for ECS Fargate services, built on Pingora.

mod acme;
mod backend;
mod discovery;
mod dns;
mod proxy;
mod store;
mod tls;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use aws_config::BehaviorVersion;
use aws_config::default_provider::credentials::DefaultCredentialsChain;
use aws_config::ecs::EcsCredentialsProvider;
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_config::meta::credentials::CredentialsProviderChain;
use clap::Parser;
use pingora::listeners::tls::TlsSettings;
use pingora::server::Server;
use pingora::server::configuration::ServerConf;
use pingora::services::background::background_service;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// ECS cluster to discover containers in
    #[arg(long, env = "ECS_CLUSTER")]
    cluster: String,
    /// S3 bucket that stores the ACME account, certificates and locks
    #[arg(long)]
    s3_bucket: String,
    /// Key prefix inside the bucket
    #[arg(long, default_value = "ecsproxy")]
    s3_path: String,
    /// Only route to containers whose proxy-constraint label equals this value
    #[arg(long)]
    proxy_constraint: Option<String>,
    /// Redirect plain HTTP requests to HTTPS (307, path intact) instead of proxying them
    #[arg(long)]
    http_redirect: bool,
    /// Seconds a newly healthy backend waits before it receives traffic
    #[arg(long, default_value_t = 10)]
    warmup: u64,
    /// Seconds a request may spend queueing, retrying and waiting on a backend
    #[arg(long, default_value_t = 60)]
    request_timeout: u64,
    /// Contact email for the ACME account
    #[arg(long)]
    acme_email: Option<String>,
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    acme_directory: String,
    /// PEM root certificate to trust for the ACME directory (for test CAs such as Pebble)
    #[arg(long, hide = true)]
    acme_ca_cert: Option<String>,
    /// Plain HTTP listen address
    #[arg(long, default_value = "0.0.0.0:80")]
    http_listen: String,
    /// HTTPS listen address
    #[arg(long, default_value = "0.0.0.0:443")]
    https_listen: String,
    /// Worker threads; defaults to the number of CPUs
    #[arg(long)]
    threads: Option<usize>,
}

/// Task/instance role credentials first, then the standard chain (env keys, profiles, ...).
async fn aws_config() -> aws_config::SdkConfig {
    let credentials = CredentialsProviderChain::first_try(
        "EcsContainer",
        EcsCredentialsProvider::builder().build(),
    )
    .or_else(
        "Ec2InstanceMetadata",
        ImdsCredentialsProvider::builder().build(),
    )
    .or_else("Default", DefaultCredentialsChain::builder().build().await);
    aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(credentials)
        .load()
        .await
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let aws = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(aws_config());
    // Keep each CA's account and certificates apart, so switching to staging never reuses production state.
    let ca = args
        .acme_directory
        .split('/')
        .nth(2)
        .context("--acme-directory must be a URL")?;
    let store = store::Store::new(
        aws_sdk_s3::Client::new(&aws),
        &args.s3_bucket,
        &format!("{}/{ca}", args.s3_path),
    );
    let dns = dns::Dns::new(aws_sdk_route53::Client::new(&aws));

    let resolver = Arc::new(tls::CertResolver::default());
    let table = Arc::new(ArcSwap::from_pointee(backend::Table::default()));
    let acme = Arc::new(acme::Acme::new(
        args.acme_directory,
        args.acme_email,
        args.acme_ca_cert,
        store,
        dns,
        resolver.clone(),
    ));

    let threads = args
        .threads
        .or(std::thread::available_parallelism().ok().map(usize::from))
        .unwrap_or(1);
    let mut server = Server::new_with_opt_and_conf(
        None,
        ServerConf {
            threads,
            ..Default::default()
        },
    );
    server.bootstrap();

    let proxy = proxy::Proxy {
        table: table.clone(),
        acme: acme.clone(),
        redirect: args.http_redirect,
        timeout: Duration::from_secs(args.request_timeout),
    };
    let mut service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    service.add_tcp(&args.http_listen);
    let mut tls = TlsSettings::intermediate("", "").context("TLS settings")?;
    tls.set_cert_resolver(resolver);
    tls.enable_h2();
    service.add_tls_with_settings(&args.https_listen, None, tls);
    server.add_service(service);

    let discovery = discovery::Discovery {
        ecs: aws_sdk_ecs::Client::new(&aws),
        cluster: args.cluster,
        constraint: args.proxy_constraint,
        warmup: Duration::from_secs(args.warmup),
        table,
        acme,
    };
    server.add_service(background_service("ecs discovery", discovery));

    log::info!(
        "ecsproxy {} listening on {} and {}",
        env!("CARGO_PKG_VERSION"),
        args.http_listen,
        args.https_listen
    );
    server.run_forever();
}
