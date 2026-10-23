//! TACEO:OPRF node binary.
//!
//! Runs an OPRF node with the simple request authenticator (the requested
//! `OprfKeyId` is taken from the request as-is) and the Postgres secret manager.
//! Configured via environment variables using the `TACEO_OPRF_NODE__` prefix
//! and `__` as separator. This is the binary of the reproducible node image
//! (`build/Dockerfile.oprf-node`).

use std::{net::SocketAddr, process::ExitCode, sync::Arc, time::Duration};

use config::{Config, Environment};
use eyre::Context;
use nodes_common::postgres::PostgresConfig;
use oprf_client::tls::{connector, pinned_client_config};
use oprf_service::{
    OprfServiceBuilder, StartedServices,
    config::OprfNodeServiceConfig,
    secret_manager::{SecretManagerService, postgres::PostgresSecretManager},
};
use serde::Deserialize;
use url::Url;

use crate::{simple_authenticator::ExampleOprfRequestAuthenticator, tls::NodeTlsConfig};

mod simple_authenticator;
mod tls;

/// The top-level configuration for the OPRF node binary.
/// Loads the node configuration from environment variables.
/// Configured via environment variables using the `TACEO_OPRF_NODE__` prefix and `__` as separator.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct OprfNodeConfig {
    /// The bind addr of the AXUM server
    #[serde(default = "default_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Max wait time the service waits for its workers during shutdown.
    #[serde(default = "default_max_wait_shutdown")]
    #[serde(with = "humantime_serde")]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF service config
    #[serde(rename = "service")]
    pub node_config: OprfNodeServiceConfig,

    /// The postgres config for the secret-manager
    #[serde(rename = "postgres")]
    pub postgres_config: PostgresConfig,

    /// The http base urls of the other OPRF nodes to delegate requests to.
    pub node_urls: Vec<Url>,

    /// Serve TLS with this certificate and key. Without it the node serves plain HTTP.
    #[serde(default)]
    pub tls: Option<NodeTlsConfig>,

    /// PEM bundle of certificates the delegation connections accept (pinned, no CA fallback).
    /// Without it the usual webpki-roots verification applies.
    #[serde(default)]
    pub tls_pinned_certs: Option<String>,

    /// Loopback address of the enclave launcher's attestation server. Without it
    /// `GET /attestation` answers 503.
    #[serde(default)]
    pub attestation_launcher: Option<SocketAddr>,
}

fn default_bind_addr() -> SocketAddr {
    "0.0.0.0:4321".parse().expect("valid SocketAddr")
}

fn default_max_wait_shutdown() -> Duration {
    Duration::from_secs(10)
}

fn env_source() -> Environment {
    Environment::with_prefix("TACEO_OPRF_NODE")
        .separator("__")
        .list_separator(",")
        .with_list_parse_key("rpc.http_urls")
        .with_list_parse_key("node_urls")
        .try_parsing(true)
}

/// Loads the node configuration from the environment.
///
/// # Errors
///
/// Returns an error if the environment configuration cannot be built or parsed.
pub fn load_example_config() -> eyre::Result<OprfNodeConfig> {
    let cfg = Config::builder().add_source(env_source());

    cfg.build()
        .context("while building from config")?
        .try_deserialize()
        .context("while parsing config")
}

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let _guard = telemetry_batteries::init()?;

    tracing::info!("{}", nodes_common::version_info!());

    let config = load_example_config()?;
    tracing::info!("starting oprf-service with config: {config:#?}");

    // Load the postgres secret manager.
    let secret_manager = Arc::new(
        PostgresSecretManager::init(&config.postgres_config)
            .await
            .context("while starting postgres secret-manager")?,
    );

    let result = start_service(
        config,
        secret_manager,
        nodes_common::default_shutdown_signal(),
    )
    .await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            // we don't want to double print the error therefore we just return FAILURE
            tracing::error!(?err, "oprf-service exited with error");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Starts the OPRF node and waits for it to shut down.
///
/// # Errors
///
/// Returns an error if service initialization, networking, or shutdown fails.
pub async fn start_service(
    config: OprfNodeConfig,
    secret_manager: SecretManagerService,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> eyre::Result<()> {
    let (cancellation_token, _) = nodes_common::spawn_shutdown_task(shutdown_signal);

    let tls = match &config.tls {
        Some(tls) => Some(tls.rustls_config().await?),
        None => None,
    };
    let delegate_connector = connector(
        &pinned_client_config(config.tls_pinned_certs.as_deref())
            .context("while building the delegation TLS config")?,
    );

    tracing::info!("loading node-information from secret-manager..");
    let node_information = secret_manager
        .load_node_information()
        .await
        .context("while loading node information")?;
    tracing::info!("node information: {node_information:#?}");

    tracing::info!("init oprf service..");
    let oprf_service_router = OprfServiceBuilder::init(
        config.node_config,
        secret_manager,
        StartedServices::default(),
        &node_information,
        nodes_common::version_info!(),
    )
    .module_with_delegate(
        "/example",
        Arc::new(ExampleOprfRequestAuthenticator),
        oprf_client::to_oprf_uri_many(config.node_urls, "example")?,
        delegate_connector,
    )
    .build()
    .merge(taceo_oprf_enclave_attestation::router(
        config.attestation_launcher,
    ));

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    let axum_cancel_token = cancellation_token.clone();
    let server = tokio::spawn(async move {
        tracing::info!(
            "starting axum server on {}",
            listener
                .local_addr()
                .map_or_else(|_| String::from("invalid addr"), |addr| addr.to_string())
        );
        let axum_shutdown_signal = axum_cancel_token.clone();
        let axum_result = tls::serve(listener, oprf_service_router, tls, async move {
            axum_shutdown_signal.cancelled().await;
        })
        .await;
        tracing::info!("axum server shutdown");
        if let Err(err) = axum_result {
            tracing::error!(%err, "got error from axum");
        }
        // we cancel the token in case axum encountered an error to shutdown the service
        axum_cancel_token.cancel();
    });

    tracing::info!("everything started successfully - now waiting for shutdown...");
    cancellation_token.cancelled().await;

    tracing::info!(
        "waiting for shutdown of services (max wait time {:?})..",
        config.max_wait_time_shutdown
    );
    match tokio::time::timeout(config.max_wait_time_shutdown, server).await {
        Ok(Ok(())) => {
            tracing::info!("successfully finished shutdown in time");
            Ok(())
        }
        Ok(Err(err)) => Err(eyre::Report::from(err)),
        Err(_) => eyre::bail!("could not finish shutdown in time"),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test code"
)]
mod tests {
    use std::collections::HashMap;

    use super::{OprfNodeConfig, env_source};

    fn load(extra: Option<(&str, &str)>) -> OprfNodeConfig {
        let mut env = HashMap::from([
            ("TACEO_OPRF_NODE__SERVICE__ENVIRONMENT", "dev"),
            ("TACEO_OPRF_NODE__SERVICE__VERSION_REQ", ">=0.0.0"),
            (
                "TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING",
                "postgres://x",
            ),
            ("TACEO_OPRF_NODE__NODE_URLS", "http://127.0.0.1:1"),
        ]);
        env.extend(extra);
        let env = env
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        config::Config::builder()
            .add_source(env_source().source(Some(env)))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }

    #[test]
    fn config_reads_attestation_launcher() {
        let cfg = load(Some((
            "TACEO_OPRF_NODE__ATTESTATION_LAUNCHER",
            "127.0.0.1:9901",
        )));
        assert_eq!(
            cfg.attestation_launcher,
            Some("127.0.0.1:9901".parse().unwrap())
        );
        assert_eq!(load(None).attestation_launcher, None);
    }
}
