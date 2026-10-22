use std::{
    error::Error,
    sync::{Arc, Mutex},
    time::Duration,
};

use oprf_types::{OprfKeyId, ShareEpoch, api::OprfPublicKeyWithEpoch, crypto::OprfPublicKey};
use reqwest::StatusCode;
use tokio::task::JoinSet;

/// The most recent failure of a retried request, kept so a timeout can name its cause.
#[derive(Clone, Default)]
pub struct LastError(Arc<Mutex<Option<String>>>);

impl LastError {
    fn set(&self, msg: String) {
        *self.0.lock().expect("not poisoned") = Some(msg);
    }

    fn set_err(&self, err: &dyn Error) {
        self.set(error_chain(err));
    }

    fn get(&self) -> Option<String> {
        self.0.lock().expect("not poisoned").clone()
    }
}

fn error_chain(err: &dyn Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        out.push_str(": ");
        out.push_str(&err.to_string());
        source = err.source();
    }
    out
}

/// One `url: last error` entry per request that has failed at least once.
fn describe_failures<'a>(requests: impl IntoIterator<Item = (&'a str, &'a LastError)>) -> String {
    let failures = requests
        .into_iter()
        .filter_map(|(url, last)| last.get().map(|err| format!("{url}: {err}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        "no request failed".to_owned()
    } else {
        failures.join("; ")
    }
}

async fn health_check(client: reqwest::Client, health_url: String, last_error: LastError) {
    loop {
        match client.get(&health_url).send().await {
            Err(err) => last_error.set_err(&err),
            Ok(resp) => match resp.error_for_status() {
                Err(err) => last_error.set_err(&err),
                Ok(resp) => match resp.text().await {
                    Err(err) => last_error.set_err(&err),
                    Ok(msg) if msg == "healthy" => break,
                    Ok(msg) => last_error.set(format!("unexpected health response: {msg:?}")),
                },
            },
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tracing::info!("healthy: {health_url}");
}

pub async fn service_down(
    client: &reqwest::Client,
    service: &str,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let health_url = format!("{service}/health");
    tokio::time::timeout(max_wait_time, async move {
        loop {
            if client.get(&health_url).send().await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .map_err(|_| eyre::eyre!("services not healthy in provided time: {max_wait_time:?}"))
}

pub async fn services_health_check(
    client: &reqwest::Client,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let urls = services
        .iter()
        .map(|service| format!("{service}/health"))
        .collect::<Vec<_>>();
    let last_errors = urls
        .iter()
        .map(|_| LastError::default())
        .collect::<Vec<_>>();
    let health_checks = urls
        .iter()
        .zip(&last_errors)
        .map(|(url, last)| health_check(client.clone(), url.clone(), last.clone()))
        .collect::<JoinSet<_>>();

    tokio::time::timeout(max_wait_time, health_checks.join_all())
        .await
        .map_err(|_| {
            eyre::eyre!(
                "services not healthy in provided time: {max_wait_time:?} ({})",
                describe_failures(urls.iter().map(String::as_str).zip(&last_errors))
            )
        })?;
    Ok(())
}

pub async fn load_oprf_public_key(
    client: reqwest::Client,
    oprf_key_url: String,
    epoch: ShareEpoch,
    last_error: LastError,
) -> OprfPublicKey {
    loop {
        match client
            .get(&oprf_key_url)
            .send()
            .await
            .and_then(|response| response.error_for_status())
        {
            Err(err) => last_error.set_err(&err),
            Ok(response) => match response.json::<OprfPublicKeyWithEpoch>().await {
                Err(err) => last_error.set_err(&err),
                Ok(material) if material.epoch == epoch => return material.key,
                Ok(material) => last_error.set(format!("node has epoch {}", material.epoch)),
            },
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn oprf_public_key_from_services(
    client: &reqwest::Client,
    oprf_key_id: OprfKeyId,
    epoch: ShareEpoch,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<OprfPublicKey> {
    let urls = services
        .iter()
        .map(|service| format!("{service}/oprf_pub/{oprf_key_id}"))
        .collect::<Vec<_>>();
    let last_errors = urls
        .iter()
        .map(|_| LastError::default())
        .collect::<Vec<_>>();
    let oprf_public_key_checks = urls
        .iter()
        .zip(&last_errors)
        .map(|(url, last)| load_oprf_public_key(client.clone(), url.clone(), epoch, last.clone()))
        .collect::<JoinSet<_>>();
    match tokio::time::timeout(max_wait_time, oprf_public_key_checks.join_all())
        .await
        .map_err(|_| {
            eyre::eyre!(
                "could not load OPRF material in provided time: {max_wait_time:?} ({})",
                describe_failures(urls.iter().map(String::as_str).zip(&last_errors))
            )
        }) {
        Ok(mut keys) => {
            let key = keys.pop().expect("at least one here");
            if keys.into_iter().all(|other| key == other) {
                Ok(key)
            } else {
                eyre::bail!("keys did not match for all services");
            }
        }
        Err(err) => Err(err),
    }
}
pub async fn oprf_public_key_not_known_check(
    client: reqwest::Client,
    health_url: String,
    last_error: LastError,
) {
    loop {
        match client
            .get(&health_url)
            .send()
            .await
            .and_then(|response| response.error_for_status())
        {
            Err(err) if err.status() == Some(StatusCode::NOT_FOUND) => break,
            Err(err) => last_error.set_err(&err),
            Ok(_) => last_error.set("node still knows the key".to_owned()),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn assert_key_id_unknown(
    client: &reqwest::Client,
    oprf_key_id: OprfKeyId,
    services: &[String],
    max_wait_time: Duration,
) -> eyre::Result<()> {
    let urls = services
        .iter()
        .map(|service| format!("{service}/oprf_pub/{oprf_key_id}"))
        .collect::<Vec<_>>();
    let last_errors = urls
        .iter()
        .map(|_| LastError::default())
        .collect::<Vec<_>>();
    let health_checks = urls
        .iter()
        .zip(&last_errors)
        .map(|(url, last)| {
            oprf_public_key_not_known_check(client.clone(), url.clone(), last.clone())
        })
        .collect::<JoinSet<_>>();
    tokio::time::timeout(max_wait_time, health_checks.join_all())
        .await
        .map_err(|_| {
            eyre::eyre!(
                "services still have OPRF public-key {oprf_key_id} after: {max_wait_time:?} ({})",
                describe_failures(urls.iter().map(String::as_str).zip(&last_errors))
            )
        })?;
    Ok(())
}
