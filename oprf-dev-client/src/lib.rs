use std::{
    collections::HashMap,
    path::Path,
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, UNIX_EPOCH},
};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160},
    providers::{DynProvider, Provider as _, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use eyre::Context;
use oprf_client::{
    Attestation, Connector, NodeError, OprfSessions,
    attestation::{AttestationPolicy, Expected},
};
use oprf_core::{
    ddlog_equality::shamir::{DLogCommitmentsShamir, DLogProofShareShamir},
    oprf::BlindedOprfRequest,
};
use oprf_types::{OprfKeyId, ShareEpoch, api::OprfRequest, async_trait, crypto::OprfPublicKey};
use rand::{CryptoRng, Rng, SeedableRng};
use rustls::ClientConfig;
use secrecy::ExposeSecret as _;
use serde::Serialize;
use tokio::{sync::mpsc, task::JoinSet};
use uuid::Uuid;

pub(crate) mod config;
pub use config::*;
mod contract;
pub mod health_checks;

#[async_trait::async_trait]
pub trait DevClient: Send + Sync + 'static {
    type Setup: Send + Sync + 'static + Clone;
    type RequestAuth: Clone + Serialize + Send + 'static;

    async fn setup_oprf_test(
        &self,
        config: &DevClientConfig,
        provider: DynProvider,
        client: &reqwest::Client,
    ) -> eyre::Result<Self::Setup>;

    async fn run_oprf(
        &self,
        config: &DevClientConfig,
        setup: Self::Setup,
        connector: Connector,
        attestation: &Attestation,
    ) -> eyre::Result<ShareEpoch>;

    async fn run_delegate_oprf(
        &self,
        config: &DevClientConfig,
        setup: Self::Setup,
        delegate_service: Option<String>,
        client: &reqwest::Client,
        attestation: &Attestation,
    ) -> eyre::Result<ShareEpoch>;

    async fn prepare_stress_test_item<R: Rng + CryptoRng + Send>(
        &self,
        setup: &Self::Setup,
        rng: &mut R,
    ) -> eyre::Result<StressTestItem<Self::RequestAuth>>;

    fn get_oprf_key(&self, setup: &Self::Setup) -> OprfPublicKey;
    fn get_oprf_key_id(&self, setup: &Self::Setup) -> OprfKeyId;
}

pub struct StressTestItem<OprfRequestAuth> {
    pub request_id: Uuid,
    pub blinded_query: BlindedOprfRequest,
    pub init_request: OprfRequest<OprfRequestAuth>,
    pub auth_module: String,
}

fn avg(durations: &[Duration]) -> Duration {
    let n = durations.len();
    if n != 0 {
        let total = durations.iter().sum::<Duration>();
        total / n as u32
    } else {
        Duration::ZERO
    }
}

/// Reads the pinned certificates from `pinned_certs` (a PEM file) and builds the one TLS config
/// shared by the WebSocket connector and the HTTP client. Without a file the webpki roots apply.
pub fn load_tls_config(pinned_certs: Option<&Path>) -> eyre::Result<Arc<ClientConfig>> {
    let pem = pinned_certs
        .map(|path| {
            std::fs::read_to_string(path)
                .with_context(|| format!("while reading pinned certificates {}", path.display()))
        })
        .transpose()?;
    oprf_client::tls::pinned_client_config(pem.as_deref())
        .context("while building the TLS configuration")
}

pub fn setup_connector(tls_config: &Arc<ClientConfig>) -> Connector {
    oprf_client::tls::connector(tls_config)
}

pub async fn delete_test(
    config: DevClientConfig,
    provider: DynProvider,
    client: &reqwest::Client,
) -> eyre::Result<()> {
    let registry = config.registry()?;
    tracing::info!("creating new key to delete afterwards");
    let (oprf_key_id, _) = init_key_gen(
        client,
        &config.nodes,
        registry,
        provider.clone(),
        config.max_wait_time,
    )
    .await?;
    tracing::info!("created the key - now delete it..");
    contract::delete_oprf_key_material(provider, registry, oprf_key_id).await?;
    tracing::info!("sent delete event - ping nodes to check this works");
    health_checks::assert_key_id_unknown(client, oprf_key_id, &config.nodes, config.max_wait_time)
        .await?;
    tracing::info!("successfully deleted key-material");
    Ok(())
}

pub async fn send_init_requests<OprfRequestAuth: Clone + Serialize + Send + 'static>(
    nodes: &[String],
    threshold: usize,
    connector: Connector,
    sequential: bool,
    requests: HashMap<Uuid, (OprfRequest<OprfRequestAuth>, String)>,
    attestation: &Attestation,
) -> eyre::Result<(
    HashMap<Uuid, OprfSessions>,
    HashMap<Uuid, DLogCommitmentsShamir>,
)> {
    tracing::info!("start sending init requests..");
    let n = requests.len();
    let start = Instant::now();

    let tasks = requests
        .into_iter()
        .map(|(id, (req, module))| {
            let nodes = nodes.to_vec();
            let connector = connector.clone();
            let attestation = attestation.clone();
            async move {
                let nodes = oprf_client::to_oprf_uri_many(nodes, module)
                    .context("while producing OPRF uris")?;
                let init_start = Instant::now();
                let sessions = oprf_client::init_sessions(
                    req.request_id,
                    &nodes,
                    threshold,
                    req,
                    connector,
                    &attestation,
                )
                .await
                .map_err(|errors| init_sessions_error(id, &errors))?;
                let init_duration = init_start.elapsed();
                eyre::Ok((id, sessions, init_duration))
            }
        })
        .collect();
    let init_results = run_all(tasks, sequential).await;
    let init_full_duration = start.elapsed();

    let mut sessions = HashMap::with_capacity(n);
    let mut finish_requests = HashMap::with_capacity(n);
    let mut durations = Vec::with_capacity(n);
    let mut first_error = None;
    for result in init_results {
        match result {
            Ok((id, session, duration)) => {
                let finish_request = oprf_client::generate_challenge_request(&session);
                sessions.insert(id, session);
                finish_requests.insert(id, finish_request);
                durations.push(duration);
            }
            Err(err) => {
                tracing::error!(?err, "got an error during init");
                first_error.get_or_insert(err);
            }
        }
    }

    if let Some(err) = first_error {
        eyre::bail!(
            "init did encounter errors in {} of {n} runs, the first: {err:#}",
            n - durations.len()
        );
    }

    let init_throughput = n as f64 / init_full_duration.as_secs_f64();
    let init_avg = avg(&durations);
    tracing::info!(
        "init req - total time: {init_full_duration:?} avg: {init_avg:?} throughput: {init_throughput} req/s"
    );

    Ok((sessions, finish_requests))
}

pub async fn send_finish_requests(
    mut sessions: HashMap<Uuid, OprfSessions>,
    sequential: bool,
    requests: HashMap<Uuid, DLogCommitmentsShamir>,
) -> eyre::Result<HashMap<Uuid, Vec<DLogProofShareShamir>>> {
    tracing::info!("start sending finish requests..");
    let n = requests.len();
    let start = Instant::now();

    let tasks = requests
        .into_iter()
        .map(|(id, req)| {
            let session = sessions.remove(&id).expect("is there");
            async move {
                let finish_start = Instant::now();
                let responses = oprf_client::finish_sessions(session, req.clone())
                    .await
                    .context(format!("while handling session-id: {id}"))?;
                let duration = finish_start.elapsed();
                eyre::Ok((id, responses, duration))
            }
        })
        .collect();
    let finish_results = run_all(tasks, sequential).await;
    let finish_full_duration = start.elapsed();

    let mut responses = HashMap::with_capacity(n);
    let mut durations = Vec::with_capacity(n);
    for result in finish_results {
        match result {
            Ok((id, res, duration)) => {
                responses.insert(id, res);
                durations.push(duration);
            }
            Err(err) => tracing::error!(?err, "Got an error during finish"),
        }
    }

    let final_throughput = n as f64 / finish_full_duration.as_secs_f64();
    let finish_avg = avg(&durations);
    tracing::info!(
        "finish req - total time: {finish_full_duration:?} avg: {finish_avg:?} throughput: {final_throughput} req/s"
    );

    Ok(responses)
}

/// The error of one `init_sessions` call: the attestation failures if there are any (an
/// attestation failure must not read as a generic init error), else every node error.
fn init_sessions_error(id: Uuid, errors: &[NodeError]) -> eyre::Report {
    let attestation = errors
        .iter()
        .filter_map(|err| match err {
            NodeError::Attestation(err) => Some(err.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if attestation.is_empty() {
        let all = errors.iter().map(ToString::to_string).collect::<Vec<_>>();
        eyre::eyre!(
            "Error during init-sessions for session-id: {id}: {}",
            all.join("; ")
        )
    } else {
        eyre::eyre!("{}", attestation.join("; "))
    }
}

/// Runs `tasks` and returns every result. With `sequential`, each task finishes before the next
/// one is spawned.
async fn run_all<T: Send + 'static>(
    tasks: Vec<impl Future<Output = T> + Send + 'static>,
    sequential: bool,
) -> Vec<T> {
    if !sequential {
        let mut set = JoinSet::new();
        for task in tasks {
            set.spawn(task);
        }
        return set.join_all().await;
    }
    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        let mut one = JoinSet::new();
        one.spawn(task);
        results.extend(one.join_all().await);
    }
    results
}

/// The attestation mode `config` asks for: [`Attestation::EveryCall`] with `--attest-every-call`,
/// else [`Attestation::OnDemand`]. `http` must be built from the same TLS config as the
/// WebSocket connector.
///
/// # Errors
/// If the switch is on without an expected-values file, or the file does not load.
pub fn attestation_mode(
    config: &DevClientConfig,
    http: &reqwest::Client,
) -> eyre::Result<Attestation> {
    if !config.attest_every_call {
        return Ok(Attestation::OnDemand);
    }
    let path = config.attestation_pcrs.as_deref().ok_or_else(|| {
        eyre::eyre!(
            "--attest-every-call / OPRF_DEV_CLIENT_ATTEST_EVERY_CALL needs the expected-values \
             file: set --attestation-pcrs / OPRF_DEV_CLIENT_ATTESTATION_PCRS"
        )
    })?;
    Ok(Attestation::EveryCall {
        policy: Arc::new(load_policy(path)?),
        http: http.clone(),
    })
}

fn load_policy(path: &Path) -> eyre::Result<AttestationPolicy> {
    AttestationPolicy::from_file(path).with_context(|| {
        format!(
            "while loading attestation expected-values file {}",
            path.display()
        )
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The `attest` command: attests every node `--attestation-pcrs` lists with a PCR0 and prints
/// `<url> pcr0=<hex> public_sha256=<hex> timestamp=<RFC 3339>` per node, or its failure.
///
/// # Errors
/// If the file is missing or does not load, lists no node to attest, or any attestation fails.
pub async fn attest_command(config: &DevClientConfig, http: &reqwest::Client) -> eyre::Result<()> {
    let path = config.attestation_pcrs.as_deref().ok_or_else(|| {
        eyre::eyre!(
            "the attest command needs the expected-values file: set --attestation-pcrs / \
             OPRF_DEV_CLIENT_ATTESTATION_PCRS"
        )
    })?;
    let policy = load_policy(path)?;
    let mut attempted = 0usize;
    let mut failures = Vec::new();
    for (url, expected) in policy.entries() {
        if matches!(expected, Expected::Unattested) {
            continue;
        }
        attempted += 1;
        match oprf_client::attestation::attest(http, url, &policy).await {
            Ok(Some(verified)) => println!(
                "{url} pcr0={} public_sha256={} timestamp={}",
                hex(&verified.pcr0),
                hex(&verified.public_sha256),
                humantime::format_rfc3339_millis(
                    UNIX_EPOCH + Duration::from_millis(verified.timestamp_ms)
                )
            ),
            Ok(None) => println!("{url} unattested"),
            Err(err) => {
                eprintln!("{err}");
                failures.push(err.to_string());
            }
        }
    }
    if attempted == 0 {
        eyre::bail!(
            "{} lists no node to attest (every entry is unattested)",
            path.display()
        );
    }
    if !failures.is_empty() {
        eyre::bail!(
            "{} of {attempted} attestations failed: {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

pub async fn init_key_gen(
    client: &reqwest::Client,
    nodes: &[String],
    oprf_key_registry: Address,
    provider: DynProvider,
    max_wait_time: Duration,
) -> eyre::Result<(OprfKeyId, OprfPublicKey)> {
    let oprf_key_id_u32: u32 = rand::random();
    let oprf_key_id = OprfKeyId::new(U160::from(oprf_key_id_u32));
    tracing::info!("init OPRF key gen with: {oprf_key_id}");
    contract::init_key_gen(provider, oprf_key_registry, oprf_key_id).await?;
    tracing::info!("waiting for key-gen to finish..");
    let oprf_public_key = health_checks::oprf_public_key_from_services(
        client,
        oprf_key_id,
        ShareEpoch::default(),
        nodes,
        max_wait_time,
    )
    .await?;
    tracing::info!("key-gen successful");
    Ok((oprf_key_id, oprf_public_key))
}

async fn stress_test_key_gen(
    client: &reqwest::Client,
    cmd: StressTestKeyGenCommand,
    nodes: &[String],
    oprf_key_registry: Address,
    provider: DynProvider,
    max_wait_time: Duration,
) -> eyre::Result<()> {
    // initiate key-gens and reshares
    let mut key_gens = JoinSet::new();
    for _ in 0..cmd.runs {
        let oprf_key_id_u32: u32 = rand::random();
        let oprf_key_id = OprfKeyId::new(U160::from(oprf_key_id_u32));
        tracing::debug!("init OPRF key gen with: {oprf_key_id}");
        contract::init_key_gen(provider.clone(), oprf_key_registry, oprf_key_id).await?;
        key_gens.spawn({
            let nodes = nodes.to_vec();
            let client = client.clone();
            async move {
                health_checks::oprf_public_key_from_services(
                    &client,
                    oprf_key_id,
                    ShareEpoch::default(),
                    &nodes,
                    max_wait_time,
                )
                .await?;
                eyre::Ok(oprf_key_id)
            }
        });
    }
    tracing::info!("finished init key-gens, now starting reshares");
    let mut reshares = JoinSet::new();
    while let Some(key_gen_result) = key_gens.join_next().await {
        let key_id = key_gen_result
            .expect("Can join")
            .context("Could not fetch oprf-key-gen")?;
        tracing::debug!("init OPRF reshare for {key_id}");
        contract::init_reshare(provider.clone(), oprf_key_registry, key_id).await?;
        // do an oprf to check if correct
        reshares.spawn({
            let nodes = nodes.to_vec();
            let client = client.clone();
            async move {
                health_checks::oprf_public_key_from_services(
                    &client,
                    key_id,
                    ShareEpoch::default().next(),
                    &nodes,
                    max_wait_time,
                )
                .await?;
                eyre::Ok(())
            }
        });
    }
    tracing::info!(
        "started {} key-gens + reshare - waiting to finish",
        cmd.runs
    );
    reshares
        .join_all()
        .await
        .into_iter()
        .collect::<eyre::Result<Vec<_>>>()
        .context("cannot finish reshares")?;
    Ok(())
}

async fn delegate_test<T: DevClient>(
    dev_client: T,
    config: DevClientConfig,
    cmd: DelegateTestCommand,
    setup: T::Setup,
    client: &reqwest::Client,
    attestation: &Attestation,
) -> eyre::Result<()> {
    dev_client
        .run_delegate_oprf(&config, setup, cmd.delegate_service, client, attestation)
        .await?;
    Ok(())
}

async fn stress_test<T: DevClient>(
    dev_client: T,
    config: DevClientConfig,
    cmd: StressTestOprfCommand,
    setup: T::Setup,
    connector: Connector,
    attestation: &Attestation,
) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_rng(rand::thread_rng())?;
    let StressTestOprfCommand {
        runs,
        sequential,
        skip_checks,
    } = cmd;

    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);
    for _ in 0..runs {
        let StressTestItem {
            request_id,
            blinded_query,
            init_request,
            auth_module,
        } = dev_client
            .prepare_stress_test_item(&setup, &mut rng)
            .await?;
        blinded_requests.insert(request_id, blinded_query);
        init_requests.insert(request_id, (init_request, auth_module));
    }
    tracing::info!("sending init requests..");

    let (sessions, finish_requests) = send_init_requests(
        &config.nodes,
        config.threshold,
        connector,
        sequential,
        init_requests,
        attestation,
    )
    .await?;
    tracing::info!("sending finish requests..");
    let responses = send_finish_requests(sessions, cmd.sequential, finish_requests.clone()).await?;

    if !skip_checks {
        tracing::info!("checking OPRF + proofs");
        for (id, res) in responses {
            let blinded_req = blinded_requests.get(&id).expect("is there").to_owned();
            let finish_req = finish_requests.get(&id).expect("is there").to_owned();
            let _dlog_proof = oprf_client::verify_dlog_equality(
                id,
                dev_client.get_oprf_key(&setup),
                &blinded_req,
                &res,
                finish_req,
            )?;
        }
    }
    Ok(())
}

async fn reshare_test<T: DevClient>(
    dev_client: T,
    acceptance_num: usize,
    config: DevClientConfig,
    setup: T::Setup,
    provider: DynProvider,
    connector: Connector,
    attestation: &Attestation,
) -> eyre::Result<()> {
    let registry = config.registry()?;
    let oprf_key_id = dev_client.get_oprf_key_id(&setup);
    tracing::info!("running OPRF to get current epoch..");
    let current_epoch = dev_client
        .run_oprf(&config, setup.clone(), connector.clone(), attestation)
        .await?;
    tracing::info!("current epoch: {current_epoch}");

    tracing::info!("start OPRF client task");
    let (tx, mut rx) = mpsc::channel(32);
    // we need this so that we don't get random warnings when we kill the task abruptly
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let oprf_client_task = tokio::task::spawn({
        let config = config.clone();
        let connector = connector.clone();
        let shutdown_signal = Arc::clone(&shutdown_signal);
        let setup = setup.clone();
        let attestation = attestation.clone();
        async move {
            let mut counter = 0;
            loop {
                if shutdown_signal.load(Ordering::Relaxed) {
                    break;
                }
                let result = dev_client
                    .run_oprf(&config, setup.clone(), connector.clone(), &attestation)
                    .await;
                counter += 1;
                if counter % 50 == 0 {
                    tracing::debug!("send OPRF: {}", counter);
                }
                if tx.send(result).await.is_err() {
                    break;
                }
            }
        }
    });

    tracing::info!("Doing reshare!");
    contract::init_reshare(provider.clone(), registry, oprf_key_id).await?;
    tokio::time::timeout(
        config.max_wait_time,
        wait_for_epoch(&mut rx, acceptance_num, current_epoch.next()),
    )
    .await??;

    tracing::info!("Doing reshare!");
    contract::init_reshare(provider.clone(), registry, oprf_key_id).await?;
    tokio::time::timeout(
        config.max_wait_time,
        wait_for_epoch(&mut rx, acceptance_num, current_epoch.next().next()),
    )
    .await??;
    shutdown_signal.store(true, Ordering::Relaxed);

    if tokio::time::timeout(Duration::from_secs(5), oprf_client_task)
        .await
        .is_err()
    {
        tracing::warn!("test succeeded but could not finish client tasks in 5 seconds?")
    };
    Ok(())
}

async fn wait_for_epoch(
    rx: &mut mpsc::Receiver<Result<ShareEpoch, eyre::Report>>,
    acceptance_num: usize,
    target_epoch: ShareEpoch,
) -> eyre::Result<()> {
    let mut new_epoch_found = 0;
    while let Some(result) = rx.recv().await {
        match result {
            Ok(epoch) if epoch == target_epoch => {
                new_epoch_found += 1;
                if new_epoch_found == acceptance_num {
                    tracing::info!(
                        "successfully used new epoch {} {acceptance_num} times!",
                        target_epoch
                    );
                    return Ok(());
                }
            }
            Ok(_) => continue,
            Err(err) => {
                return Err(err);
            }
        }
    }
    eyre::bail!("Channel closed without getting {acceptance_num}");
}

pub async fn run<T: DevClient>(config: DevClientConfig, dev_client: T) -> eyre::Result<()> {
    let tls_config = load_tls_config(config.tls_pinned_certs.as_deref())?;
    let client =
        oprf_client::tls::http_client(&tls_config).context("while building HTTP client")?;
    // needs only the expected-values file and the TLS settings
    if matches!(config.command, Command::Attest) {
        return attest_command(&config, &client).await;
    }
    let attestation = attestation_mode(&config, &client)?;
    let connector = setup_connector(&tls_config);

    if config.skip_health_check {
        tracing::info!("skipping health check for all nodes");
    } else {
        tracing::info!("health check for all nodes...");
        health_checks::services_health_check(&client, &config.nodes, Duration::from_secs(5))
            .await
            .context("while doing health checks")?;
        tracing::info!("everyone online..");
    }

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let wallet = EthereumWallet::from(private_key.clone());

    tracing::info!("init rpc provider..");
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(config.chain_rpc_url.expose_secret())
        .await
        .context("while connecting to RPC")?
        .erased();

    match config.command.clone() {
        Command::Test => {
            tracing::info!("running oprf-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone(), &client)
                .await?;
            tracing::info!("starting oprf computation");
            dev_client
                .run_oprf(&config, setup, connector, &attestation)
                .await?;
            tracing::info!("oprf-test successful");
        }
        Command::DeleteTest => {
            tracing::info!("running delete-test");
            delete_test(config, provider, &client).await?;
            tracing::info!("oprf delete test successful");
        }
        Command::DelegateTest(cmd) => {
            tracing::info!("running delegate-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone(), &client)
                .await?;
            delegate_test(dev_client, config, cmd, setup, &client, &attestation).await?;
            tracing::info!("oprf delegate test successful");
        }
        Command::StressTestOprf(cmd) => {
            tracing::info!("running oprf stress-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone(), &client)
                .await?;
            stress_test(dev_client, config, cmd, setup, connector, &attestation).await?;
            tracing::info!("stress-test successful");
        }
        Command::StressTestKeyGen(cmd) => {
            tracing::info!("running key-gen stress-test");
            stress_test_key_gen(
                &client,
                cmd,
                &config.nodes,
                config.registry()?,
                provider,
                config.max_wait_time,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::ReshareTest(ReshareTest { acceptance_num }) => {
            tracing::info!("running reshare-test");
            let setup = dev_client
                .setup_oprf_test(&config, provider.clone(), &client)
                .await?;
            reshare_test(
                dev_client,
                acceptance_num,
                config,
                setup,
                provider,
                connector,
                &attestation,
            )
            .await?;
            tracing::info!("reshare-test successful");
        }
        Command::Attest => {} // dispatched before the health check
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// Five tasks that record how many of them run at once.
    fn counted_tasks(
        running: &Arc<AtomicUsize>,
        peak: &Arc<AtomicUsize>,
    ) -> Vec<impl Future<Output = usize> + Send + 'static> {
        (0..5)
            .map(|i| {
                let running = Arc::clone(running);
                let peak = Arc::clone(peak);
                async move {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    running.fetch_sub(1, Ordering::SeqCst);
                    i
                }
            })
            .collect()
    }

    async fn deadline<T>(f: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("test exceeded its deadline")
    }

    #[tokio::test]
    async fn run_all_sequential_keeps_every_result_and_runs_one_at_a_time() {
        let (running, peak) = (Arc::default(), Arc::default());
        let mut results = deadline(run_all(counted_tasks(&running, &peak), true)).await;
        results.sort_unstable();
        assert_eq!(results, vec![0, 1, 2, 3, 4]);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_all_concurrent_keeps_every_result() {
        let (running, peak) = (Arc::default(), Arc::default());
        let mut results = deadline(run_all(counted_tasks(&running, &peak), false)).await;
        results.sort_unstable();
        assert_eq!(results, vec![0, 1, 2, 3, 4]);
        assert!(peak.load(Ordering::SeqCst) > 1);
    }
}
