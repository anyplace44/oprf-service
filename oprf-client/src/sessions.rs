//! Handles session management of the client.
//!
//! See [`init_sessions`] and [`finish_sessions`] for more information.

use std::collections::HashMap;

use crate::NodeError;
use crate::ws::WebSocketSession;

use futures::stream::{FuturesUnordered, StreamExt};
use http::Uri;
use oprf_core::ddlog_equality::shamir::{
    DLogCommitmentsShamir, DLogProofShareShamir, PartialDLogCommitmentsShamir,
};
use oprf_types::{
    ShareEpoch,
    api::{OprfRequest, OprfResponse},
    crypto::{OprfPublicKey, PartyId},
};
use serde::Serialize;
use tracing::instrument;
use uuid::Uuid;

use crate::{Attestation, Connector};

/// Holds the active OPRF sessions with multiple nodes.
#[derive(Default)]
pub struct OprfSessions {
    pub(super) ws: Vec<WebSocketSession>,
    pub(super) party_ids: Vec<PartyId>,
    pub(super) commitments: Vec<PartialDLogCommitmentsShamir>,
    pub(super) oprf_public_keys: Vec<OprfPublicKey>,
    pub(super) epoch: ShareEpoch,
}

impl OprfSessions {
    /// Creates an empty [`OprfSessions`] with preallocated capacity.
    ///
    fn with_capacity(epoch: ShareEpoch, capacity: usize) -> Self {
        Self {
            epoch,
            ws: Vec::with_capacity(capacity),
            party_ids: Vec::with_capacity(capacity),
            commitments: Vec::with_capacity(capacity),
            oprf_public_keys: Vec::with_capacity(capacity),
        }
    }

    /// Adds a node's response to the sessions.
    fn push(&mut self, ws: WebSocketSession, response: OprfResponse) -> Result<(), String> {
        let OprfResponse {
            commitments,
            party_id,
            oprf_pub_key_with_epoch,
        } = response;
        if let Some(position) = self
            .party_ids
            .iter()
            .position(|hay| *hay == response.party_id)
        {
            return Err(self.ws[position].service.clone());
        }
        self.ws.push(ws);
        self.party_ids.push(party_id);
        self.commitments.push(commitments);
        self.oprf_public_keys.push(oprf_pub_key_with_epoch.key);
        Ok(())
    }

    /// Returns the number of sessions currently stored.
    fn len(&self) -> usize {
        self.ws.len()
    }

    /// Sorts the sessions, party IDs and commitments by party ID in ascending order.
    fn sort_by_party_id(&mut self) {
        let mut combined = self
            .ws
            .drain(..)
            .zip(self.party_ids.drain(..))
            .zip(self.commitments.drain(..))
            .zip(self.oprf_public_keys.drain(..))
            .map(|(((ws, party_id), commitments), oprf_public_key)| {
                (ws, party_id, commitments, oprf_public_key)
            })
            .collect::<Vec<_>>();
        combined.sort_by_key(|(_, party_id, _, _)| *party_id);
        for (ws, party_id, commitments, oprf_public_key) in combined {
            self.ws.push(ws);
            self.party_ids.push(party_id);
            self.commitments.push(commitments);
            self.oprf_public_keys.push(oprf_public_key);
        }
    }
}

/// Tries to establish a web-socket connection to the given service. On success sends the provided `req` to the service and reads the [`OprfResponse`].
///
/// With [`Attestation::EveryCall`], the service is attested first (fresh nonce); on failure
/// nothing is opened and the error is [`NodeError::Attestation`].
///
/// Returns the [`WebSocketSession`] and the response on success.
#[instrument(level = "trace", skip(req, connector, attestation))]
async fn init_session<Auth: Serialize>(
    service: Uri,
    request_id: Uuid,
    req: OprfRequest<Auth>,
    connector: Connector,
    attestation: &Attestation,
) -> Result<(WebSocketSession, OprfResponse), NodeError> {
    attest_service(&service, attestation).await?;
    let mut session = WebSocketSession::new(service, request_id, connector).await?;
    session.send(req).await?;
    let response = session.read::<OprfResponse>().await?;
    Ok((session, response))
}

#[cfg(not(target_arch = "wasm32"))]
async fn attest_service(service: &Uri, attestation: &Attestation) -> Result<(), NodeError> {
    let Attestation::EveryCall { policy, http } = attestation else {
        return Ok(());
    };
    let url = url::Url::parse(&service.to_string()).map_err(|err| {
        NodeError::Attestation(crate::attestation::AttestationError {
            url: service.to_string(),
            failure: crate::attestation::AttestationFailure::Transport(format!("not a URL: {err}")),
        })
    })?;
    match crate::attestation::attest(http, &url, policy).await {
        Ok(Some(verified)) => {
            tracing::debug!(%url, pcr0 = %hex::encode(verified.pcr0), "node attested");
            Ok(())
        }
        Ok(None) => {
            tracing::debug!(%url, "node listed as unattested, attestation skipped");
            Ok(())
        }
        Err(err) => Err(NodeError::Attestation(err)),
    }
}

#[cfg(target_arch = "wasm32")]
#[expect(
    clippy::unused_async,
    reason = "same shape as the native attestation step"
)]
async fn attest_service(_service: &Uri, attestation: &Attestation) -> Result<(), NodeError> {
    let Attestation::OnDemand = attestation;
    Ok(())
}

/// Write the `req` request to the provided [`WebSocketSession`].
///
/// On success, returns the parsed [`DLogProofShareShamir`].
#[instrument(level = "trace", skip_all)]
async fn finish_session(
    mut session: WebSocketSession,
    req: DLogCommitmentsShamir,
) -> Result<DLogProofShareShamir, NodeError> {
    session.send(req).await?;
    let resp = session.read().await?;
    Ok(resp)
}

/// Completes all OPRF sessions in parallel by sending the provided [`DLogCommitmentsShamir`] to the open sessions.
///
/// **Important:**
/// - These must be the *same parties* that were used during the initial
///   `init_sessions` call.
/// - The order of the sessions matters: we return responses in the order provided and they need to match the original session list. This is crucial because Lagrange coefficients are computed in the meantime, and they need to match the shares obtained earlier.
///
/// Fails fast if any single request errors.
#[instrument(level = "debug", skip_all)]
pub async fn finish_sessions(
    sessions: OprfSessions,
    req: DLogCommitmentsShamir,
) -> Result<Vec<DLogProofShareShamir>, NodeError> {
    futures::future::try_join_all(
        sessions
            .ws
            .into_iter()
            .map(|service| finish_session(service, req.clone())),
    )
    .await
}

/// Initializes new OPRF sessions by opening a web-socket at `/api/{module}/oprf` on a list of nodes, collecting responses until the given `threshold` is met.
///
/// Nodes are queried concurrently. Errors from some services are logged and ignored, unless they prevent reaching the threshold.
///
/// With [`Attestation::EveryCall`], each node is attested (fresh nonce) before its
/// web-socket is opened; a node that fails attestation contributes a
/// [`NodeError::Attestation`] and is not contacted further.
///
/// Returns a [`OprfSessions`] ready to be finalized with [`finish_sessions`].
#[instrument(level = "debug", skip_all)]
pub async fn init_sessions<OprfRequestAuth: Clone + Serialize + 'static>(
    request_id: Uuid,
    oprf_services: &[Uri],
    threshold: usize,
    req: OprfRequest<OprfRequestAuth>,
    connector: Connector,
    attestation: &Attestation,
) -> Result<OprfSessions, Vec<NodeError>> {
    let mut futures: FuturesUnordered<_> = oprf_services
        .iter()
        .map(|service| {
            let connector = connector.clone();
            let req = req.clone();
            let service = service.to_owned();
            async move {
                init_session(service.clone(), request_id, req, connector, attestation)
                    .await
                    .map_err(|err| (service, err))
            }
        })
        .collect();
    let mut epoch_session_map = HashMap::new();
    let mut session_errors = Vec::new();
    while let Some(result) = futures.next().await {
        match result {
            Ok((session, resp)) => {
                let epoch = resp.oprf_pub_key_with_epoch.epoch;
                let epoch_session = epoch_session_map
                    .entry(epoch)
                    .or_insert_with(|| OprfSessions::with_capacity(epoch, threshold));
                tracing::debug!("received session for epoch: {epoch}");
                let service = session.service.clone();
                if let Err(duplicate_service) = epoch_session.push(session, resp) {
                    tracing::warn!("{duplicate_service} and {service} send same Party ID!");
                    continue;
                }
                if epoch_session.len() == threshold {
                    let mut chosen_sessions = std::mem::take(epoch_session);
                    chosen_sessions.sort_by_party_id();
                    tracing::debug!(
                        "Initiated sessions {} with epoch {}",
                        chosen_sessions.len(),
                        chosen_sessions.epoch
                    );
                    return Ok(chosen_sessions);
                }
            }
            Err((service, err)) => {
                let node = service
                    .authority()
                    .map_or_else(|| "unknown service".to_owned(), ToString::to_string);
                if matches!(err, NodeError::Attestation(_)) {
                    // threshold success can hide this node's failure, so it must be visible
                    tracing::warn!(%err, "node failed attestation: {node}");
                } else {
                    // we very much expect certain services to return an error therefore we do not log at warn/error level.
                    tracing::debug!(%err, "got error response from {node:?}");
                }
                session_errors.push(err);
            }
        }
    }

    if epoch_session_map.is_empty() {
        tracing::debug!("could not get a single session!");
    } else {
        tracing::debug!("could not get enough sessions. I got the following sessions:");
        #[allow(
            clippy::iter_over_hash_type,
            reason = "HashMap iter only used for logging + error construction"
        )]
        for (epoch, sessions) in epoch_session_map {
            tracing::debug!("got for epoch {epoch} {} sessions", sessions.len());

            // As we collapse each session into the epoch_session_map we need to add an EpochMismatch instance per session, otherwise the aggregate_error function will not work
            for _ in sessions.party_ids {
                session_errors.push(NodeError::EpochMismatch(epoch));
            }
        }
    }
    Err(session_errors)
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        extract::{WebSocketUpgrade, ws::WebSocket},
        response::IntoResponse,
        routing::any,
    };
    use axum_test::{TestServer, TestServerBuilder};
    use http::Uri;
    use oprf_core::ddlog_equality::shamir::{DLogSessionShamir, DLogShareShamir};
    use oprf_types::{
        ShareEpoch,
        api::{OprfPublicKeyWithEpoch, OprfResponse},
        crypto::{OprfPublicKey, PartyId},
    };
    use uuid::Uuid;

    use crate::{OprfSessions, ws::WebSocketSession};

    fn ws_handler<C, Fut>(ws: WebSocketUpgrade, callback: C) -> impl IntoResponse
    where
        C: FnOnce(WebSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        ws.on_upgrade(callback)
    }

    async fn panic_on_message(mut socket: WebSocket) {
        let _ = socket.recv().await;
        panic!("Should not be called")
    }

    fn mock_server<C, Fut>(callback: C) -> (TestServer, Uri)
    where
        C: FnOnce(WebSocket) -> Fut + Send + Sync + 'static + Clone,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let test_server = TestServerBuilder::new()
            .http_transport()
            .build(Router::new().route(
                "/api/test/oprf",
                any(
                    move |webscoket_upgrade| async move { ws_handler(webscoket_upgrade, callback) },
                ),
            ));
        let address = test_server
            .server_address()
            .expect("Must be there")
            .to_string()
            .replacen("http", "ws", 1);
        // remove trailing '/'
        let address = if let Some(prefix) = address.strip_suffix("/") {
            prefix.to_string()
        } else {
            address
        };
        (
            test_server,
            format!("{address}/api/test/oprf")
                .parse()
                .expect("Is valid URI"),
        )
    }

    fn oprf_response_with_party_id(id: u16) -> OprfResponse {
        OprfResponse {
            commitments: DLogSessionShamir::partial_commitments(
                rand::random(),
                DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>()),
                &mut rand::thread_rng(),
            )
            .1,
            party_id: PartyId::from(id),
            oprf_pub_key_with_epoch: OprfPublicKeyWithEpoch {
                key: OprfPublicKey::from(rand::random::<ark_babyjubjub::EdwardsAffine>()),
                epoch: ShareEpoch::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_reject_duplicate_party_id() {
        let (_test_server, should_address) = mock_server(panic_on_message);

        let websocket_session0 = WebSocketSession::new(
            should_address.clone(),
            Uuid::new_v4(),
            tokio_tungstenite::Connector::Plain,
        )
        .await
        .expect("Can open websocket-session");

        let websocket_session1 = WebSocketSession::new(
            should_address.clone(),
            Uuid::new_v4(),
            tokio_tungstenite::Connector::Plain,
        )
        .await
        .expect("Can open websocket-session");

        let mut oprf_sessions = OprfSessions::with_capacity(ShareEpoch::default(), 2);

        oprf_sessions
            .push(websocket_session0, oprf_response_with_party_id(0))
            .expect("Should work");

        let is_address = oprf_sessions
            .push(websocket_session1, oprf_response_with_party_id(0))
            .expect_err("Should not work");
        assert_eq!(
            is_address,
            should_address
                .authority()
                .expect("Has an authority")
                .to_string()
        );
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(
    clippy::unwrap_used,
    clippy::missing_assert_message,
    reason = "test code"
)]
mod attested_tests {
    use std::{net::SocketAddr, sync::Arc};

    use axum::{
        Router,
        extract::{
            WebSocketUpgrade,
            ws::{Message, WebSocket},
        },
        routing::any,
    };
    use http::Uri;
    use oprf_core::ddlog_equality::shamir::{DLogSessionShamir, DLogShareShamir};
    use oprf_types::{
        ShareEpoch,
        api::{OprfPublicKeyWithEpoch, OprfRequest, OprfResponse},
        crypto::{OprfPublicKey, PartyId},
    };
    use uuid::Uuid;

    use crate::{
        Attestation, NodeError,
        attestation::{
            AttestationFailure, AttestationPolicy,
            test_support::{
                Chain, Events, TEST_PCR0, attestation_route, chain, deadline, kinds_of, serve,
            },
        },
        init_sessions,
    };

    const OTHER_PCR0: &str = "bb";

    /// A node serving `/attestation` and the OPRF WebSocket; records `(node, "ws", "")`
    /// when the upgrade request arrives.
    async fn node(
        name: &'static str,
        party: u16,
        chain: &Arc<Chain>,
        events: &Events,
    ) -> SocketAddr {
        let ws_events = events.clone();
        let app = Router::new()
            .route(
                "/attestation",
                attestation_route(name, chain.clone(), events.clone()),
            )
            .route(
                "/api/test/oprf",
                any(move |ws: WebSocketUpgrade| {
                    ws_events.lock().unwrap().push((name, "ws", String::new()));
                    async move { ws.on_upgrade(move |socket| answer_init(socket, party)) }
                }),
            );
        serve(app).await
    }

    async fn answer_init(mut socket: WebSocket, party: u16) {
        let _request = socket.recv().await;
        let response = OprfResponse {
            commitments: DLogSessionShamir::partial_commitments(
                rand::random(),
                DLogShareShamir::from(rand::random::<ark_babyjubjub::Fr>()),
                &mut rand::thread_rng(),
            )
            .1,
            party_id: PartyId::from(party),
            oprf_pub_key_with_epoch: OprfPublicKeyWithEpoch {
                key: OprfPublicKey::from(rand::random::<ark_babyjubjub::EdwardsAffine>()),
                epoch: ShareEpoch::default(),
            },
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&response, &mut buf).unwrap();
        if socket.send(Message::Binary(buf.into())).await.is_ok() {
            let _closed = socket.recv().await;
        }
    }

    fn ws_uri(addr: SocketAddr) -> Uri {
        format!("ws://{addr}/api/test/oprf").parse().unwrap()
    }

    fn every_call(policy_text: &str, chain: &Chain) -> Attestation {
        Attestation::EveryCall {
            policy: Arc::new(
                AttestationPolicy::parse(policy_text)
                    .unwrap()
                    .with_anchor(chain.root_der.clone()),
            ),
            http: reqwest::Client::new(),
        }
    }

    fn listed(addr: SocketAddr, pcr0_hex: &str) -> String {
        format!("http://{addr} {pcr0_hex}\n")
    }

    async fn run(
        services: &[Uri],
        attestation: &Attestation,
    ) -> Result<crate::OprfSessions, Vec<NodeError>> {
        let req = OprfRequest {
            request_id: Uuid::new_v4(),
            blinded_query: rand::random::<ark_babyjubjub::EdwardsAffine>(),
            auth: (),
        };
        deadline(init_sessions(
            req.request_id,
            services,
            services.len(),
            req,
            tokio_tungstenite::Connector::Plain,
            attestation,
        ))
        .await
    }

    fn attestation_failures(errors: &[NodeError]) -> Vec<(String, AttestationFailure)> {
        errors
            .iter()
            .filter_map(|e| match e {
                NodeError::Attestation(a) => Some((a.url.clone(), a.failure.clone())),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn every_call_attests_each_node_before_its_session() {
        let chain = Arc::new(chain());
        let events = Events::default();
        let a = node("a", 1, &chain, &events).await;
        let b = node("b", 2, &chain, &events).await;
        let pcr = hex::encode(TEST_PCR0);
        let attestation = every_call(&(listed(a, &pcr) + &listed(b, &pcr)), &chain);
        let services = [ws_uri(a), ws_uri(b)];

        let first = run(&services, &attestation).await;
        assert!(first.is_ok(), "{:?}", first.err());
        let second = run(&services, &attestation).await;
        assert!(second.is_ok(), "{:?}", second.err());

        for name in ["a", "b"] {
            assert_eq!(
                kinds_of(&events, name),
                ["attest", "ws", "attest", "ws"],
                "node {name}"
            );
        }
        let nonces: Vec<String> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, k, _)| *n == "a" && *k == "attest")
            .map(|(_, _, nonce)| nonce.clone())
            .collect();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1], "each call draws a fresh nonce");
    }

    #[tokio::test]
    async fn failed_attestation_opens_no_session() {
        let chain = Arc::new(chain());
        let events = Events::default();
        let a = node("a", 1, &chain, &events).await;
        let b = node("b", 2, &chain, &events).await;
        let text = listed(a, &hex::encode(TEST_PCR0)) + &listed(b, &OTHER_PCR0.repeat(48));
        let attestation = every_call(&text, &chain);

        let errors = run(&[ws_uri(a), ws_uri(b)], &attestation)
            .await
            .err()
            .expect("node b must fail attestation");

        assert_eq!(kinds_of(&events, "b"), ["attest"], "no session at b");
        let failures = attestation_failures(&errors);
        assert_eq!(failures.len(), 1, "{errors:?}");
        assert!(failures[0].0.contains(&b.to_string()), "{failures:?}");
        assert!(
            matches!(failures[0].1, AttestationFailure::Pcr0NotAllowed(_)),
            "{failures:?}"
        );
    }

    #[tokio::test]
    async fn unattested_node_skips_attestation() {
        let chain = Arc::new(chain());
        let events = Events::default();
        let a = node("a", 1, &chain, &events).await;
        let b = node("b", 2, &chain, &events).await;
        let text = listed(a, &hex::encode(TEST_PCR0)) + &format!("http://{b} unattested\n");
        let attestation = every_call(&text, &chain);

        let result = run(&[ws_uri(a), ws_uri(b)], &attestation).await;

        assert!(result.is_ok(), "{:?}", result.err());
        assert_eq!(kinds_of(&events, "a"), ["attest", "ws"]);
        assert_eq!(kinds_of(&events, "b"), ["ws"]);
    }

    #[tokio::test]
    async fn unlisted_node_is_refused() {
        let chain = Arc::new(chain());
        let events = Events::default();
        let a = node("a", 1, &chain, &events).await;
        let b = node("b", 2, &chain, &events).await;
        let attestation = every_call(&listed(a, &hex::encode(TEST_PCR0)), &chain);

        let errors = run(&[ws_uri(a), ws_uri(b)], &attestation)
            .await
            .err()
            .expect("node b is not listed");

        assert!(kinds_of(&events, "b").is_empty(), "b was contacted");
        let failures = attestation_failures(&errors);
        assert_eq!(failures.len(), 1, "{errors:?}");
        assert!(failures[0].0.contains(&b.to_string()), "{failures:?}");
        assert_eq!(failures[0].1, AttestationFailure::NotListed);
    }

    #[tokio::test]
    async fn on_demand_never_calls_attestation() {
        let chain = Arc::new(chain());
        let events = Events::default();
        let a = node("a", 1, &chain, &events).await;
        let b = node("b", 2, &chain, &events).await;

        let result = run(&[ws_uri(a), ws_uri(b)], &Attestation::OnDemand).await;

        assert!(result.is_ok(), "{:?}", result.err());
        assert_eq!(kinds_of(&events, "a"), ["ws"]);
        assert_eq!(kinds_of(&events, "b"), ["ws"]);
    }
}
