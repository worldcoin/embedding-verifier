//! End-to-end tests for the match client, over real HTTP.
//!
//! The stub plays host *and* enclave, so the whole channel round-trip runs. An accepted `Success`
//! is not covered: it needs a token signed by the key inside a genuine attestation, which cannot
//! be forged. `e2e` covers that against a real enclave. A *rejected* `Success` is covered here,
//! and is the case that matters — forging one is exactly what an untrusted host would try.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use attested_channel::channel::{Responder, SealedRequest, UnwrapErr};
use attested_channel::nitro::VerifiedAttestation;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flamingo_verifier_client::nitro::PcrMeasurement;
use flamingo_verifier_client::{
    ClientError, Config, FaceVerifierClient, Requester, VerifiedAssignment,
};
use flamingo_verifier_protocol::match_token::MatchToken;
use flamingo_verifier_protocol::messages::{
    AttestedStatement, FailureReason, MatchInputs, MatchResult,
};
use getrandom::SysRng;
use hex_literal::hex;
use serde_json::{Value, json};

fn config(base_url: &str) -> Config {
    let pcrs = vec![PcrMeasurement::new(
        0,
        hex!(
            "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
        ),
    )];

    Config::new(base_url, vec![pcrs]).expect("config should be valid")
}

fn inputs() -> MatchInputs {
    MatchInputs {
        version: attested_channel::channel::CHANNEL_VERSION,
        live_image: b"liveness-frame".to_vec(),
        credential_image: b"credential-thumbnail".to_vec(),
        light_guard_image: None,
        hashes_json: br#"{"thumbnail.png":"aa"}"#.to_vec(),
        challenge_image: b"challenge-frame".to_vec(),
        match_threshold: 0.5,
    }
}

/// Serves `router` on an ephemeral port and returns its base URL.
async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");

    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("stub should run");
    });

    format!("http://{address}")
}

/// A stub that owns the enclave side of the channel.
#[derive(Clone)]
struct Enclave {
    responder: Arc<Responder>,
    answer: MatchResult,
    /// The request body the client sent, for asserting the wire shape.
    seen: Arc<Mutex<Option<Value>>>,
    /// Reply on a channel the client holds no opener for.
    foreign_reply: bool,
}

/// Keyed to `responder`, bypassing `request_assignment` so the stub can open what the client seals.
fn assignment_for(responder: &Responder) -> VerifiedAssignment {
    VerifiedAssignment {
        attestation: VerifiedAttestation {
            enclave_public_key: responder.public_key().to_vec(),
            module_id: "i-test-enc0".to_owned(),
            timestamp_millis: 0,
            pcrs: BTreeMap::new(),
        },
        requester: Requester::new(responder.public_key()).expect("key should decode"),
    }
}

async fn serve_enclave(
    answer: MatchResult,
    foreign_reply: bool,
) -> (String, Arc<Responder>, Arc<Mutex<Option<Value>>>) {
    let responder = Arc::new(Responder::generate(&mut UnwrapErr(SysRng)));
    let seen = Arc::new(Mutex::new(None));
    let state = Enclave {
        responder: Arc::clone(&responder),
        answer,
        seen: Arc::clone(&seen),
        foreign_reply,
    };

    let router = Router::new()
        .route(
            "/v1/matches",
            post(
                |State(state): State<Enclave>, Json(body): Json<Value>| async move {
                    *state.seen.lock().expect("lock should be held") = Some(body.clone());

                    let sealed = STANDARD
                        .decode(
                            body["ciphertext"]
                                .as_str()
                                .expect("ciphertext should be a string"),
                        )
                        .expect("ciphertext should be base64");
                    let (_, own_sealer) = state
                        .responder
                        .open(&SealedRequest::from_bytes(sealed))
                        .expect("the enclave should open a request sealed to its own key");

                    // Same enclave key, different context: the client's opener must reject it.
                    let sealer = if state.foreign_reply {
                        let stranger = Requester::new(state.responder.public_key())
                            .expect("key should decode");
                        let (other, _) = stranger
                            .seal(b"unrelated", &mut UnwrapErr(SysRng))
                            .expect("sealing should succeed");
                        state
                            .responder
                            .open(&other)
                            .expect("the enclave opens its own")
                            .1
                    } else {
                        own_sealer
                    };

                    let encoded = state
                        .answer
                        .to_padded_cbor()
                        .expect("result should fit the envelope");
                    let response = sealer
                        .seal(&encoded, &mut UnwrapErr(SysRng))
                        .expect("sealing should succeed");

                    Json(json!({
                        "response_ciphertext": STANDARD.encode(response.into_bytes()),
                    }))
                },
            ),
        )
        .with_state(state);

    (serve(router).await, responder, seen)
}

/// Serves a fixed error envelope, as the host's `AppError` renders one.
async fn serve_error(status: StatusCode, code: &'static str, allow_retry: bool) -> String {
    let router = Router::new().route(
        "/v1/matches",
        post(move || async move {
            (
                status,
                Json(json!({
                    "allowRetry": allow_retry,
                    "error": { "code": code, "message": "stub" },
                })),
            )
        }),
    );

    serve(router).await
}

#[tokio::test]
async fn a_sealed_rejection_round_trips() {
    let answer = MatchResult::Failed(FailureReason::MatchBelowThreshold);
    let (base_url, responder, seen) = serve_enclave(answer.clone(), false).await;
    let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");

    let result = client
        .request_match(&assignment_for(&responder), &inputs())
        .await
        .expect("a rejection is a normal return");

    assert_eq!(result, answer);

    // The wire shape the host reads.
    let body = seen.lock().expect("lock should be held").clone().unwrap();
    assert!(
        STANDARD
            .decode(body["ciphertext"].as_str().unwrap())
            .is_ok(),
        "the sealed request must be base64"
    );
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the request carries the ciphertext and nothing else"
    );
}

#[tokio::test]
async fn a_reply_from_another_exchange_cannot_be_opened() {
    let (base_url, responder, _) =
        serve_enclave(MatchResult::Failed(FailureReason::MalformedInputs), true).await;
    let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");

    let error = client
        .request_match(&assignment_for(&responder), &inputs())
        .await
        .expect_err("a reply sealed on another exchange must not open");

    assert!(matches!(error, ClientError::Channel(_)), "got {error:?}");
}

#[tokio::test]
async fn a_stale_assignment_asks_for_a_reassignment() {
    let base_url = serve_error(StatusCode::CONFLICT, "reassign_required", true).await;
    let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");
    let responder = Responder::generate(&mut UnwrapErr(SysRng));

    let error = client
        .request_match(&assignment_for(&responder), &inputs())
        .await
        .expect_err("a 409 is an error, not a result");

    assert!(
        matches!(error, ClientError::ReassignRequired),
        "a 409 must be distinguishable so the caller can retry once, got {error:?}"
    );
}

#[tokio::test]
async fn other_envelopes_keep_their_code_and_retry_flag() {
    let base_url = serve_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large", false).await;
    let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");
    let responder = Responder::generate(&mut UnwrapErr(SysRng));

    let error = client
        .request_match(&assignment_for(&responder), &inputs())
        .await
        .expect_err("a 413 is an error");

    match error {
        ClientError::Api {
            status,
            code,
            allow_retry,
        } => {
            assert_eq!(status, 413);
            assert_eq!(code, "request_too_large");
            assert!(!allow_retry);
        }
        other => panic!("expected an envelope, got {other:?}"),
    }
}

#[tokio::test]
async fn a_status_without_an_envelope_still_surfaces() {
    let router = Router::new().route(
        "/v1/matches",
        post(|| async { (StatusCode::BAD_GATEWAY, "not json") }),
    );
    let base_url = serve(router).await;
    let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");
    let responder = Responder::generate(&mut UnwrapErr(SysRng));

    let error = client
        .request_match(&assignment_for(&responder), &inputs())
        .await
        .expect_err("a 413 is an error");

    assert!(matches!(error, ClientError::Status(502)), "got {error:?}");
}

/// A statement is only as good as the attestation beside it, so one that does not verify must be
/// an error rather than a `Success` the caller could mistake for a held match.
#[tokio::test]
async fn a_statement_whose_attestation_does_not_verify_is_rejected() {
    // An empty document is the enclave omitting it; junk is a host substituting its own.
    for attestation in [Vec::new(), b"not a COSE attestation document".to_vec()] {
        let answer = MatchResult::Success(AttestedStatement {
            token: MatchToken::from_bytes(b"cose-sign1".to_vec()),
            signing_key_attestation: attestation,
        });
        let (base_url, responder, _) = serve_enclave(answer, false).await;
        let client = FaceVerifierClient::new(config(&base_url)).expect("client should build");

        let error = client
            .request_match(&assignment_for(&responder), &inputs())
            .await
            .expect_err("an unverifiable attestation must not yield a statement");

        assert!(
            matches!(error, ClientError::Attestation(_)),
            "expected an attestation failure, got {error:?}"
        );
    }
}
