//! End-to-end tests for the embedding extraction client over real HTTP.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use attested_channel::channel::{Responder, SealedRequest, UnwrapErr};
use attested_channel::nitro::VerifiedAttestation;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use deepface_client::nitro::PcrMeasurement;
use deepface_client::{Config, FaceVerifierClient, Requester, VerifiedAssignment};
use deepface_protocol::embedding::{Embedding, ExtractEmbeddingInputs, ExtractEmbeddingResult};
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

#[derive(Clone)]
struct Enclave {
    responder: Arc<Responder>,
    seen: Arc<Mutex<Option<Value>>>,
    answer: ExtractEmbeddingResult,
}

#[tokio::test]
async fn a_sealed_embedding_round_trips() {
    let answer = ExtractEmbeddingResult::Success(Embedding {
        vector: "ZmFrZS12ZWN0b3I=".to_owned(),
        embedding_type: "ghostfacenet_flipped_mean".to_owned(),
        embedding_version: "2.0.0".to_owned(),
        embedding_inference_backend: "face-engine".to_owned(),
    });
    let responder = Arc::new(Responder::generate(&mut UnwrapErr(SysRng)));
    let seen = Arc::new(Mutex::new(None));
    let state = Enclave {
        responder: Arc::clone(&responder),
        seen: Arc::clone(&seen),
        answer: answer.clone(),
    };
    let router = Router::new()
        .route(
            "/v1/extract-embedding",
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
                    let (_, sealer) = state
                        .responder
                        .open(&SealedRequest::from_bytes(sealed))
                        .expect("enclave should open its request");
                    let encoded = state.answer.to_cbor().expect("result should encode");
                    let response = sealer
                        .seal(&encoded, &mut UnwrapErr(SysRng))
                        .expect("response should seal");

                    Json(json!({
                        "response_ciphertext": STANDARD.encode(response.into_bytes()),
                    }))
                },
            ),
        )
        .with_state(state);
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

    let client =
        FaceVerifierClient::new(config(&format!("http://{address}"))).expect("client should build");
    let result = client
        .request_extract_embedding(
            &assignment_for(&responder),
            &ExtractEmbeddingInputs {
                version: attested_channel::channel::CHANNEL_VERSION,
                image: b"enrollment-image".to_vec(),
            },
        )
        .await
        .expect("extraction should succeed");

    assert_eq!(result, answer);
    let body = seen.lock().expect("lock should be held").clone().unwrap();
    assert!(
        STANDARD
            .decode(
                body["ciphertext"]
                    .as_str()
                    .expect("ciphertext should be present")
            )
            .is_ok()
    );
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(1),
        "the request exposes only ciphertext"
    );
}
