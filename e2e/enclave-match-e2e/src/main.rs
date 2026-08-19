use std::{env, fs, path::PathBuf, time::SystemTime};

use anyhow::{Context, Result, anyhow, ensure};
use enclave_types::{GetEnclaveKeysRequest, MatchRequest};
use pontifex::client::ConnectionDetails;
use serde::Serialize;
use sha2::{Digest, Sha256};
use verifier_client::{Client, Config};

const DEFAULT_ENCLAVE_PORT: u32 = 1000;
const DEFAULT_MATCH_THRESHOLD: f32 = 0.9;

/// Plaintext schema wrapped by [`MatchRequest`].
///
/// This is intentionally not part of `enclave-types`: Pontifex only transports
/// the opaque payload, while this schema is the private match protocol.
#[derive(Serialize)]
struct MatchInputs<'a> {
    #[serde(with = "serde_bytes")]
    live_image: &'a [u8],
    #[serde(with = "serde_bytes")]
    credential_image: &'a [u8],
    #[serde(with = "serde_bytes")]
    hashes_json: &'a [u8],
    #[serde(with = "serde_bytes")]
    challenge_image: &'a [u8],
    match_threshold: f32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let image_paths = image_paths()?;
    let credential_image = read_image(&image_paths.credential, "credential")?;
    let live_image = read_image(&image_paths.live, "live")?;
    let challenge_image = read_image(&image_paths.challenge, "challenge")?;

    let enclave_cid = required_u32("ENCLAVE_CID")?;
    let enclave_port = optional_u32("ENCLAVE_PORT", DEFAULT_ENCLAVE_PORT)?;
    let match_threshold = optional_f32("MATCH_THRESHOLD", DEFAULT_MATCH_THRESHOLD)?;
    let connection = ConnectionDetails::new(enclave_cid, enclave_port);

    let config = load_config()?;
    let verifier = config.verifier();

    let keys_response = pontifex::client::send(connection, &GetEnclaveKeysRequest)
        .await
        .context("failed to call the enclave keys route")?
        .map_err(|error| anyhow!("enclave rejected the enclave-keys request: {error:?}"))?;

    let encryption_key = Client::new(config)
        .context("failed to build the assignment client")?
        .request_assignment(SystemTime::now())
        .await
        .context("enclave assignment did not verify")?
        .enclave_public_key;
    ensure!(
        encryption_key.len() == 32,
        "attested encryption public key was not 32 bytes"
    );
    let signing_key = verifier
        .verify(&keys_response.signing_key_attestation, SystemTime::now())
        .context("the signing-key attestation document did not verify")?
        .enclave_public_key;
    ensure!(
        signing_key.len() == 32,
        "attested signing public key was not 32 bytes"
    );

    let hashes_json = hashes_json_for(&credential_image);
    let payload = MatchInputs {
        live_image: &live_image,
        credential_image: &credential_image,
        hashes_json: &hashes_json,
        challenge_image: &challenge_image,
        match_threshold,
    };
    let mut sealed_payload = Vec::new();
    ciborium::into_writer(&payload, &mut sealed_payload)
        .context("failed to encode the match payload")?;

    let response = pontifex::client::send(connection, &MatchRequest { sealed_payload })
        .await
        .context("failed to call the enclave matches route")?
        .map_err(|error| anyhow!("enclave rejected the match request: {error:?}"))?;

    ensure!(
        response.statement.match_coefficient >= match_threshold,
        "credential/live score {} did not meet threshold {}",
        response.statement.match_coefficient,
        match_threshold
    );
    ensure!(
        response.statement.live_image_hash == Sha256::digest(&live_image).as_slice(),
        "statement did not commit to the live image"
    );
    ensure!(
        response.statement.challenger_image_hash == Sha256::digest(&challenge_image).as_slice(),
        "statement did not commit to the challenge image"
    );
    ensure!(
        response.statement.credential_claim == Sha256::digest(&hashes_json).as_slice(),
        "statement did not commit to hashes.json"
    );

    println!(
        "match succeeded: credential/live similarity={:.6}, threshold={:.6}",
        response.statement.match_coefficient, match_threshold
    );
    Ok(())
}

/// Loads the client configuration named by `VERIFIER_CONFIG`. Schema is in the README.
fn load_config() -> Result<Config> {
    let path = env::var("VERIFIER_CONFIG")
        .context("VERIFIER_CONFIG must name a JSON client configuration file")?;
    let json = fs::read_to_string(&path)
        .with_context(|| format!("failed to read the client config at {path}"))?;

    Config::from_json(&json).with_context(|| format!("{path} is not a valid client config"))
}

struct ImagePaths {
    credential: PathBuf,
    live: PathBuf,
    challenge: PathBuf,
}

fn image_paths() -> Result<ImagePaths> {
    let mut args = env::args_os().skip(1);
    let usage = "usage: enclave-match-e2e <credential-image> <live-image> <challenge-image>";
    let credential = args.next().map(PathBuf::from).context(usage)?;
    let live = args.next().map(PathBuf::from).context(usage)?;
    let challenge = args.next().map(PathBuf::from).context(usage)?;
    ensure!(args.next().is_none(), "{usage}");

    Ok(ImagePaths {
        credential,
        live,
        challenge,
    })
}

fn read_image(path: &PathBuf, label: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {label} image at {}", path.display()))
}

fn hashes_json_for(image: &[u8]) -> Vec<u8> {
    let hash = hex::encode(Sha256::digest(image));
    format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
}

fn required_u32(name: &str) -> Result<u32> {
    env::var(name)
        .with_context(|| format!("{name} must be set"))
        .and_then(|value| {
            value
                .parse()
                .with_context(|| format!("{name} must be a valid u32"))
        })
}

fn optional_u32(name: &str, default: u32) -> Result<u32> {
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .with_context(|| format!("{name} must be a valid u32"))
    })
}

fn optional_f32(name: &str, default: f32) -> Result<f32> {
    env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .with_context(|| format!("{name} must be a valid f32"))
    })
}
