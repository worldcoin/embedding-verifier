use std::{env, fs, path::PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use crypto_box::{PublicKey, aead::OsRng};
use enclave_types::{GetEnclaveKeysRequest, MatchRequest};
use pontifex::{SecureModule, client::ConnectionDetails};
use serde::Serialize;
use sha2::{Digest, Sha256};

const DEFAULT_ENCLAVE_PORT: u32 = 1000;
const DEFAULT_MATCH_THRESHOLD: f32 = 0.9;

/// Plaintext schema wrapped by the sealed [`MatchRequest`] payload.
///
/// This is intentionally not part of `enclave-types`: Pontifex only transports
/// the opaque ciphertext, while this schema is the private encrypted protocol.
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

    let keys_response = pontifex::client::send(connection, &GetEnclaveKeysRequest)
        .await
        .context("failed to call the enclave keys route")?
        .map_err(|error| anyhow!("enclave rejected the enclave-keys request: {error:?}"))?;
    let encryption_key =
        attested_public_key(&keys_response.encryption_key_attestation, "encryption")?;
    let encryption_key: [u8; 32] = encryption_key
        .try_into()
        .map_err(|_| anyhow!("attested encryption public key was not 32 bytes"))?;

    let hashes_json = hashes_json_for(&credential_image);
    let payload = MatchInputs {
        live_image: &live_image,
        credential_image: &credential_image,
        hashes_json: &hashes_json,
        challenge_image: &challenge_image,
        match_threshold,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&payload, &mut plaintext)
        .context("failed to encode the encrypted match payload")?;

    let sealed_payload = PublicKey::from(encryption_key)
        .seal(&mut OsRng, &plaintext)
        .map_err(|error| anyhow!("failed to seal the match payload: {error}"))?;
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

/// Extracts the `public_key` an attestation document commits to.
///
/// Parsing only: the COSE signature, the chain to the AWS Nitro root, and the expected
/// PCRs are a real client's job, and this harness is not one.
fn attested_public_key(document: &[u8], label: &str) -> Result<Vec<u8>> {
    let attestation = SecureModule::parse_raw_attestation_doc(document).map_err(|error| {
        anyhow!("failed to parse the {label}-key attestation document: {error:?}")
    })?;
    let public_key = attestation
        .public_key
        .with_context(|| format!("{label}-key attestation did not contain a public key"))?;

    Ok(public_key.into_vec())
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
