use std::{env, fs, path::PathBuf, time::SystemTime};

use anyhow::{Context, Result, anyhow, bail, ensure};
use attested_channel::channel::{CHANNEL_VERSION, SealedResponse, UnwrapErr};
use deepface_client::{Config, FaceVerifierClient};
use deepface_protocol::match_token::{self, EdDSAPublicKey};
use deepface_protocol::messages::{
    CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN, MatchInputs, MatchResult, encrypt_challenge,
};
use deepface_types::MatchRequest;
use enclave_types::GetSigningKeyRequest;
use pontifex::client::ConnectionDetails;
use sha2::{Digest, Sha256};

const DEFAULT_ENCLAVE_PORT: u32 = 1000;
const DEFAULT_MATCH_THRESHOLD: f32 = 0.9;

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

    let signing_key_attestation = pontifex::client::send(connection, &GetSigningKeyRequest)
        .await
        .context("failed to call the enclave signing-key route")?
        .map_err(|error| anyhow!("enclave rejected the signing-key request: {error:?}"))?;

    let assignment = FaceVerifierClient::new(config)
        .context("failed to build the assignment client")?
        .request_assignment(SystemTime::now())
        .await
        .context("enclave assignment did not verify")?;
    let requester = assignment.requester;
    let signing_key = verifier
        .verify(&signing_key_attestation.document, SystemTime::now())
        .context("the signing-key attestation document did not verify")?
        .enclave_public_key;
    let signing_key = <[u8; 32]>::try_from(signing_key.as_slice())
        .map_err(|_| anyhow!("attested signing public key was not 32 bytes"))?;
    let signing_key = EdDSAPublicKey::from_compressed_bytes(signing_key)
        .map_err(|error| anyhow!("attested signing public key did not decode: {error:?}"))?;

    // Stands in for the RP: encrypt the challenge frame, keep the key for the sealed payload.
    let challenge_image_key: [u8; CHALLENGE_KEY_LEN] = rand::random();
    let challenge_image_iv: [u8; CHALLENGE_IV_LEN] = rand::random();
    let challenge_ciphertext =
        encrypt_challenge(&challenge_image, &challenge_image_key, &challenge_image_iv)
            .map_err(|error| anyhow!("failed to encrypt the challenge image: {error:?}"))?;

    let hashes_json = hashes_json_for(&credential_image);
    let inputs = MatchInputs {
        version: CHANNEL_VERSION,
        live_image: live_image.clone(),
        credential_image: credential_image.clone(),
        hashes_json: hashes_json.clone(),
        challenge_image_key,
        challenge_image_iv,
        match_threshold,
    };
    let plaintext = inputs
        .to_cbor()
        .map_err(|error| anyhow!("failed to encode the match inputs: {error:?}"))?;
    let (sealed, opener) = requester
        .seal(&plaintext, &mut UnwrapErr(getrandom::SysRng))
        .map_err(|error| anyhow!("failed to seal the match request: {error:?}"))?;

    let response = pontifex::client::send(
        connection,
        &MatchRequest {
            body: sealed.into_bytes(),
            challenge_ciphertext,
        },
    )
    .await
    .context("failed to call the enclave matches route")?
    .map_err(|error| anyhow!("enclave rejected the match request: {error:?}"))?;

    let sealed_outcome = opener
        .open(&SealedResponse::from_bytes(response.ciphertext))
        .map_err(|error| anyhow!("failed to open the sealed response: {error:?}"))?;
    let result = MatchResult::from_cbor(&sealed_outcome)
        .map_err(|error| anyhow!("failed to decode the sealed result: {error:?}"))?;

    // The sealed result is the only account of what happened; the host reported nothing but success.
    let token = match result {
        MatchResult::Success(token) => token,
        MatchResult::Failed(reason) => bail!("no statement was issued: {reason:?}"),
    };

    let statement = match_token::verify(&token, &signing_key)
        .map_err(|error| anyhow!("the match statement did not verify: {error:?}"))?;
    ensure!(
        statement.match_coefficient >= match_threshold,
        "credential/live score {} did not meet threshold {}",
        statement.match_coefficient,
        match_threshold
    );
    ensure!(
        statement.live_image_hash == Sha256::digest(&live_image).as_slice(),
        "statement did not commit to the live image"
    );
    ensure!(
        statement.challenger_image_hash == Sha256::digest(&challenge_image).as_slice(),
        "statement did not commit to the challenge image"
    );
    ensure!(
        statement.credential_claim == Sha256::digest(&hashes_json).as_slice(),
        "statement did not commit to hashes.json"
    );

    println!(
        "match succeeded: credential/live similarity={:.6}, threshold={:.6}",
        statement.match_coefficient, match_threshold
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
    let usage = "usage: e2e <credential-image> <live-image> <challenge-image>";
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
