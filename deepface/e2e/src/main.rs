//! End-to-end harness: drives a deployed verifier the way a relying party would.
//!
//! Everything goes through the host over HTTPS — the assignment, the challenge fetch and the
//! match — because that is the surface an RP actually talks to. An earlier version sealed to the
//! enclave and then sent the match over vsock, which meant it had to run on the Nitro instance
//! and never exercised the host relay, the challenge fetch, or the load balancer at all.
//!
//! The load balancer is the reason for `MATCH_ROUNDS`. Behind an ALB with more than one replica,
//! the assignment picks a pod and the sealed channel is bound to *that pod's* enclave key. A match
//! that lands anywhere else cannot be opened, so a successful match is itself proof the affinity
//! cookie was honoured — no cookie inspection needed. One round only proves it for one call; with
//! two replicas a broken cookie escapes a single round about half the time, so the default of five
//! makes that roughly a 3% chance.
//!
//! Usage:
//!   e2e <credential-image> <live-image> <challenge-image>
//!   e2e prepare-challenge <challenge-image> <output-file>
//!
//! `prepare-challenge` encrypts a challenge frame and prints the key and IV. Upload the output to
//! the challenge bucket, then pass its object id and those values back in as environment.
//!
//! Env for a run:
//!   VERIFIER_CONFIG    JSON client configuration (the deploy publishes one)
//!   CHALLENGE_IMAGE_ID object id of the encrypted challenge in the bucket
//!   CHALLENGE_KEY      hex, 32 bytes, as printed by prepare-challenge
//!   CHALLENGE_IV       hex, 12 bytes, likewise
//!   MATCH_ROUNDS       matches to run on one assignment (default 5)
//!   MATCH_THRESHOLD    minimum similarity (default 0.9)

use std::{env, fs, path::PathBuf, time::SystemTime};

use anyhow::{Context, Result, anyhow, bail, ensure};
use attested_channel::channel::CHANNEL_VERSION;
use deepface_client::{Config, FaceVerifierClient, VerifiedAssignment};
use deepface_protocol::match_token::{self, EdDSAPublicKey};
use deepface_protocol::messages::{
    CHALLENGE_IV_LEN, CHALLENGE_KEY_LEN, MatchInputs, MatchResult, encrypt_challenge,
};
use sha2::{Digest, Sha256};

const DEFAULT_MATCH_THRESHOLD: f32 = 0.9;
const DEFAULT_MATCH_ROUNDS: u32 = 5;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next().context(USAGE)?;
    if first == "prepare-challenge" {
        return prepare_challenge(args.collect());
    }
    run(first, args.collect()).await
}

const USAGE: &str = "usage: e2e <credential-image> <live-image> <challenge-image>\n   \
                     or: e2e prepare-challenge <challenge-image> <output-file>";

/// Encrypts a challenge frame so it can be uploaded once and reused as a fixture.
fn prepare_challenge(args: Vec<String>) -> Result<()> {
    let [input, output] = <[String; 2]>::try_from(args).map_err(|_| anyhow!(USAGE))?;
    let plaintext = fs::read(&input).with_context(|| format!("failed to read {input}"))?;

    let key: [u8; CHALLENGE_KEY_LEN] = rand::random();
    let iv: [u8; CHALLENGE_IV_LEN] = rand::random();
    let ciphertext = encrypt_challenge(&plaintext, &key, &iv)
        .map_err(|error| anyhow!("failed to encrypt the challenge image: {error:?}"))?;
    fs::write(&output, &ciphertext).with_context(|| format!("failed to write {output}"))?;

    println!("wrote {output} ({} bytes)", ciphertext.len());
    println!("CHALLENGE_KEY={}", hex::encode(key));
    println!("CHALLENGE_IV={}", hex::encode(iv));
    println!("\nUpload it, then run the harness with those two values and the object id.");
    Ok(())
}

async fn run(credential_path: String, rest: Vec<String>) -> Result<()> {
    let [live_path, challenge_path] = <[String; 2]>::try_from(rest).map_err(|_| anyhow!(USAGE))?;
    let credential_image = read_image(&credential_path.into(), "credential")?;
    let live_image = read_image(&live_path.into(), "live")?;
    // Read only to assert the statement commits to it; the host fetches the ciphertext itself.
    let challenge_image = read_image(&challenge_path.into(), "challenge")?;

    let challenge_image_id = required("CHALLENGE_IMAGE_ID")?;
    let challenge_image_key = required_hex::<CHALLENGE_KEY_LEN>("CHALLENGE_KEY")?;
    let challenge_image_iv = required_hex::<CHALLENGE_IV_LEN>("CHALLENGE_IV")?;
    let match_threshold = optional("MATCH_THRESHOLD", DEFAULT_MATCH_THRESHOLD)?;
    let rounds = optional("MATCH_ROUNDS", DEFAULT_MATCH_ROUNDS)?;
    ensure!(rounds > 0, "MATCH_ROUNDS must be at least 1");

    let config = load_config()?;
    let verifier = config.verifier();
    let client = FaceVerifierClient::new(config).context("failed to build the client")?;

    // One assignment, then every match on the same client. That is the point: the client must
    // carry the load balancer's affinity cookie from here to each match below.
    let assignment = client
        .request_assignment(SystemTime::now())
        .await
        .context("enclave assignment did not verify")?;
    println!("assignment verified against the pinned measurements");

    let hashes_json = hashes_json_for(&credential_image);
    let inputs = MatchInputs {
        version: CHANNEL_VERSION,
        live_image: live_image.clone(),
        credential_image,
        // Vanilla mode: the LightGuard flow cannot produce a signed statement yet.
        light_guard_image: None,
        hashes_json: hashes_json.clone(),
        challenge_image_key,
        challenge_image_iv,
        match_threshold,
    };

    for round in 1..=rounds {
        let statement = one_match(&client, &assignment, &inputs, &challenge_image_id)
            .await
            .with_context(|| {
                format!(
                    "round {round}/{rounds} failed. A sealed request the enclave cannot open means \
                     the match reached a different pod than the assignment — load balancer \
                     affinity is not holding."
                )
            })?;

        let signing_key = verify_signing_key(&verifier, &statement.attestation)?;
        let claims = match_token::verify(&statement.token, &signing_key)
            .map_err(|error| anyhow!("the match statement did not verify: {error:?}"))?;

        ensure!(
            claims.match_coefficient >= match_threshold,
            "round {round}: credential/live score {} did not meet threshold {}",
            claims.match_coefficient,
            match_threshold
        );
        ensure!(
            claims.live_image_hash == Sha256::digest(&live_image).as_slice(),
            "round {round}: statement did not commit to the live image"
        );
        ensure!(
            claims.challenger_image_hash == Sha256::digest(&challenge_image).as_slice(),
            "round {round}: statement did not commit to the challenge image the host fetched"
        );
        ensure!(
            claims.credential_claim == Sha256::digest(&hashes_json).as_slice(),
            "round {round}: statement did not commit to hashes.json"
        );

        println!(
            "round {round}/{rounds}: match ok, similarity={:.6}",
            claims.match_coefficient
        );
    }

    println!(
        "\n{rounds} matches on one assignment, all served by the assigned enclave.\n\
         Attestation, host relay, challenge fetch and load balancer affinity all verified."
    );
    Ok(())
}

struct Statement {
    attestation: Vec<u8>,
    token: match_token::MatchToken,
}

async fn one_match(
    client: &FaceVerifierClient,
    assignment: &VerifiedAssignment,
    inputs: &MatchInputs,
    challenge_image_id: &str,
) -> Result<Statement> {
    let result = client
        .request_match(assignment, inputs, challenge_image_id, SystemTime::now())
        .await
        .context("the match call failed")?;

    // The sealed result is the only account of what happened; the host reports success either way.
    match result {
        MatchResult::Success(attested) => Ok(Statement {
            attestation: attested.signing_key_attestation,
            token: attested.token,
        }),
        MatchResult::Failed(reason) => bail!("no statement was issued: {reason:?}"),
    }
}

/// The whole chain: pinned measurements, then the key the document attests, then its signature.
fn verify_signing_key(
    verifier: &attested_channel::nitro::EnclaveAttestationVerifier,
    attestation: &[u8],
) -> Result<EdDSAPublicKey> {
    let key = verifier
        .verify(attestation, SystemTime::now())
        .context("the signing-key attestation document did not verify")?
        .enclave_public_key;
    let key = <[u8; 32]>::try_from(key.as_slice())
        .map_err(|_| anyhow!("attested signing public key was not 32 bytes"))?;
    EdDSAPublicKey::from_compressed_bytes(key)
        .map_err(|error| anyhow!("attested signing public key did not decode: {error:?}"))
}

/// Loads the client configuration named by `VERIFIER_CONFIG`. The deploy publishes one.
fn load_config() -> Result<Config> {
    let path = env::var("VERIFIER_CONFIG")
        .context("VERIFIER_CONFIG must name a JSON client configuration file")?;
    let json = fs::read_to_string(&path)
        .with_context(|| format!("failed to read the client config at {path}"))?;
    Config::from_json(&json).with_context(|| format!("{path} is not a valid client config"))
}

fn read_image(path: &PathBuf, label: &str) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {label} image at {}", path.display()))
}

fn hashes_json_for(image: &[u8]) -> Vec<u8> {
    let hash = hex::encode(Sha256::digest(image));
    format!(r#"{{"thumbnail.png":"{hash}"}}"#).into_bytes()
}

fn required(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("{name} must be set"))
}

fn required_hex<const N: usize>(name: &str) -> Result<[u8; N]> {
    let raw = required(name)?;
    let bytes = hex::decode(raw.trim().trim_start_matches("0x"))
        .map_err(|error| anyhow!("{name} must be hex: {error}"))?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("{name} must be {N} bytes of hex"))
}

fn optional<T: std::str::FromStr>(name: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Err(_) => Ok(default),
        Ok(value) => value
            .parse()
            .map_err(|error| anyhow!("{name} must be a valid value: {error}")),
    }
}
