//! DynamoDB-backed [`KeyRegistry`].

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::config::BehaviorVersion;
use aws_sdk_dynamodb::config::retry::RetryConfig;
use aws_sdk_dynamodb::config::timeout::TimeoutConfig;
use aws_sdk_dynamodb::primitives::Blob;
use aws_sdk_dynamodb::types::AttributeValue;

use super::{KeyRegistry, KeyStatus, RegistryEntry, RegistryError, SigningPublicKey};

/// Partition key. Canonical `0x` hex, so a lookup is a point read.
const PUBLIC_KEY: &str = "public_key";
const ATTESTATION: &str = "attestation";
const PCR0: &str = "pcr0";
const VALID_FROM: &str = "valid_from";
const RETIRED_AT: &str = "retired_at";
const STATUS: &str = "status";
/// The attribute the table's TTL is configured on.
const EXPIRES_AT: &str = "expires_at";

/// How long a row outlives the boot that wrote it.
///
/// A row must survive every statement its key signed: once it expires the lookup answers `404`,
/// and a `404` is a hard verification failure that MUST NOT be retried into a pass. This is a
/// floor set by the match statement's lifetime, not a storage-cost dial.
const RETENTION: Duration = Duration::from_hours(24 * 90);

/// Bound on one attempt, so a hung connection cannot pin a request or the boot task.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound on a call including its retries.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(6);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Attempts per call. The SDK spaces them with exponential backoff and jitter.
const MAX_ATTEMPTS: u32 = 3;

/// The `Signing Key` registry, in DynamoDB.
#[derive(Debug, Clone)]
pub struct DynamoKeyRegistry {
    client: Client,
    table: String,
}

impl DynamoKeyRegistry {
    /// Builds a registry over `table`, taking credentials and region from the environment.
    pub async fn new(table: String) -> Self {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(CONNECT_TIMEOUT)
                    .operation_attempt_timeout(ATTEMPT_TIMEOUT)
                    .operation_timeout(OPERATION_TIMEOUT)
                    .build(),
            )
            .retry_config(RetryConfig::standard().with_max_attempts(MAX_ATTEMPTS))
            .load()
            .await;

        Self {
            client: Client::new(&config),
            table,
        }
    }

    /// Reads a stored item back, naming the first attribute that was unusable.
    fn read_entry(
        public_key: SigningPublicKey,
        item: &HashMap<String, AttributeValue>,
    ) -> Result<RegistryEntry, RegistryError> {
        let malformed = |reason: &str| RegistryError::Malformed {
            public_key,
            reason: reason.to_owned(),
        };

        let attestation = item
            .get(ATTESTATION)
            .and_then(|value| value.as_b().ok())
            .ok_or_else(|| malformed("attestation is missing or not binary"))?
            .as_ref()
            .to_vec();

        let pcr0 = item
            .get(PCR0)
            .and_then(|value| value.as_s().ok())
            .and_then(|text| hex::decode(text).ok())
            .ok_or_else(|| malformed("pcr0 is missing or not hex"))?;

        let valid_from = read_number(item, VALID_FROM)
            .ok_or_else(|| malformed("valid_from is missing or not a number"))?;

        // Absent is the normal shape for a key that has not retired. Present but unreadable is not,
        // and must not quietly read as "still active".
        let retired_at = match item.get(RETIRED_AT) {
            None | Some(AttributeValue::Null(_)) => None,
            Some(_) => Some(
                read_number(item, RETIRED_AT)
                    .ok_or_else(|| malformed("retired_at is not a number"))?,
            ),
        };

        let status = item
            .get(STATUS)
            .and_then(|value| value.as_s().ok())
            .and_then(|text| KeyStatus::parse(text))
            .ok_or_else(|| malformed("status is missing or not one of active/retired/revoked"))?;

        Ok(RegistryEntry {
            public_key,
            attestation,
            pcr0,
            valid_from,
            retired_at,
            status,
        })
    }
}

#[async_trait]
impl KeyRegistry for DynamoKeyRegistry {
    async fn get(
        &self,
        public_key: SigningPublicKey,
    ) -> Result<Option<RegistryEntry>, RegistryError> {
        let output = self
            .client
            .get_item()
            .table_name(&self.table)
            // A miss is terminal for the caller, so never serve one that only reflects a replica
            // lagging a boot seconds behind.
            .consistent_read(true)
            .key(PUBLIC_KEY, AttributeValue::S(public_key.to_string()))
            .send()
            .await
            .map_err(|error| RegistryError::Unavailable(format!("get_item: {error}")))?;

        output
            .item
            .map(|item| Self::read_entry(public_key, &item))
            .transpose()
    }

    async fn set(&self, entry: &RegistryEntry) -> Result<(), RegistryError> {
        let mut request = self
            .client
            .put_item()
            .table_name(&self.table)
            .item(PUBLIC_KEY, AttributeValue::S(entry.public_key.to_string()))
            .item(
                ATTESTATION,
                AttributeValue::B(Blob::new(entry.attestation.clone())),
            )
            .item(PCR0, AttributeValue::S(hex::encode(&entry.pcr0)))
            .item(VALID_FROM, AttributeValue::N(entry.valid_from.to_string()))
            .item(STATUS, AttributeValue::S(entry.status.as_str().to_owned()))
            .item(
                EXPIRES_AT,
                AttributeValue::N(
                    entry
                        .valid_from
                        .saturating_add(RETENTION.as_secs())
                        .to_string(),
                ),
            );

        if let Some(retired_at) = entry.retired_at {
            request = request.item(RETIRED_AT, AttributeValue::N(retired_at.to_string()));
        }

        request
            .send()
            .await
            .map(|_| ())
            .map_err(|error| RegistryError::Unavailable(format!("put_item: {error}")))
    }
}

/// Reads an `N` attribute as a `u64`.
fn read_number(item: &HashMap<String, AttributeValue>, name: &str) -> Option<u64> {
    item.get(name)
        .and_then(|value| value.as_n().ok())
        .and_then(|text| text.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aws_sdk_dynamodb::primitives::Blob;
    use aws_sdk_dynamodb::types::AttributeValue;

    use super::{
        ATTESTATION, DynamoKeyRegistry, EXPIRES_AT, PCR0, PUBLIC_KEY, RETIRED_AT, STATUS,
        VALID_FROM,
    };
    use crate::key_registry::{KeyStatus, RegistryError, SigningPublicKey};

    fn public_key() -> SigningPublicKey {
        SigningPublicKey::from_bytes([7; 32])
    }

    fn item() -> HashMap<String, AttributeValue> {
        HashMap::from([
            (
                PUBLIC_KEY.to_owned(),
                AttributeValue::S(public_key().to_string()),
            ),
            (
                ATTESTATION.to_owned(),
                AttributeValue::B(Blob::new(vec![1, 2, 3])),
            ),
            (PCR0.to_owned(), AttributeValue::S(hex::encode([9u8; 48]))),
            (
                VALID_FROM.to_owned(),
                AttributeValue::N("1780000000".into()),
            ),
            (STATUS.to_owned(), AttributeValue::S("active".into())),
            (
                EXPIRES_AT.to_owned(),
                AttributeValue::N("1790000000".into()),
            ),
        ])
    }

    #[test]
    fn reads_a_well_formed_row() {
        let entry = DynamoKeyRegistry::read_entry(public_key(), &item()).expect("should read");

        assert_eq!(entry.public_key, public_key());
        assert_eq!(entry.attestation, vec![1, 2, 3]);
        assert_eq!(entry.pcr0, vec![9u8; 48]);
        assert_eq!(entry.valid_from, 1_780_000_000);
        assert_eq!(entry.retired_at, None);
        assert_eq!(entry.status, KeyStatus::Active);
    }

    #[test]
    fn reads_a_retired_row() {
        let mut item = item();
        item.insert(STATUS.to_owned(), AttributeValue::S("retired".into()));
        item.insert(
            RETIRED_AT.to_owned(),
            AttributeValue::N("1780000900".into()),
        );

        let entry = DynamoKeyRegistry::read_entry(public_key(), &item).expect("should read");

        assert_eq!(entry.status, KeyStatus::Retired);
        assert_eq!(entry.retired_at, Some(1_780_000_900));
    }

    /// A row the host cannot read is a data fault, never an implicit `active`.
    #[test]
    fn a_row_missing_an_attribute_is_malformed() {
        for attribute in [ATTESTATION, PCR0, VALID_FROM, STATUS] {
            let mut item = item();
            item.remove(attribute);

            let error = DynamoKeyRegistry::read_entry(public_key(), &item)
                .expect_err("{attribute} is required");

            assert!(matches!(error, RegistryError::Malformed { .. }));
        }
    }

    #[test]
    fn an_unreadable_retired_at_is_malformed_rather_than_absent() {
        let mut item = item();
        item.insert(RETIRED_AT.to_owned(), AttributeValue::S("yesterday".into()));

        let error =
            DynamoKeyRegistry::read_entry(public_key(), &item).expect_err("should not be absent");

        assert!(matches!(error, RegistryError::Malformed { .. }));
    }
}
