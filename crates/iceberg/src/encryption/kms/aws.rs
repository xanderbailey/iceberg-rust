// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! AWS KMS implementation for key management.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{DataKeySpec, EncryptionAlgorithmSpec};

use super::super::KeyManagementClient;
use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Property key for the AWS KMS key ID to use for wrapping.
pub const AWS_KMS_KEY_ID: &str = "kms.aws.key-id";

/// Property key for the encryption algorithm.
pub const AWS_KMS_ENCRYPTION_ALGORITHM: &str = "kms.aws.encryption-algorithm";

/// Property key for the data key spec.
pub const AWS_KMS_DATA_KEY_SPEC: &str = "kms.aws.data-key-spec";

/// AWS KMS client for key management operations.
///
/// This implementation uses AWS Key Management Service for encrypting/decrypting
/// data encryption keys with a KMS-managed master key.
///
/// # Example
///
/// ```ignore
/// use iceberg::encryption::kms::AwsKms;
///
/// let kms = AwsKms::new().await?;
/// let (plaintext_key, encrypted_key) = kms
///     .generate_data_key("arn:aws:kms:us-east-1:123456789:key/my-key", 16)
///     .await?;
/// ```
#[derive(Debug, Clone)]
pub struct AwsKms {
    client: KmsClient,
    encryption_algorithm: EncryptionAlgorithmSpec,
    data_key_spec: DataKeySpec,
}

impl AwsKms {
    /// Create a new AWS KMS client with default configuration.
    ///
    /// This loads AWS credentials from the environment using the default
    /// credential provider chain.
    pub async fn new() -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = KmsClient::new(&config);

        Ok(Self {
            client,
            encryption_algorithm: EncryptionAlgorithmSpec::SymmetricDefault,
            data_key_spec: DataKeySpec::Aes128,
        })
    }

    /// Create a new AWS KMS client with custom configuration.
    pub async fn with_config(config: &aws_config::SdkConfig) -> Self {
        let client = KmsClient::new(config);

        Self {
            client,
            encryption_algorithm: EncryptionAlgorithmSpec::SymmetricDefault,
            data_key_spec: DataKeySpec::Aes128,
        }
    }

    /// Create a new AWS KMS client from properties.
    pub async fn from_properties(properties: &HashMap<String, String>) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = KmsClient::new(&config);

        let encryption_algorithm = properties
            .get(AWS_KMS_ENCRYPTION_ALGORITHM)
            .map(|s| parse_encryption_algorithm(s))
            .transpose()?
            .unwrap_or(EncryptionAlgorithmSpec::SymmetricDefault);

        let data_key_spec = properties
            .get(AWS_KMS_DATA_KEY_SPEC)
            .map(|s| parse_data_key_spec(s))
            .transpose()?
            .unwrap_or(DataKeySpec::Aes128);

        Ok(Self {
            client,
            encryption_algorithm,
            data_key_spec,
        })
    }

    /// Set the encryption algorithm to use.
    pub fn with_encryption_algorithm(mut self, algorithm: EncryptionAlgorithmSpec) -> Self {
        self.encryption_algorithm = algorithm;
        self
    }

    /// Set the data key specification.
    pub fn with_data_key_spec(mut self, spec: DataKeySpec) -> Self {
        self.data_key_spec = spec;
        self
    }
}

#[async_trait]
impl KeyManagementClient for AwsKms {
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey> {
        let response = self
            .client
            .encrypt()
            .key_id(master_key_id)
            .encryption_algorithm(self.encryption_algorithm.clone())
            .plaintext(Blob::new(key))
            .send()
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Unexpected, "Failed to encrypt key with AWS KMS")
                    .with_source(e)
            })?;

        let ciphertext = response
            .ciphertext_blob()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "AWS KMS encrypt response missing ciphertext",
                )
            })?
            .clone()
            .into_inner();

        let key_id = response.key_id().unwrap_or(master_key_id).to_string();

        let mut properties = HashMap::new();
        properties.insert("master-key-id".to_string(), master_key_id.to_string());
        properties.insert(
            "encryption-algorithm".to_string(),
            self.encryption_algorithm.as_str().to_string(),
        );

        Ok(EncryptedKey::builder()
            .key_id(key_id)
            .encrypted_key_metadata(ciphertext)
            .encrypted_by_id(master_key_id)
            .properties(properties)
            .build())
    }

    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>> {
        let master_key_id = encrypted_key
            .properties()
            .get("master-key-id")
            .map(|s| s.as_str())
            .or_else(|| encrypted_key.encrypted_by_id())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    "Encrypted key missing master-key-id property",
                )
            })?;

        let response = self
            .client
            .decrypt()
            .key_id(master_key_id)
            .encryption_algorithm(self.encryption_algorithm.clone())
            .ciphertext_blob(Blob::new(encrypted_key.encrypted_key_metadata()))
            .send()
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Unexpected, "Failed to decrypt key with AWS KMS")
                    .with_source(e)
            })?;

        let plaintext = response
            .plaintext()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "AWS KMS decrypt response missing plaintext",
                )
            })?
            .clone()
            .into_inner();

        Ok(plaintext)
    }

    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)> {
        // Validate key length matches the data key spec
        let expected_length = match self.data_key_spec {
            DataKeySpec::Aes128 => 16,
            DataKeySpec::Aes256 => 32,
            _ => {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!("Unsupported data key spec: {:?}", self.data_key_spec),
                ));
            }
        };

        if key_length != expected_length {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "Key length {} does not match data key spec {:?} (expected {})",
                    key_length, self.data_key_spec, expected_length
                ),
            ));
        }

        let response = self
            .client
            .generate_data_key()
            .key_id(master_key_id)
            .key_spec(self.data_key_spec.clone())
            .send()
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    "Failed to generate data key with AWS KMS",
                )
                .with_source(e)
            })?;

        let plaintext = response
            .plaintext()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "AWS KMS generate_data_key response missing plaintext",
                )
            })?
            .clone()
            .into_inner();

        let ciphertext = response
            .ciphertext_blob()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unexpected,
                    "AWS KMS generate_data_key response missing ciphertext",
                )
            })?
            .clone()
            .into_inner();

        let key_id = response.key_id().unwrap_or(master_key_id).to_string();

        let mut properties = HashMap::new();
        properties.insert("master-key-id".to_string(), master_key_id.to_string());

        let encrypted_key = EncryptedKey::builder()
            .key_id(key_id)
            .encrypted_key_metadata(ciphertext)
            .encrypted_by_id(master_key_id)
            .properties(properties)
            .build();

        Ok((plaintext, encrypted_key))
    }
}

fn parse_encryption_algorithm(s: &str) -> Result<EncryptionAlgorithmSpec> {
    match s.to_uppercase().as_str() {
        "SYMMETRIC_DEFAULT" => Ok(EncryptionAlgorithmSpec::SymmetricDefault),
        "RSAES_OAEP_SHA_1" => Ok(EncryptionAlgorithmSpec::RsaesOaepSha1),
        "RSAES_OAEP_SHA_256" => Ok(EncryptionAlgorithmSpec::RsaesOaepSha256),
        _ => Err(Error::new(
            ErrorKind::DataInvalid,
            format!("Unknown encryption algorithm: {}", s),
        )),
    }
}

fn parse_data_key_spec(s: &str) -> Result<DataKeySpec> {
    match s.to_uppercase().as_str() {
        "AES_128" | "AES128" => Ok(DataKeySpec::Aes128),
        "AES_256" | "AES256" => Ok(DataKeySpec::Aes256),
        _ => Err(Error::new(
            ErrorKind::DataInvalid,
            format!("Unknown data key spec: {}", s),
        )),
    }
}

/// Create an Arc-wrapped AWS KMS client.
pub async fn create_aws_kms() -> Result<Arc<dyn KeyManagementClient>> {
    Ok(Arc::new(AwsKms::new().await?))
}
