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

//! AWS KMS client implementation

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{DataKeySpec, EncryptionAlgorithmSpec};
use aws_sdk_kms::{Client, Config};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use uuid::Uuid;

use crate::encryption::key_management::KeyManagementClient;
use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// AWS KMS client for key management
#[derive(Clone, Debug)]
pub struct AwsKmsClient {
    client: Client,
    encryption_context: HashMap<String, String>,
}

impl AwsKmsClient {
    /// Create a new AWS KMS client with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            client: Client::from_conf(config),
            encryption_context: HashMap::new(),
        }
    }

    /// Create a new AWS KMS client from the default configuration
    pub async fn from_env() -> Result<Self> {
        let config = aws_config::load_from_env().await;
        let kms_config = aws_sdk_kms::config::Builder::from(&config).build();
        Ok(Self::new(kms_config))
    }

    /// Set encryption context for all operations
    pub fn with_encryption_context(mut self, context: HashMap<String, String>) -> Self {
        self.encryption_context = context;
        self
    }

    /// Add an entry to the encryption context
    pub fn add_encryption_context(&mut self, key: String, value: String) {
        self.encryption_context.insert(key, value);
    }
}

#[async_trait]
impl KeyManagementClient for AwsKmsClient {
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey> {
        // Prepare encryption context
        let mut context = self.encryption_context.clone();
        context.insert("iceberg.table.id".to_string(), Uuid::new_v4().to_string());
        context.insert(
            "iceberg.encryption.timestamp".to_string(),
            Utc::now().to_rfc3339(),
        );

        // Encrypt the data key
        let response = self
            .client
            .encrypt()
            .key_id(master_key_id)
            .plaintext(Blob::new(key.to_vec()))
            .set_encryption_context(Some(context.clone()))
            .encryption_algorithm(EncryptionAlgorithmSpec::SymmetricDefault)
            .send()
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AWS KMS encrypt failed").with_source(e)
            })?;

        let ciphertext_blob = response
            .ciphertext_blob
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "AWS KMS returned no ciphertext"))?;

        // Create encrypted key metadata
        let mut properties = HashMap::new();
        properties.insert("kms-type".to_string(), "aws-kms".to_string());
        properties.insert("created-at".to_string(), Utc::now().timestamp().to_string());
        properties.insert("master-key-id".to_string(), master_key_id.to_string());

        // Store encryption context in properties
        for (k, v) in context {
            properties.insert(format!("context.{}", k), v);
        }

        if let Some(key_id) = response.key_id {
            properties.insert("aws-key-arn".to_string(), key_id);
        }

        Ok(EncryptedKey::builder()
            .key_id(Uuid::new_v4().to_string())
            .encrypted_key_metadata(ciphertext_blob.into_inner())
            .encrypted_by_id(format!("aws-kms:{}", master_key_id))
            .properties(properties)
            .build())
    }

    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>> {
        // Reconstruct encryption context from properties
        let mut context = HashMap::new();
        for (key, value) in encrypted_key.properties() {
            if key.starts_with("context.") {
                let context_key = key.strip_prefix("context.").unwrap();
                context.insert(context_key.to_string(), value.clone());
            }
        }

        // Decrypt the data key
        let response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted_key.encrypted_key_metadata().to_vec()))
            .set_encryption_context(Some(context))
            .send()
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AWS KMS decrypt failed").with_source(e)
            })?;

        let plaintext = response
            .plaintext
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "AWS KMS returned no plaintext"))?;

        Ok(plaintext.into_inner())
    }

    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)> {
        // Determine key spec based on length
        let key_spec = match key_length {
            16 => DataKeySpec::Aes128,
            32 => DataKeySpec::Aes256,
            _ => {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!("Unsupported key length: {}", key_length),
                ));
            }
        };

        // Prepare encryption context
        let mut context = self.encryption_context.clone();
        context.insert("iceberg.table.id".to_string(), Uuid::new_v4().to_string());
        context.insert(
            "iceberg.encryption.timestamp".to_string(),
            Utc::now().to_rfc3339(),
        );

        // Generate data key
        let response = self
            .client
            .generate_data_key()
            .key_id(master_key_id)
            .key_spec(key_spec)
            .set_encryption_context(Some(context.clone()))
            .send()
            .await
            .map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AWS KMS generate data key failed").with_source(e)
            })?;

        let plaintext = response
            .plaintext
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "AWS KMS returned no plaintext"))?;

        let ciphertext = response
            .ciphertext_blob
            .ok_or_else(|| Error::new(ErrorKind::Unexpected, "AWS KMS returned no ciphertext"))?;

        // Create encrypted key metadata
        let mut properties = HashMap::new();
        properties.insert("kms-type".to_string(), "aws-kms".to_string());
        properties.insert("created-at".to_string(), Utc::now().timestamp().to_string());
        properties.insert("master-key-id".to_string(), master_key_id.to_string());
        properties.insert("key-spec".to_string(), format!("{}-bit", key_length * 8));

        // Store encryption context in properties
        for (k, v) in context {
            properties.insert(format!("context.{}", k), v);
        }

        if let Some(key_id) = response.key_id {
            properties.insert("aws-key-arn".to_string(), key_id);
        }

        let encrypted_key = EncryptedKey::builder()
            .key_id(Uuid::new_v4().to_string())
            .encrypted_key_metadata(ciphertext.into_inner())
            .encrypted_by_id(format!("aws-kms:{}", master_key_id))
            .properties(properties)
            .build();

        Ok((plaintext.into_inner(), encrypted_key))
    }

    fn kms_type(&self) -> &str {
        "aws-kms"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_aws_kms_integration() {
        // This test requires actual AWS credentials and a KMS key
        // Set AWS_PROFILE or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
        // and provide a KMS key ID to test

        let kms_key_id = std::env::var("TEST_AWS_KMS_KEY_ID")
            .expect("TEST_AWS_KMS_KEY_ID must be set for integration test");

        let client = AwsKmsClient::from_env().await.unwrap();

        // Test generating a data key
        let (plaintext, encrypted_key) = client.generate_data_key(&kms_key_id, 32).await.unwrap();

        assert_eq!(plaintext.len(), 32);

        // Test unwrapping the key
        let unwrapped = client.unwrap_key(&encrypted_key).await.unwrap();
        assert_eq!(unwrapped, plaintext);

        // Test wrapping a custom key
        let custom_key = b"another-32-byte-key-for-testing!";
        let wrapped = client.wrap_key(custom_key, &kms_key_id).await.unwrap();

        let unwrapped_custom = client.unwrap_key(&wrapped).await.unwrap();
        assert_eq!(unwrapped_custom, custom_key);
    }
}

