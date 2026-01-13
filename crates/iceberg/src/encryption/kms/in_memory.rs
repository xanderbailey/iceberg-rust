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

//! In-memory KMS implementation for testing

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use rand::RngCore;
use uuid::Uuid;

use crate::encryption::crypto::{AesGcmEncryptor, EncryptionAlgorithm, SecureKey};
use crate::encryption::key_management::KeyManagementClient;
use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// In-memory KMS for testing and development
///
/// This implementation stores master keys in memory and uses them to
/// encrypt/decrypt data encryption keys. NOT for production use.
#[derive(Debug, Clone)]
pub struct InMemoryKms {
    /// Master keys stored by ID
    master_keys: Arc<Mutex<HashMap<String, SecureKey>>>,
    /// Default algorithm for encryption
    algorithm: EncryptionAlgorithm,
}

impl InMemoryKms {
    /// Create a new in-memory KMS
    pub fn new() -> Self {
        Self::with_algorithm(EncryptionAlgorithm::Aes256Gcm)
    }

    /// Create a new in-memory KMS with specified algorithm
    pub fn with_algorithm(algorithm: EncryptionAlgorithm) -> Self {
        Self {
            master_keys: Arc::new(Mutex::new(HashMap::new())),
            algorithm,
        }
    }

    /// Add a master key to the KMS
    pub fn add_master_key(&self, key_id: String) -> Result<()> {
        let key = SecureKey::generate(self.algorithm);
        let mut keys = self
            .master_keys
            .lock()
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Failed to lock master keys"))?;
        keys.insert(key_id, key);
        Ok(())
    }

    /// Generate a master key if it doesn't exist
    fn ensure_master_key(&self, key_id: &str) -> Result<()> {
        let mut keys = self
            .master_keys
            .lock()
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Failed to lock master keys"))?;

        if !keys.contains_key(key_id) {
            let key = SecureKey::generate(self.algorithm);
            keys.insert(key_id.to_string(), key);
        }

        Ok(())
    }

    /// Get a master key by ID
    fn get_master_key(&self, key_id: &str) -> Result<SecureKey> {
        let keys = self
            .master_keys
            .lock()
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Failed to lock master keys"))?;

        keys.get(key_id).cloned().ok_or_else(|| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Master key not found: {}", key_id),
            )
        })
    }
}

impl Default for InMemoryKms {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyManagementClient for InMemoryKms {
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey> {
        self.ensure_master_key(master_key_id)?;
        let master_key = self.get_master_key(master_key_id)?;

        // Create encryptor with master key
        let aad_prefix = AesGcmEncryptor::generate_aad_prefix();
        let encryptor = AesGcmEncryptor::new(self.algorithm, master_key, aad_prefix)?;

        // Encrypt the data key
        let aad = master_key_id.as_bytes();
        let encrypted_data = encryptor.encrypt(key, aad).await?;

        // Create encrypted key metadata
        let mut properties = HashMap::new();
        properties.insert("kms-type".to_string(), "in-memory".to_string());
        properties.insert("algorithm".to_string(), self.algorithm.to_string());
        properties.insert("created-at".to_string(), Utc::now().timestamp().to_string());
        properties.insert("master-key-id".to_string(), master_key_id.to_string());
        properties.insert(
            "aad-prefix".to_string(),
            BASE64.encode(&encryptor.aad_prefix()),
        );

        Ok(EncryptedKey::builder()
            .key_id(Uuid::new_v4().to_string())
            .encrypted_key_metadata(encrypted_data.to_vec())
            .encrypted_by_id(format!("in-memory-kms:{}", master_key_id))
            .properties(properties)
            .build())
    }

    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>> {
        // Extract master key ID from properties
        let master_key_id = encrypted_key
            .properties()
            .get("master-key-id")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    "Missing master-key-id in encrypted key",
                )
            })?;

        let master_key = self.get_master_key(master_key_id)?;

        // Extract AAD prefix from properties
        let aad_prefix_str = encrypted_key
            .properties()
            .get("aad-prefix")
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    "Missing aad-prefix in encrypted key",
                )
            })?;

        let aad_prefix = BASE64.decode(aad_prefix_str).map_err(|e| {
            Error::new(ErrorKind::DataInvalid, "Invalid aad-prefix encoding").with_source(e)
        })?;

        // Create decryptor with master key
        let encryptor = AesGcmEncryptor::new(self.algorithm, master_key, aad_prefix)?;

        // Decrypt the data key
        let aad = master_key_id.as_bytes();
        let decrypted = encryptor
            .decrypt(encrypted_key.encrypted_key_metadata(), aad)
            .await?;

        Ok(decrypted.to_vec())
    }

    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)> {
        self.ensure_master_key(master_key_id)?;

        // Generate random data key
        let mut data_key = vec![0u8; key_length];
        rand::rngs::OsRng.fill_bytes(&mut data_key);

        // Wrap the key
        let encrypted_key = self.wrap_key(&data_key, master_key_id).await?;

        Ok((data_key, encrypted_key))
    }

    fn kms_type(&self) -> &str {
        "in-memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_kms_wrap_unwrap() {
        let kms = InMemoryKms::new();
        let master_key_id = "test-master-key";

        // Generate a test data key
        let data_key = b"this-is-a-32-byte-data-key-12345";

        // Wrap the key
        let encrypted_key = kms.wrap_key(data_key, master_key_id).await.unwrap();

        // Verify encrypted key properties
        assert!(encrypted_key.properties().contains_key("master-key-id"));
        assert_eq!(
            encrypted_key.properties().get("kms-type"),
            Some(&"in-memory".to_string())
        );

        // Unwrap the key
        let unwrapped = kms.unwrap_key(&encrypted_key).await.unwrap();

        // Verify the unwrapped key matches
        assert_eq!(unwrapped, data_key);
    }

    #[tokio::test]
    async fn test_generate_data_key() {
        let kms = InMemoryKms::new();
        let master_key_id = "test-master-key";

        // Generate a 32-byte data key
        let (plaintext, encrypted_key) = kms.generate_data_key(master_key_id, 32).await.unwrap();

        // Verify key length
        assert_eq!(plaintext.len(), 32);

        // Verify we can unwrap it
        let unwrapped = kms.unwrap_key(&encrypted_key).await.unwrap();
        assert_eq!(unwrapped, plaintext);
    }

    #[tokio::test]
    async fn test_multiple_master_keys() {
        let kms = InMemoryKms::new();

        // Add multiple master keys
        kms.add_master_key("key-1".to_string()).unwrap();
        kms.add_master_key("key-2".to_string()).unwrap();

        // Generate data keys with different master keys
        let (data1, encrypted1) = kms.generate_data_key("key-1", 32).await.unwrap();
        let (data2, encrypted2) = kms.generate_data_key("key-2", 32).await.unwrap();

        // Keys should be different
        assert_ne!(data1, data2);

        // Each should unwrap correctly
        let unwrapped1 = kms.unwrap_key(&encrypted1).await.unwrap();
        let unwrapped2 = kms.unwrap_key(&encrypted2).await.unwrap();

        assert_eq!(unwrapped1, data1);
        assert_eq!(unwrapped2, data2);
    }

    #[tokio::test]
    async fn test_wrong_master_key_fails() {
        let kms = InMemoryKms::new();

        // Generate a data key
        let (_, encrypted_key) = kms.generate_data_key("key-1", 32).await.unwrap();

        // Create a new KMS instance (without the master key)
        let kms2 = InMemoryKms::new();

        // Unwrapping should fail
        let result = kms2.unwrap_key(&encrypted_key).await;
        assert!(result.is_err());
    }
}

