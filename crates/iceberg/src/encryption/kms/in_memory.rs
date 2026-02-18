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

//! In-memory KMS implementation for testing and development.
//!
//! **WARNING**: This implementation is NOT suitable for production use.
//! Keys are stored in memory only and will be lost when the process exits.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use uuid::Uuid;

use crate::encryption::key_management::KeyManagementClient;
use crate::encryption::{AesGcmEncryptor, EncryptionAlgorithm, SecureKey};
use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Property key for storing the master key ID used for wrapping.
const MASTER_KEY_ID_PROPERTY: &str = "master-key-id";

/// In-memory Key Management System for testing and development.
///
/// This KMS stores master keys in memory and uses AES-GCM to wrap/unwrap
/// data encryption keys. It is intended for testing and development only.
///
/// # Example
///
/// ```
/// use iceberg::encryption::KeyManagementClient;
/// use iceberg::encryption::kms::InMemoryKms;
///
/// # async fn example() -> iceberg::Result<()> {
/// let kms = InMemoryKms::new();
///
/// // Add a master key (or use auto-generated one)
/// kms.add_master_key("my-master-key")?;
///
/// // Generate a data encryption key
/// let (dek, encrypted_dek) = kms.generate_data_key("my-master-key", 16).await?;
///
/// // Later, unwrap the DEK
/// let unwrapped_dek = kms.unwrap_key(&encrypted_dek).await?;
/// assert_eq!(dek, unwrapped_dek);
/// # Ok(())
/// # }
/// ```
///
/// # Security Warning
///
/// This implementation is **NOT** suitable for production use because:
/// - Master keys are stored in memory without protection
/// - Keys are lost when the process exits
/// - No audit logging or access controls
/// - No key rotation capabilities at the master key level
///
/// For production use, implement `KeyManagementClient` with a proper KMS
/// like AWS KMS, Azure Key Vault, or HashiCorp Vault.
#[derive(Debug)]
pub struct InMemoryKms {
    /// Master keys indexed by key ID
    master_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Encryption algorithm to use
    algorithm: EncryptionAlgorithm,
}

impl Clone for InMemoryKms {
    fn clone(&self) -> Self {
        Self {
            master_keys: Arc::clone(&self.master_keys),
            algorithm: self.algorithm,
        }
    }
}

impl Default for InMemoryKms {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKms {
    /// Creates a new in-memory KMS.
    pub fn new() -> Self {
        Self {
            master_keys: Arc::new(RwLock::new(HashMap::new())),
            algorithm: EncryptionAlgorithm::Aes128Gcm,
        }
    }

    /// Adds a master key with the given ID.
    ///
    /// A new random key is generated for the given ID. If a key with this ID
    /// already exists, this method returns an error.
    pub fn add_master_key(&self, key_id: impl Into<String>) -> Result<()> {
        let key_id = key_id.into();
        let key = SecureKey::generate(self.algorithm);

        let mut keys = self.master_keys.write().map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to acquire write lock: {e}"),
            )
        })?;

        if keys.contains_key(&key_id) {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!("Master key already exists: {key_id}"),
            ));
        }

        keys.insert(key_id, key.as_bytes().to_vec());
        Ok(())
    }

    /// Gets or creates a master key with the given ID.
    ///
    /// If the key doesn't exist, a new random key is generated.
    fn get_or_create_master_key(&self, key_id: &str) -> Result<Vec<u8>> {
        // Try read first
        {
            let keys = self.master_keys.read().map_err(|e| {
                Error::new(
                    ErrorKind::Unexpected,
                    format!("Failed to acquire read lock: {e}"),
                )
            })?;

            if let Some(key) = keys.get(key_id) {
                return Ok(key.clone());
            }
        }

        // Need to create - acquire write lock
        let mut keys = self.master_keys.write().map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to acquire write lock: {e}"),
            )
        })?;

        // Double-check after acquiring write lock
        if let Some(key) = keys.get(key_id) {
            return Ok(key.clone());
        }

        // Generate new key
        let key = SecureKey::generate(self.algorithm);
        let key_bytes = key.as_bytes().to_vec();
        keys.insert(key_id.to_string(), key_bytes.clone());
        Ok(key_bytes)
    }

    /// Gets a master key by ID, returning an error if not found.
    fn get_master_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let keys = self.master_keys.read().map_err(|e| {
            Error::new(
                ErrorKind::Unexpected,
                format!("Failed to acquire read lock: {e}"),
            )
        })?;

        keys.get(key_id).cloned().ok_or_else(|| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("Master key not found: {key_id}"),
            )
        })
    }

    /// Returns the number of master keys currently stored.
    pub fn key_count(&self) -> usize {
        self.master_keys.read().map(|keys| keys.len()).unwrap_or(0)
    }

    /// Checks if a master key with the given ID exists.
    pub fn has_key(&self, key_id: &str) -> bool {
        self.master_keys
            .read()
            .map(|keys| keys.contains_key(key_id))
            .unwrap_or(false)
    }
}

#[async_trait]
impl KeyManagementClient for InMemoryKms {
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey> {
        let master_key_bytes = self.get_or_create_master_key(master_key_id)?;
        let master_key = SecureKey::new(master_key_bytes, self.algorithm)?;
        let encryptor = AesGcmEncryptor::new(master_key);

        // Encrypt the DEK using the master key
        let encrypted_key_metadata = encryptor.encrypt(key, None)?;

        let key_id = Uuid::new_v4().to_string();

        let mut properties = HashMap::new();
        properties.insert(
            MASTER_KEY_ID_PROPERTY.to_string(),
            master_key_id.to_string(),
        );

        Ok(EncryptedKey::builder()
            .key_id(key_id)
            .encrypted_key_metadata(encrypted_key_metadata)
            .encrypted_by_id("in-memory")
            .properties(properties)
            .build())
    }

    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>> {
        let master_key_id = encrypted_key
            .properties()
            .get(MASTER_KEY_ID_PROPERTY)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    "Encrypted key missing master-key-id property",
                )
            })?;

        let master_key_bytes = self.get_master_key(master_key_id)?;
        let master_key = SecureKey::new(master_key_bytes, self.algorithm)?;
        let encryptor = AesGcmEncryptor::new(master_key);

        encryptor.decrypt(encrypted_key.encrypted_key_metadata(), None)
    }

    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)> {
        // Validate key length
        if key_length != self.algorithm.key_length() {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "Invalid key length: expected {} for {:?}, got {}",
                    self.algorithm.key_length(),
                    self.algorithm,
                    key_length
                ),
            ));
        }

        // Generate a new random DEK
        let dek = SecureKey::generate(self.algorithm);
        let dek_bytes = dek.as_bytes().to_vec();

        // Wrap the DEK
        let encrypted_key = self.wrap_key(&dek_bytes, master_key_id).await?;

        Ok((dek_bytes, encrypted_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wrap_unwrap_roundtrip() {
        let kms = InMemoryKms::new();
        let dek = vec![0u8; 16];

        let encrypted = kms.wrap_key(&dek, "master-1").await.unwrap();
        assert_eq!(encrypted.encrypted_by_id(), Some("in-memory"));
        assert!(encrypted.properties().contains_key(MASTER_KEY_ID_PROPERTY));

        let unwrapped = kms.unwrap_key(&encrypted).await.unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[tokio::test]
    async fn test_generate_data_key() {
        let kms = InMemoryKms::new();

        let (dek, encrypted) = kms.generate_data_key("master-1", 16).await.unwrap();
        assert_eq!(dek.len(), 16);

        let unwrapped = kms.unwrap_key(&encrypted).await.unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[tokio::test]
    async fn test_generate_data_key_invalid_length() {
        let kms = InMemoryKms::new();

        let result = kms.generate_data_key("master-1", 32).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_master_keys() {
        let kms = InMemoryKms::new();
        let dek1 = vec![1u8; 16];
        let dek2 = vec![2u8; 16];

        let encrypted1 = kms.wrap_key(&dek1, "master-1").await.unwrap();
        let encrypted2 = kms.wrap_key(&dek2, "master-2").await.unwrap();

        let unwrapped1 = kms.unwrap_key(&encrypted1).await.unwrap();
        let unwrapped2 = kms.unwrap_key(&encrypted2).await.unwrap();

        assert_eq!(unwrapped1, dek1);
        assert_eq!(unwrapped2, dek2);
    }

    #[tokio::test]
    async fn test_wrong_master_key_fails_unwrap() {
        let kms1 = InMemoryKms::new();
        let kms2 = InMemoryKms::new();
        let dek = vec![0u8; 16];

        // Wrap with kms1's master key
        let encrypted = kms1.wrap_key(&dek, "master-1").await.unwrap();

        // Try to unwrap with kms2 (different master keys)
        // First, kms2 needs to have a master key with the same ID but different value
        kms2.add_master_key("master-1").unwrap();
        let result = kms2.unwrap_key(&encrypted).await;

        // Should fail because the master keys are different
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_add_master_key() {
        let kms = InMemoryKms::new();

        kms.add_master_key("my-key").unwrap();
        assert!(kms.has_key("my-key"));
        assert_eq!(kms.key_count(), 1);

        // Adding same key again should fail
        let result = kms.add_master_key("my-key");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_auto_create_master_key() {
        let kms = InMemoryKms::new();
        assert_eq!(kms.key_count(), 0);

        // Wrapping should auto-create the master key
        let dek = vec![0u8; 16];
        kms.wrap_key(&dek, "auto-created").await.unwrap();

        assert!(kms.has_key("auto-created"));
        assert_eq!(kms.key_count(), 1);
    }

    #[tokio::test]
    async fn test_clone_shares_state() {
        let kms1 = InMemoryKms::new();
        let kms2 = kms1.clone();

        kms1.add_master_key("shared-key").unwrap();
        assert!(kms2.has_key("shared-key"));
    }

    #[tokio::test]
    async fn test_encrypted_key_has_metadata() {
        let kms = InMemoryKms::new();
        let dek = vec![0u8; 16];

        let encrypted = kms.wrap_key(&dek, "master-1").await.unwrap();

        // Check that metadata is populated
        assert!(!encrypted.key_id().is_empty());
        assert_eq!(encrypted.encrypted_by_id(), Some("in-memory"));
    }
}
