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

//! Encryption manager for data files

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::encryption::{
    AesGcmEncryptor, DecryptedInputFile, EncryptedOutputFile, EncryptionAlgorithm, KeyCache,
    KeyManagementClient, KeyMetadata, KeyRotationInfo, SecureKey,
};
use crate::io::{InputFile, OutputFile};
use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Configuration for encryption operations
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Master key identifier
    pub master_key_id: String,

    /// Encryption algorithm to use
    pub algorithm: EncryptionAlgorithm,

    /// Key rotation period in days
    pub key_rotation_days: u32,

    /// Additional properties
    pub properties: HashMap<String, String>,
}

impl EncryptionConfig {
    /// Create a new encryption configuration
    pub fn new(master_key_id: String, algorithm: EncryptionAlgorithm) -> Self {
        Self {
            master_key_id,
            algorithm,
            key_rotation_days: 730, // 2 years default
            properties: HashMap::new(),
        }
    }

    /// Set the key rotation period
    pub fn with_key_rotation_days(mut self, days: u32) -> Self {
        self.key_rotation_days = days;
        self
    }

    /// Add a property
    pub fn with_property(mut self, key: String, value: String) -> Self {
        self.properties.insert(key, value);
        self
    }
}

/// Trait for encryption managers
#[async_trait]
pub trait EncryptionManager: Send + Sync {
    /// Encrypt a data file
    async fn encrypt_data_file(&self, plain_output: OutputFile) -> Result<EncryptedOutputFile>;

    /// Decrypt a data file
    async fn decrypt_data_file(&self, encrypted_input: InputFile) -> Result<DecryptedInputFile>;

    /// Rotate encryption keys
    async fn rotate_keys(&self) -> Result<()>;

    /// Get the current key metadata
    async fn current_key_metadata(&self) -> Result<KeyMetadata>;

    /// Check if key rotation is needed
    async fn needs_rotation(&self) -> Result<bool>;

    /// Get the raw encryption key for native format encryption
    async fn get_raw_key(&self, key_metadata: &KeyMetadata) -> Result<Vec<u8>>;
}

/// Standard implementation of encryption manager
#[derive(Clone)]
pub struct StandardEncryptionManager {
    /// Key management client
    kms: Arc<dyn KeyManagementClient>,

    /// Encryption configuration
    config: EncryptionConfig,

    /// Key cache
    cache: KeyCache,

    /// Key rotation information
    rotation_info: Arc<RwLock<KeyRotationInfo>>,

    /// Table identifier
    table_id: String,
}

impl StandardEncryptionManager {
    /// Create a new standard encryption manager
    pub async fn new(
        kms: Arc<dyn KeyManagementClient>,
        config: EncryptionConfig,
        table_id: String,
    ) -> Result<Self> {
        // Generate initial key
        let initial_key = Self::generate_initial_key(&kms, &config, &table_id).await?;

        Ok(Self {
            kms,
            config,
            cache: KeyCache::new(),
            rotation_info: Arc::new(RwLock::new(KeyRotationInfo::new(initial_key))),
            table_id,
        })
    }

    /// Create with existing key rotation info
    pub fn with_rotation_info(
        kms: Arc<dyn KeyManagementClient>,
        config: EncryptionConfig,
        table_id: String,
        rotation_info: KeyRotationInfo,
    ) -> Self {
        Self {
            kms,
            config,
            cache: KeyCache::new(),
            rotation_info: Arc::new(RwLock::new(rotation_info)),
            table_id,
        }
    }

    /// Generate initial key metadata
    async fn generate_initial_key(
        kms: &Arc<dyn KeyManagementClient>,
        config: &EncryptionConfig,
        table_id: &str,
    ) -> Result<KeyMetadata> {
        // Generate data encryption key
        let (plaintext_key, encrypted_key) = kms
            .generate_data_key(&config.master_key_id, config.algorithm.key_length())
            .await?;

        // Generate AAD prefix
        let aad_prefix = AesGcmEncryptor::generate_aad_prefix();

        // Create key metadata
        let mut key_metadata = KeyMetadata::new(
            Uuid::new_v4().to_string(),
            encrypted_key,
            config.algorithm.to_string(),
            aad_prefix,
        );

        key_metadata
            .properties
            .insert("table-id".to_string(), table_id.to_string());
        key_metadata
            .properties
            .insert("kms-type".to_string(), kms.kms_type().to_string());

        Ok(key_metadata)
    }

    /// Get or create encryptor for a key
    async fn get_or_create_encryptor(
        &self,
        key_metadata: &KeyMetadata,
    ) -> Result<Arc<AesGcmEncryptor>> {
        let key_id = &key_metadata.key_id;

        // Check cache first
        if let Some(secure_key) = self.cache.get(key_id).await {
            let algorithm = EncryptionAlgorithm::from_str(&key_metadata.algorithm)?;
            return Ok(Arc::new(AesGcmEncryptor::new(
                algorithm,
                secure_key,
                key_metadata.aad_prefix.clone(),
            )?));
        }

        // Unwrap the key using KMS
        let plaintext_key = self.kms.unwrap_key(&key_metadata.encrypted_key).await?;
        let secure_key = SecureKey::new(plaintext_key);

        // Cache the key
        self.cache.put(key_id.clone(), secure_key.clone()).await?;

        // Create encryptor
        let algorithm = EncryptionAlgorithm::from_str(&key_metadata.algorithm)?;
        Ok(Arc::new(AesGcmEncryptor::new(
            algorithm,
            secure_key,
            key_metadata.aad_prefix.clone(),
        )?))
    }

    /// Get the raw encryption key for native format encryption
    pub async fn get_raw_key(&self, key_metadata: &KeyMetadata) -> Result<Vec<u8>> {
        // Unwrap the key using KMS
        self.kms.unwrap_key(&key_metadata.encrypted_key).await
    }

    /// Get encryptor for a specific key ID
    async fn get_encryptor_by_key_id(&self, key_id: &str) -> Result<Arc<AesGcmEncryptor>> {
        let rotation_info = self.rotation_info.read().await;

        let key_metadata = rotation_info.find_key(key_id).ok_or_else(|| {
            Error::new(ErrorKind::DataInvalid, format!("Key not found: {}", key_id))
        })?;

        self.get_or_create_encryptor(key_metadata).await
    }
}

#[async_trait]
impl EncryptionManager for StandardEncryptionManager {
    async fn encrypt_data_file(&self, plain_output: OutputFile) -> Result<EncryptedOutputFile> {
        let rotation_info = self.rotation_info.read().await;
        let key_metadata = &rotation_info.current_key;

        // Get or create encryptor
        let encryptor = self.get_or_create_encryptor(key_metadata).await?;

        Ok(EncryptedOutputFile::new(
            plain_output,
            key_metadata.clone(),
            encryptor,
        ))
    }

    async fn decrypt_data_file(&self, encrypted_input: InputFile) -> Result<DecryptedInputFile> {
        // Extract key ID from file metadata (this would come from the data file metadata)
        // For now, use the current key as a placeholder
        let rotation_info = self.rotation_info.read().await;
        let key_metadata = &rotation_info.current_key;

        // Get or create decryptor
        let decryptor = self.get_or_create_encryptor(key_metadata).await?;

        Ok(DecryptedInputFile::new(
            encrypted_input,
            key_metadata.clone(),
            decryptor,
        ))
    }

    async fn rotate_keys(&self) -> Result<()> {
        let mut rotation_info = self.rotation_info.write().await;

        if !rotation_info.needs_rotation() {
            return Ok(());
        }

        // Generate new key
        let (plaintext_key, encrypted_key) = self
            .kms
            .generate_data_key(
                &self.config.master_key_id,
                self.config.algorithm.key_length(),
            )
            .await?;

        // Generate new AAD prefix
        let aad_prefix = AesGcmEncryptor::generate_aad_prefix();

        // Create new key metadata
        let new_key = rotation_info.current_key.rotate(encrypted_key, aad_prefix);

        // Rotate keys
        rotation_info.rotate(new_key);

        // Clear cache to force re-fetching keys
        self.cache.clear().await;

        Ok(())
    }

    async fn current_key_metadata(&self) -> Result<KeyMetadata> {
        let rotation_info = self.rotation_info.read().await;
        Ok(rotation_info.current_key.clone())
    }

    async fn needs_rotation(&self) -> Result<bool> {
        let rotation_info = self.rotation_info.read().await;
        Ok(rotation_info.needs_rotation())
    }

    async fn get_raw_key(&self, key_metadata: &KeyMetadata) -> Result<Vec<u8>> {
        // Unwrap the key using KMS
        self.kms.unwrap_key(&key_metadata.encrypted_key).await
    }
}

/// Builder for StandardEncryptionManager
pub struct StandardEncryptionManagerBuilder {
    kms: Option<Arc<dyn KeyManagementClient>>,
    config: Option<EncryptionConfig>,
    table_id: Option<String>,
    rotation_info: Option<KeyRotationInfo>,
}

impl StandardEncryptionManagerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            kms: None,
            config: None,
            table_id: None,
            rotation_info: None,
        }
    }

    /// Set the KMS client
    pub fn kms(mut self, kms: Arc<dyn KeyManagementClient>) -> Self {
        self.kms = Some(kms);
        self
    }

    /// Set the encryption configuration
    pub fn config(mut self, config: EncryptionConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the table ID
    pub fn table_id(mut self, table_id: String) -> Self {
        self.table_id = Some(table_id);
        self
    }

    /// Set existing rotation info
    pub fn rotation_info(mut self, rotation_info: KeyRotationInfo) -> Self {
        self.rotation_info = Some(rotation_info);
        self
    }

    /// Build the encryption manager
    pub async fn build(self) -> Result<StandardEncryptionManager> {
        let kms = self
            .kms
            .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "KMS client is required"))?;

        let config = self
            .config
            .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "Encryption config is required"))?;

        let table_id = self
            .table_id
            .ok_or_else(|| Error::new(ErrorKind::DataInvalid, "Table ID is required"))?;

        if let Some(rotation_info) = self.rotation_info {
            Ok(StandardEncryptionManager::with_rotation_info(
                kms,
                config,
                table_id,
                rotation_info,
            ))
        } else {
            StandardEncryptionManager::new(kms, config, table_id).await
        }
    }
}

impl Default for StandardEncryptionManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::kms::InMemoryKms;

    #[tokio::test]
    async fn test_standard_encryption_manager() {
        let kms = Arc::new(InMemoryKms::new());
        let config = EncryptionConfig::new(
            "test-master-key".to_string(),
            EncryptionAlgorithm::Aes256Gcm,
        );
        let table_id = "test-table-123";

        let manager = StandardEncryptionManager::new(kms, config, table_id.to_string())
            .await
            .unwrap();

        // Test getting current key metadata
        let key_metadata = manager.current_key_metadata().await.unwrap();
        assert_eq!(key_metadata.algorithm, "AES-256-GCM");

        // Test that rotation is not needed initially
        assert!(!manager.needs_rotation().await.unwrap());
    }

    #[tokio::test]
    async fn test_encryption_manager_builder() {
        let kms = Arc::new(InMemoryKms::new());
        let config = EncryptionConfig::new(
            "test-master-key".to_string(),
            EncryptionAlgorithm::Aes128Gcm,
        );

        let manager = StandardEncryptionManagerBuilder::new()
            .kms(kms)
            .config(config)
            .table_id("test-table".to_string())
            .build()
            .await
            .unwrap();

        let key_metadata = manager.current_key_metadata().await.unwrap();
        assert_eq!(key_metadata.algorithm, "AES-128-GCM");
    }
}

