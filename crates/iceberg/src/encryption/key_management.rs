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

//! Key management client trait for encryption key operations

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Trait for key management system clients
///
/// This trait defines the interface for interacting with key management systems
/// like AWS KMS, Azure Key Vault, or custom implementations.
#[async_trait]
pub trait KeyManagementClient: Send + Sync {
    /// Wrap (encrypt) a data encryption key using a master key
    ///
    /// # Arguments
    /// * `key` - The data encryption key to wrap
    /// * `master_key_id` - The identifier of the master key to use for wrapping
    ///
    /// # Returns
    /// The wrapped key with metadata
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey>;

    /// Unwrap (decrypt) a data encryption key
    ///
    /// # Arguments
    /// * `encrypted_key` - The encrypted key with metadata
    ///
    /// # Returns
    /// The unwrapped data encryption key
    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>>;

    /// Generate a new data encryption key
    ///
    /// # Arguments
    /// * `master_key_id` - The identifier of the master key to use
    /// * `key_length` - The length of the key to generate in bytes
    ///
    /// # Returns
    /// A tuple of (plaintext key, encrypted key metadata)
    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)>;

    /// Check if a key needs rotation based on its age
    ///
    /// # Arguments
    /// * `encrypted_key` - The encrypted key to check
    /// * `max_age_days` - Maximum age in days before rotation is needed
    ///
    /// # Returns
    /// True if the key needs rotation
    async fn needs_rotation(
        &self,
        encrypted_key: &EncryptedKey,
        max_age_days: u32,
    ) -> Result<bool> {
        // Default implementation based on key properties
        if let Some(created_at) = encrypted_key.properties().get("created-at") {
            if let Ok(timestamp) = created_at.parse::<i64>() {
                let age_days = (chrono::Utc::now().timestamp() - timestamp) / 86400;
                return Ok(age_days > max_age_days as i64);
            }
        }
        // If no creation time, assume rotation is needed
        Ok(true)
    }

    /// Get the key management system type identifier
    fn kms_type(&self) -> &str;
}

/// Wrapper to make Arc<dyn KeyManagementClient> implement KeyManagementClient
#[async_trait]
impl KeyManagementClient for Arc<dyn KeyManagementClient> {
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey> {
        self.as_ref().wrap_key(key, master_key_id).await
    }

    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>> {
        self.as_ref().unwrap_key(encrypted_key).await
    }

    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)> {
        self.as_ref()
            .generate_data_key(master_key_id, key_length)
            .await
    }

    async fn needs_rotation(
        &self,
        encrypted_key: &EncryptedKey,
        max_age_days: u32,
    ) -> Result<bool> {
        self.as_ref()
            .needs_rotation(encrypted_key, max_age_days)
            .await
    }

    fn kms_type(&self) -> &str {
        self.as_ref().kms_type()
    }
}

