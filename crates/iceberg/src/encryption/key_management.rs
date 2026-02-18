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

//! Key management client trait for encryption key operations.

use std::sync::Arc;

use async_trait::async_trait;

use crate::Result;
use crate::spec::EncryptedKey;

/// Trait for key management system clients.
///
/// This trait defines the interface for interacting with key management systems
/// like AWS KMS, Azure Key Vault, or custom implementations.
///
/// # Example
///
/// ```ignore
/// use iceberg::encryption::KeyManagementClient;
///
/// async fn use_kms(kms: &dyn KeyManagementClient) -> iceberg::Result<()> {
///     // Generate a new data encryption key
///     let (plaintext_key, encrypted_key) = kms
///         .generate_data_key("master-key-id", 16)
///         .await?;
///
///     // Later, unwrap the key to use it
///     let unwrapped = kms.unwrap_key(&encrypted_key).await?;
///     assert_eq!(plaintext_key, unwrapped);
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait KeyManagementClient: Send + Sync + std::fmt::Debug {
    /// Wrap (encrypt) a data encryption key using a master key.
    ///
    /// # Arguments
    /// * `key` - The data encryption key to wrap
    /// * `master_key_id` - The identifier of the master key to use for wrapping
    ///
    /// # Returns
    /// The wrapped key with metadata
    async fn wrap_key(&self, key: &[u8], master_key_id: &str) -> Result<EncryptedKey>;

    /// Unwrap (decrypt) a data encryption key.
    ///
    /// # Arguments
    /// * `encrypted_key` - The encrypted key with metadata
    ///
    /// # Returns
    /// The unwrapped data encryption key
    async fn unwrap_key(&self, encrypted_key: &EncryptedKey) -> Result<Vec<u8>>;

    /// Generate a new data encryption key.
    ///
    /// This method generates a new random key and wraps it with the specified
    /// master key in a single operation. This is more secure than generating
    /// a key separately and then wrapping it, as the plaintext key may only
    /// need to exist in memory briefly.
    ///
    /// # Arguments
    /// * `master_key_id` - The identifier of the master key to use
    /// * `key_length` - The length of the key to generate in bytes (typically 16 for AES-128)
    ///
    /// # Returns
    /// A tuple of (plaintext key, encrypted key metadata)
    async fn generate_data_key(
        &self,
        master_key_id: &str,
        key_length: usize,
    ) -> Result<(Vec<u8>, EncryptedKey)>;
}

/// Wrapper implementation to allow `Arc<dyn KeyManagementClient>` to implement `KeyManagementClient`.
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
}
