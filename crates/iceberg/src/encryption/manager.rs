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

//! Encryption manager for file-level encryption and two-layer envelope key management.
//!
//! [`EncryptionManager`] provides file-level `decrypt` / `encrypt`
//! operations matching Java's `org.apache.iceberg.encryption.EncryptionManager`,
//! using envelope encryption:
//! - A master key (in KMS) wraps a Key Encryption Key (KEK)
//! - The KEK wraps Data Encryption Keys (DEKs) locally

use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use chrono::Utc;
use moka::future::Cache;
use uuid::Uuid;

use super::crypto::{AesGcmCipher, AesKeySize, SecureKey, SensitiveBytes};
use super::io::EncryptedOutputFile;
use super::key_metadata::StandardKeyMetadata;
use super::keys::{KeyEncryptionKey, ManifestEncryptionKey};
use super::kms::KeyManagementClient;
use crate::io::OutputFile;
use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Default cache TTL for unwrapped KEKs.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Default AAD prefix length in bytes.
/// Matches Java's `TableProperties.ENCRYPTION_AAD_LENGTH_DEFAULT`.
const AAD_PREFIX_LENGTH: usize = 16;

/// File-level encryption manager using two-layer envelope encryption.
///
/// Uses an async cache for unwrapped KEK bytes to avoid repeated KMS calls.
#[derive(typed_builder::TypedBuilder)]
#[builder(mutators(
    /// Add an encryption key (KEK or wrapped key metadata entry).
    pub fn add_encryption_key(&mut self, key: EncryptedKey) {
        self.encryption_keys
            .write()
            .expect("encryption_keys lock poisoned")
            .insert(key.key_id().to_string(), key);
    }
    /// Set all encryption keys from table metadata.
    pub fn encryption_keys(&mut self, keys: HashMap<String, EncryptedKey>) {
        self.encryption_keys = RwLock::new(keys);
    }
))]
pub struct EncryptionManager {
    kms_client: Arc<dyn KeyManagementClient>,
    #[builder(
        default = Cache::builder().time_to_live(DEFAULT_CACHE_TTL).build(),
        setter(skip)
    )]
    kek_cache: Cache<String, SensitiveBytes>,
    /// AES key size for DEK generation. Defaults to 128-bit.
    #[builder(default = AesKeySize::default())]
    key_size: AesKeySize,
    /// Master key ID from table property `encryption.key-id`.
    #[builder(setter(into))]
    table_key_id: String,
    /// All encryption keys from table metadata (KEKs and wrapped key metadata entries).
    /// Newly created KEKs and wrapped manifest-list entries are inserted here so
    /// callers can snapshot the full set at commit time via [`EncryptionManager::with_encryption_keys`].
    #[builder(default = RwLock::new(HashMap::new()), via_mutators)]
    encryption_keys: RwLock<HashMap<String, EncryptedKey>>,
}

impl fmt::Debug for EncryptionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionManager")
            .field("key_size", &self.key_size)
            .field("table_key_id", &self.table_key_id)
            .finish_non_exhaustive()
    }
}

impl EncryptionManager {
    /// Encrypt a file with AGS1 stream encryption.
    ///
    /// Returns an [`EncryptedOutputFile`] that transparently encrypts on
    /// write, along with key metadata for later decryption.
    pub fn encrypt(&self, raw_output: OutputFile) -> EncryptedOutputFile {
        let dek = SecureKey::generate(self.key_size);
        let aad_prefix = Self::generate_aad_prefix();
        let metadata = StandardKeyMetadata::new(dek.as_bytes()).with_aad_prefix(&aad_prefix);
        EncryptedOutputFile::new(raw_output, metadata)
    }

    /// Wrap a manifest list key metadata with a KEK for storage in table metadata.
    ///
    /// Stores the resulting wrapped entry (and any newly created KEK) in the
    /// manager's internal `encryption_keys` map. Callers persist the full set
    /// at commit time via [`Self::with_encryption_keys`].
    ///
    /// Returns the `key_id` of the wrapped entry, which should be recorded on
    /// the snapshot as `encryption_key_id` so readers can locate it later.
    pub async fn encrypt_manifest_list_key_metadata(
        &self,
        key_metadata: &StandardKeyMetadata,
    ) -> Result<String> {
        let kek = match self.find_active_kek() {
            Some(existing) => existing,
            None => self.create_kek().await?,
        };

        let kek_bytes = self.unwrap_key_encryption_key(&kek).await?;
        let aad = kek.timestamp_aad();
        let serialized = key_metadata.encode()?;
        let wrapped_metadata = self.wrap_dek_with_kek(&serialized, &kek_bytes, Some(aad))?;

        let entry =
            ManifestEncryptionKey::new(Uuid::new_v4().to_string(), wrapped_metadata, kek.key_id());
        let entry_id = entry.key_id().to_string();
        self.insert_encryption_key(entry.into());
        Ok(entry_id)
    }

    /// Decrypt a manifest list key metadata previously wrapped via
    /// [`Self::encrypt_manifest_list_key_metadata`].
    ///
    /// Looks up the entry by `encryption_key_id` (typically read from the
    /// snapshot) in the manager's `encryption_keys` map and parses it as a
    /// [`ManifestEncryptionKey`] — yielding a clear error if it's actually
    /// a KEK or otherwise malformed, rather than a generic crypto failure.
    pub async fn decrypt_manifest_list_key_metadata(
        &self,
        encryption_key_id: &str,
    ) -> Result<StandardKeyMetadata> {
        let entry = self.manifest_entry(encryption_key_id)?;
        let bytes = self
            .decrypt_dek(entry.kek_id(), entry.encrypted_key_metadata())
            .await?;
        StandardKeyMetadata::decode(bytes.as_bytes())
    }

    /// Borrow the encryption keys held by this manager.
    ///
    /// Use at commit time to persist newly created KEKs and wrapped
    /// manifest-list entries into `TableMetadata.encryption_keys`.
    pub fn with_encryption_keys<F, R>(&self, f: F) -> R
    where F: FnOnce(&HashMap<String, EncryptedKey>) -> R {
        let keys = self
            .encryption_keys
            .read()
            .expect("encryption_keys lock poisoned");
        f(&keys)
    }

    fn insert_encryption_key(&self, key: EncryptedKey) {
        self.encryption_keys
            .write()
            .expect("encryption_keys lock poisoned")
            .insert(key.key_id().to_string(), key);
    }

    /// Look up `key_id` in the unified map and parse it as a KEK, validating
    /// `encrypted_by_id == table_key_id`.
    fn kek(&self, key_id: &str) -> Result<KeyEncryptionKey> {
        let key = self
            .encryption_keys
            .read()
            .expect("encryption_keys lock poisoned")
            .get(key_id)
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorKind::DataInvalid, format!("KEK not found: {key_id}"))
            })?;
        KeyEncryptionKey::try_from_encrypted_key(key, &self.table_key_id)
    }

    /// Look up `key_id` in the unified map and parse it as a manifest-list
    /// entry. Fails if the id refers to a KEK or a malformed entry.
    fn manifest_entry(&self, key_id: &str) -> Result<ManifestEncryptionKey> {
        let key = self
            .encryption_keys
            .read()
            .expect("encryption_keys lock poisoned")
            .get(key_id)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    format!("Manifest encryption key '{key_id}' not found"),
                )
            })?;
        ManifestEncryptionKey::try_from_encrypted_key(key, &self.table_key_id)
    }

    /// Create a new KEK, wrapped by the table's master key, and store it in
    /// the manager's `encryption_keys` map.
    async fn create_kek(&self) -> Result<KeyEncryptionKey> {
        let (plaintext_kek, wrapped_kek) = if self.kms_client.supports_key_generation() {
            let result = self.kms_client.generate_key(&self.table_key_id).await?;
            (result.key().clone(), result.wrapped_key().to_vec())
        } else {
            let plaintext_key = SecureKey::generate(self.key_size);
            let wrapped = self
                .kms_client
                .wrap_key(plaintext_key.as_bytes(), &self.table_key_id)
                .await?;

            (SensitiveBytes::new(plaintext_key.as_bytes()), wrapped)
        };

        let key_id = Uuid::new_v4().to_string();
        let now_ms = Utc::now().timestamp_millis();

        self.kek_cache.insert(key_id.clone(), plaintext_kek).await;

        let kek = KeyEncryptionKey::new(key_id, wrapped_kek, &self.table_key_id, now_ms);
        self.insert_encryption_key(kek.deref().clone());
        Ok(kek)
    }

    /// Find the latest non-expired KEK for the table's master key.
    ///
    /// Entries that don't validate as KEKs (manifest entries, or KEKs missing
    /// `KEY_TIMESTAMP`) are skipped — `find_active_kek` is best-effort.
    /// A subsequent decrypt that targets such an entry by id will surface the
    /// validation error via [`Self::kek`].
    fn find_active_kek(&self) -> Option<KeyEncryptionKey> {
        let keys = self
            .encryption_keys
            .read()
            .expect("encryption_keys lock poisoned");
        keys.values()
            .filter_map(|key| {
                KeyEncryptionKey::try_from_encrypted_key(key.clone(), &self.table_key_id).ok()
            })
            .filter(|kek| !kek.is_expired())
            .max_by_key(KeyEncryptionKey::created_at_ms)
    }

    /// Unwrap a KEK using the KMS, with caching to avoid repeated calls.
    async fn unwrap_key_encryption_key(&self, kek: &KeyEncryptionKey) -> Result<SensitiveBytes> {
        let cache_key = kek.key_id().to_string();

        if let Some(cached) = self.kek_cache.get(&cache_key).await {
            return Ok(cached);
        }

        let master_key_id = kek
            .encrypted_by_id()
            .expect("KEK validation guarantees encrypted_by_id is set");

        let plaintext = self
            .kms_client
            .unwrap_key(kek.encrypted_key_metadata(), master_key_id)
            .await?;

        self.kek_cache.insert(cache_key, plaintext.clone()).await;

        Ok(plaintext)
    }

    /// Decrypt a wrapped DEK using the KEK identified by `kek_key_id`.
    async fn decrypt_dek(&self, kek_key_id: &str, wrapped_dek: &[u8]) -> Result<SensitiveBytes> {
        let kek = self.kek(kek_key_id)?;
        let aad = kek.timestamp_aad();
        let kek_bytes = self.unwrap_key_encryption_key(&kek).await?;
        self.unwrap_dek_with_kek(wrapped_dek, &kek_bytes, Some(aad))
            .map_err(|e| {
                Error::new(
                    e.kind(),
                    format!("Failed to unwrap key metadata with KEK '{kek_key_id}'"),
                )
                .with_source(e)
            })
    }

    /// Generate a random AAD prefix for file encryption.
    fn generate_aad_prefix() -> Box<[u8]> {
        let mut prefix = vec![0u8; AAD_PREFIX_LENGTH];
        OsRng.fill_bytes(&mut prefix);
        prefix.into_boxed_slice()
    }

    /// Wrap a DEK with a KEK using local AES-GCM.
    fn wrap_dek_with_kek(
        &self,
        dek: &[u8],
        kek: &SensitiveBytes,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = SecureKey::try_from(kek.clone())?;
        let cipher = AesGcmCipher::new(key);
        cipher.encrypt(dek, aad)
    }

    /// Unwrap a DEK with a KEK using local AES-GCM.
    fn unwrap_dek_with_kek(
        &self,
        wrapped_dek: &[u8],
        kek: &SensitiveBytes,
        aad: Option<&[u8]>,
    ) -> Result<SensitiveBytes> {
        let key = SecureKey::try_from(kek.clone())?;
        let cipher = AesGcmCipher::new(key);
        cipher.decrypt(wrapped_dek, aad).map(SensitiveBytes::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::EncryptedInputFile;
    use crate::encryption::keys::KEK_CREATED_AT_PROPERTY;
    use crate::encryption::kms::MemoryKeyManagementClient;

    const MILLIS_IN_DAY: i64 = 24 * 60 * 60 * 1000;

    fn create_test_kms() -> Arc<dyn KeyManagementClient> {
        let kms = MemoryKeyManagementClient::new();
        kms.add_master_key("master-1").unwrap();
        Arc::new(kms)
    }

    fn create_test_manager() -> EncryptionManager {
        EncryptionManager::builder()
            .kms_client(create_test_kms())
            .table_key_id("master-1")
            .build()
    }

    #[tokio::test]
    async fn test_create_kek() {
        let mgr = create_test_manager();
        let kek = mgr.create_kek().await.unwrap();

        assert!(!kek.key_id().is_empty());
        assert!(!kek.encrypted_key_metadata().is_empty());
        assert_eq!(kek.encrypted_by_id(), Some("master-1"));
        assert!(kek.properties().contains_key(KEK_CREATED_AT_PROPERTY));
    }

    fn sample_key_metadata() -> StandardKeyMetadata {
        StandardKeyMetadata::new(b"0123456789abcdef").with_aad_prefix(b"test-aad-prefix!")
    }

    #[tokio::test]
    async fn test_wrap_unwrap_key_metadata_roundtrip() {
        let mgr = create_test_manager();
        let plaintext = sample_key_metadata();

        let key_id = mgr
            .encrypt_manifest_list_key_metadata(&plaintext)
            .await
            .unwrap();

        // First wrap should create a new KEK and the wrapped entry — both stored on the manager
        assert_eq!(mgr.with_encryption_keys(|k| k.len()), 2);

        let decrypted = mgr
            .decrypt_manifest_list_key_metadata(&key_id)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_kek_reuse_when_not_expired() {
        let mgr = create_test_manager();

        // First wrap creates a new KEK + wrapped entry (2 keys)
        let _id1 = mgr
            .encrypt_manifest_list_key_metadata(&sample_key_metadata())
            .await
            .unwrap();
        let kek_id = mgr.with_encryption_keys(|keys| {
            assert_eq!(keys.len(), 2);
            keys.values()
                .find(|k| k.encrypted_by_id() == Some("master-1"))
                .unwrap()
                .key_id()
                .to_string()
        });

        // Second wrap should reuse the existing KEK (only adds 1 new wrapped entry)
        let id2 = mgr
            .encrypt_manifest_list_key_metadata(&sample_key_metadata())
            .await
            .unwrap();
        let entry2 = mgr.with_encryption_keys(|keys| {
            assert_eq!(keys.len(), 3);
            keys.get(&id2).cloned().unwrap()
        });
        assert_eq!(entry2.encrypted_by_id(), Some(kek_id.as_str()));
    }

    #[tokio::test]
    async fn test_kek_rotation_when_expired() {
        let kms = create_test_kms();

        // Create a KEK with a timestamp 3 years in the past (exceeds 730-day lifespan)
        let three_years_ago_ms = Utc::now().timestamp_millis() - (3 * 365 * MILLIS_IN_DAY);
        let mut properties = HashMap::new();
        properties.insert(
            KEK_CREATED_AT_PROPERTY.to_string(),
            three_years_ago_ms.to_string(),
        );

        // Wrap a real KEK so unwrap works if needed
        let kek_key = SecureKey::generate(AesKeySize::Bits128);
        let wrapped = kms.wrap_key(kek_key.as_bytes(), "master-1").await.unwrap();

        let old_kek = EncryptedKey::builder()
            .key_id("expired-kek")
            .encrypted_key_metadata(wrapped)
            .encrypted_by_id("master-1")
            .properties(properties)
            .build();

        // Build manager with the expired KEK
        let mgr = EncryptionManager::builder()
            .kms_client(kms)
            .table_key_id("master-1")
            .add_encryption_key(old_kek.clone())
            .build();

        // Wrap should rotate to a new KEK since the existing one is expired
        let new_entry_id = mgr
            .encrypt_manifest_list_key_metadata(&sample_key_metadata())
            .await
            .unwrap();
        let entry = mgr
            .with_encryption_keys(|keys| keys.get(&new_entry_id).cloned())
            .unwrap();
        let used_kek_id = entry.encrypted_by_id().unwrap();
        assert_ne!(used_kek_id, old_kek.key_id());
    }

    #[tokio::test]
    async fn test_kek_validation_rejects_missing_timestamp() {
        // KEK without KEY_TIMESTAMP fails to construct.
        let key = EncryptedKey::builder()
            .key_id("no-ts")
            .encrypted_key_metadata(vec![0u8; 32])
            .encrypted_by_id("master-1")
            .build();
        let result = KeyEncryptionKey::try_from_encrypted_key(key, "master-1");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains(KEK_CREATED_AT_PROPERTY)
        );
    }

    #[tokio::test]
    async fn test_kek_validation_rejects_non_kek() {
        // An entry encrypted by something other than the master key is not a KEK
        let key = EncryptedKey::builder()
            .key_id("not-a-kek")
            .encrypted_key_metadata(vec![0u8; 32])
            .encrypted_by_id("some-other-kek-id")
            .build();
        let result = KeyEncryptionKey::try_from_encrypted_key(key, "master-1");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decrypt_rejects_kek_passed_as_manifest_entry() {
        // If a caller passes a KEK id to decrypt_manifest_list_key_metadata,
        // we should fail with a clear error rather than a generic crypto failure.
        let mgr = create_test_manager();
        let kek = mgr.create_kek().await.unwrap();
        let result = mgr.decrypt_manifest_list_key_metadata(kek.key_id()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DataInvalid);
        assert!(
            err.to_string().contains("not a manifest entry"),
            "error should explain the misclassification: {err}"
        );
    }

    #[tokio::test]
    async fn test_decrypt_with_unknown_key_id() {
        let mgr = create_test_manager();
        let result = mgr.decrypt_manifest_list_key_metadata("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_kek_cache_hit() {
        let mgr = create_test_manager();

        // First wrap caches the plaintext KEK during create_kek().
        let key_id = mgr
            .encrypt_manifest_list_key_metadata(&sample_key_metadata())
            .await
            .unwrap();

        // Decrypt unwraps the KEK; with the cache populated this should not hit KMS again.
        let _ = mgr
            .decrypt_manifest_list_key_metadata(&key_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_unwrap_fails_when_kek_missing_timestamp() {
        let mgr = create_test_manager();

        // Wrap some metadata to get a valid encrypted entry stored on the manager
        let entry_id = mgr
            .encrypt_manifest_list_key_metadata(&sample_key_metadata())
            .await
            .unwrap();

        // Find the KEK that wrapped the entry and replace it with a copy that
        // is missing the KEY_TIMESTAMP property, simulating a malformed table.
        let mut keys = mgr.with_encryption_keys(|k| k.clone());
        let kek_id = keys
            .get(&entry_id)
            .unwrap()
            .encrypted_by_id()
            .unwrap()
            .to_string();
        let kek = keys.remove(&kek_id).unwrap();
        let kek_no_ts = EncryptedKey::builder()
            .key_id(kek.key_id())
            .encrypted_key_metadata(kek.encrypted_key_metadata())
            .encrypted_by_id(kek.encrypted_by_id().unwrap())
            .build();
        keys.insert(kek_no_ts.key_id().to_string(), kek_no_ts);

        let mgr = EncryptionManager::builder()
            .kms_client(create_test_kms())
            .table_key_id("master-1")
            .encryption_keys(keys)
            .build();

        let result = mgr.decrypt_manifest_list_key_metadata(&entry_id).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DataInvalid);
        assert!(
            err.to_string().contains(KEK_CREATED_AT_PROPERTY),
            "error should mention the missing property: {err}"
        );
    }

    #[tokio::test]
    async fn test_unwrap_fails_when_kek_timestamp_tampered() {
        let mgr = create_test_manager();

        // Wrap metadata normally
        let entry_id = mgr
            .encrypt_manifest_list_key_metadata(&sample_key_metadata())
            .await
            .unwrap();

        // Tamper with the KEK timestamp (change the AAD)
        let mut keys = mgr.with_encryption_keys(|k| k.clone());
        let kek_id = keys
            .get(&entry_id)
            .unwrap()
            .encrypted_by_id()
            .unwrap()
            .to_string();
        let kek = keys.remove(&kek_id).unwrap();
        let mut tampered_properties = kek.properties().clone();
        tampered_properties.insert(KEK_CREATED_AT_PROPERTY.to_string(), "9999999".to_string());
        let tampered_kek = EncryptedKey::builder()
            .key_id(kek.key_id())
            .encrypted_key_metadata(kek.encrypted_key_metadata())
            .encrypted_by_id(kek.encrypted_by_id().unwrap())
            .properties(tampered_properties)
            .build();
        keys.insert(tampered_kek.key_id().to_string(), tampered_kek);

        let mgr = EncryptionManager::builder()
            .kms_client(create_test_kms())
            .table_key_id("master-1")
            .encryption_keys(keys)
            .build();

        // Unwrap should fail because the AAD (timestamp) doesn't match what was used to wrap
        let result = mgr.decrypt_manifest_list_key_metadata(&entry_id).await;
        assert!(
            result.is_err(),
            "tampered timestamp should cause decryption failure"
        );
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        use crate::io::FileIO;

        let io = FileIO::new_with_memory();
        let path = "memory:///test/encrypt_roundtrip.bin";

        let kms = MemoryKeyManagementClient::new();
        kms.add_master_key("master-1").unwrap();
        let mgr = EncryptionManager::builder()
            .kms_client(Arc::new(kms) as Arc<dyn KeyManagementClient>)
            .table_key_id("master-1")
            .build();

        let output = io.new_output(path).unwrap();
        let encrypted_output = mgr.encrypt(output);

        let plaintext = b"Hello, encrypted Iceberg round-trip!";
        let serialized_metadata = encrypted_output.key_metadata().encode().unwrap();
        encrypted_output
            .write(bytes::Bytes::from(plaintext.to_vec()))
            .await
            .unwrap();

        let input = io.new_input(path).unwrap();
        let parsed_metadata = StandardKeyMetadata::decode(&serialized_metadata).unwrap();
        let decrypted_file = EncryptedInputFile::new(input, parsed_metadata);

        let content = decrypted_file.read().await.unwrap();
        assert_eq!(&content[..], plaintext);
    }
}
