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

//! Key metadata structures for encryption

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Metadata about an encryption key
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for the key
    pub key_id: String,

    /// Encrypted key information
    pub encrypted_key: EncryptedKey,

    /// Algorithm used for encryption
    pub algorithm: String,

    /// AAD prefix for this key
    pub aad_prefix: Vec<u8>,

    /// When the key was created (timestamp in milliseconds)
    pub created_at_ms: i64,

    /// When the key expires and should be rotated (timestamp in milliseconds)
    pub expires_at_ms: Option<i64>,

    /// Version of the key (for rotation tracking)
    pub version: u32,

    /// Additional properties
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, String>,
}

impl KeyMetadata {
    /// Create a new key metadata instance
    pub fn new(
        key_id: String,
        encrypted_key: EncryptedKey,
        algorithm: String,
        aad_prefix: Vec<u8>,
    ) -> Self {
        let created_at_ms = Utc::now().timestamp_millis();
        let expires_at_ms = Some(created_at_ms + 730 * 24 * 60 * 60 * 1000); // 2 years default

        Self {
            key_id,
            encrypted_key,
            algorithm,
            aad_prefix,
            created_at_ms,
            expires_at_ms,
            version: 1,
            properties: HashMap::new(),
        }
    }

    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at_ms) = self.expires_at_ms {
            Utc::now().timestamp_millis() > expires_at_ms
        } else {
            false
        }
    }

    /// Get the age of the key in days
    pub fn age_days(&self) -> i64 {
        let now_ms = Utc::now().timestamp_millis();
        (now_ms - self.created_at_ms) / (24 * 60 * 60 * 1000)
    }

    /// Get the creation time as DateTime
    pub fn created_at(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.created_at_ms).unwrap_or_else(|| Utc::now())
    }

    /// Get the expiration time as DateTime
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at_ms.and_then(DateTime::from_timestamp_millis)
    }

    /// Create a new version of this key metadata for rotation
    pub fn rotate(&self, new_encrypted_key: EncryptedKey, new_aad_prefix: Vec<u8>) -> Self {
        let created_at_ms = Utc::now().timestamp_millis();

        Self {
            key_id: self.key_id.clone(),
            encrypted_key: new_encrypted_key,
            algorithm: self.algorithm.clone(),
            aad_prefix: new_aad_prefix,
            created_at_ms,
            expires_at_ms: Some(created_at_ms + 730 * 24 * 60 * 60 * 1000),
            version: self.version + 1,
            properties: self.properties.clone(),
        }
    }

    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            Error::new(ErrorKind::Unexpected, "Failed to serialize key metadata").with_source(e)
        })
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| {
            Error::new(ErrorKind::DataInvalid, "Failed to deserialize key metadata").with_source(e)
        })
    }
}

/// Information about key rotation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationInfo {
    /// The current key metadata
    pub current_key: KeyMetadata,

    /// Previous key metadata (for decrypting old files)
    pub previous_keys: Vec<KeyMetadata>,

    /// When the last rotation occurred (timestamp in milliseconds)
    pub last_rotation_ms: i64,

    /// When the next rotation should occur (timestamp in milliseconds)
    pub next_rotation_ms: i64,

    /// Number of successful rotations
    pub rotation_count: u32,
}

impl KeyRotationInfo {
    /// Create new rotation info
    pub fn new(initial_key: KeyMetadata) -> Self {
        let now_ms = Utc::now().timestamp_millis();
        Self {
            current_key: initial_key,
            previous_keys: Vec::new(),
            last_rotation_ms: now_ms,
            next_rotation_ms: now_ms + 730 * 24 * 60 * 60 * 1000, // 2 years
            rotation_count: 0,
        }
    }

    /// Rotate to a new key
    pub fn rotate(&mut self, new_key: KeyMetadata) {
        // Move current key to previous keys
        let old_key = std::mem::replace(&mut self.current_key, new_key);
        self.previous_keys.push(old_key);

        // Update rotation tracking
        let now_ms = Utc::now().timestamp_millis();
        self.last_rotation_ms = now_ms;
        self.next_rotation_ms = now_ms + 730 * 24 * 60 * 60 * 1000; // 2 years
        self.rotation_count += 1;

        // Limit previous keys to last 5 versions
        if self.previous_keys.len() > 5 {
            self.previous_keys.remove(0);
        }
    }

    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        Utc::now().timestamp_millis() > self.next_rotation_ms || self.current_key.is_expired()
    }

    /// Find a key by its ID
    pub fn find_key(&self, key_id: &str) -> Option<&KeyMetadata> {
        if self.current_key.key_id == key_id {
            Some(&self.current_key)
        } else {
            self.previous_keys.iter().find(|k| k.key_id == key_id)
        }
    }

    /// Get all keys (current and previous)
    pub fn all_keys(&self) -> Vec<&KeyMetadata> {
        let mut keys = vec![&self.current_key];
        keys.extend(self.previous_keys.iter());
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_metadata_expiration() {
        let encrypted_key = EncryptedKey::builder()
            .key_id("test-key")
            .encrypted_key_metadata(vec![1, 2, 3])
            .build();

        let mut metadata = KeyMetadata::new(
            "key-1".to_string(),
            encrypted_key,
            "AES-256-GCM".to_string(),
            vec![0; 16],
        );

        // Key should not be expired initially
        assert!(!metadata.is_expired());

        // Set expiration to past
        let past_time = Utc::now() - chrono::Duration::days(1);
        metadata.expires_at_ms = Some(past_time.timestamp_millis());
        assert!(metadata.is_expired());
    }

    #[test]
    fn test_key_rotation() {
        let encrypted_key1 = EncryptedKey::builder()
            .key_id("key-1")
            .encrypted_key_metadata(vec![1, 2, 3])
            .build();

        let encrypted_key2 = EncryptedKey::builder()
            .key_id("key-2")
            .encrypted_key_metadata(vec![4, 5, 6])
            .build();

        let metadata1 = KeyMetadata::new(
            "key-1".to_string(),
            encrypted_key1,
            "AES-256-GCM".to_string(),
            vec![0; 16],
        );

        let metadata2 = metadata1.rotate(encrypted_key2, vec![1; 16]);

        assert_eq!(metadata2.version, 2);
        assert_eq!(metadata2.key_id, "key-1");
        assert_eq!(metadata2.aad_prefix, vec![1; 16]);
    }

    #[test]
    fn test_rotation_info() {
        let encrypted_key1 = EncryptedKey::builder()
            .key_id("key-1")
            .encrypted_key_metadata(vec![1, 2, 3])
            .build();

        let encrypted_key2 = EncryptedKey::builder()
            .key_id("key-2")
            .encrypted_key_metadata(vec![4, 5, 6])
            .build();

        let metadata1 = KeyMetadata::new(
            "key-1".to_string(),
            encrypted_key1,
            "AES-256-GCM".to_string(),
            vec![0; 16],
        );

        let metadata2 = KeyMetadata::new(
            "key-2".to_string(),
            encrypted_key2,
            "AES-256-GCM".to_string(),
            vec![1; 16],
        );

        let mut rotation_info = KeyRotationInfo::new(metadata1.clone());
        assert_eq!(rotation_info.rotation_count, 0);

        rotation_info.rotate(metadata2.clone());
        assert_eq!(rotation_info.rotation_count, 1);
        assert_eq!(rotation_info.current_key.key_id, "key-2");
        assert_eq!(rotation_info.previous_keys.len(), 1);
        assert_eq!(rotation_info.previous_keys[0].key_id, "key-1");

        // Test finding keys
        assert!(rotation_info.find_key("key-1").is_some());
        assert!(rotation_info.find_key("key-2").is_some());
        assert!(rotation_info.find_key("key-3").is_none());
    }
}

