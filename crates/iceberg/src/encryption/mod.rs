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

//! Encryption support for Iceberg tables
//!
//! This module provides encryption and decryption capabilities for Iceberg data files,
//! including support for various key management systems and encryption algorithms.


mod crypto;

pub use crypto::{AesGcmEncryptor, EncryptionAlgorithm, SecureKey};

pub mod cache;
pub mod crypto;
pub mod key_management;
pub mod key_metadata;
pub mod kms;
pub mod manager;
pub mod parquet;

use std::sync::Arc;

pub use cache::KeyCache;
pub use crypto::{AesGcmEncryptor, EncryptionAlgorithm, SecureKey};
pub use key_management::KeyManagementClient;
pub use key_metadata::{KeyMetadata, KeyRotationInfo};
pub use manager::{EncryptionConfig, EncryptionManager, StandardEncryptionManager};
pub use parquet::{NativeEncryptionInputFile, NativeEncryptionOutputFile};

use crate::io::{InputFile, OutputFile};

/// Represents an encrypted output file
#[derive(Debug)]
pub struct EncryptedOutputFile {
    inner: OutputFile,
    key_metadata: KeyMetadata,
    encryptor: Arc<AesGcmEncryptor>,
}

impl EncryptedOutputFile {
    /// Create a new encrypted output file
    pub fn new(
        inner: OutputFile,
        key_metadata: KeyMetadata,
        encryptor: Arc<AesGcmEncryptor>,
    ) -> Self {
        Self {
            inner,
            key_metadata,
            encryptor,
        }
    }

    /// Get a reference to the underlying output file
    pub fn inner(&self) -> &OutputFile {
        &self.inner
    }

    /// Consume self and return the inner output file
    pub fn into_inner(self) -> OutputFile {
        self.inner
    }

    /// Get the key metadata
    pub fn key_metadata(&self) -> &KeyMetadata {
        &self.key_metadata
    }

    /// Get the encryptor
    pub fn encryptor(&self) -> Arc<AesGcmEncryptor> {
        Arc::clone(&self.encryptor)
    }
}

/// Represents a decrypted input file
#[derive(Debug)]
pub struct DecryptedInputFile {
    inner: InputFile,
    key_metadata: KeyMetadata,
    decryptor: Arc<AesGcmEncryptor>,
}

impl DecryptedInputFile {
    /// Create a new decrypted input file
    pub fn new(
        inner: InputFile,
        key_metadata: KeyMetadata,
        decryptor: Arc<AesGcmEncryptor>,
    ) -> Self {
        Self {
            inner,
            key_metadata,
            decryptor,
        }
    }

    /// Get the underlying input file
    pub fn inner(&self) -> &InputFile {
        &self.inner
    }

    /// Get the key metadata
    pub fn key_metadata(&self) -> &KeyMetadata {
        &self.key_metadata
    }

    /// Get the decryptor
    pub fn decryptor(&self) -> Arc<AesGcmEncryptor> {
        Arc::clone(&self.decryptor)
    }
}

/// Encryption-related properties for table configuration
pub mod properties {
    /// Master key identifier for encryption
    pub const ENCRYPTION_MASTER_KEY_ID: &str = "encryption.key-id";

    /// Encryption algorithm to use
    pub const ENCRYPTION_ALGORITHM: &str = "encryption.algorithm";

    /// Key rotation period in days
    pub const ENCRYPTION_KEY_ROTATION_DAYS: &str = "encryption.key-rotation-days";

    /// Default key rotation period (2 years per NIST recommendations)
    pub const DEFAULT_KEY_ROTATION_DAYS: u32 = 730;
}

<<<<<<< HEAD
>>>>>>> b92118e5 (Implement KMS for encryption / decryption)
=======
#[cfg(test)]
mod integration_tests;

>>>>>>> 06c49ee3 (wire)
