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

//! Native Parquet encryption support

use crate::encryption::KeyMetadata;
use crate::io::{InputFile, OutputFile};

/// Native encryption output file for Parquet
///
/// This wraps an OutputFile with Parquet-native encryption properties.
/// When the Parquet crate supports native encryption, this will provide
/// the encryption properties directly to the Parquet writer.
#[derive(Debug)]
pub struct NativeEncryptionOutputFile {
    /// The underlying output file
    inner: OutputFile,

    /// Key metadata for encryption
    key_metadata: KeyMetadata,

    /// File encryption key
    file_key: Vec<u8>,

    /// AAD prefix for this file
    aad_prefix: Vec<u8>,

    /// Footer encryption key (optional, can be same as file key)
    footer_key: Option<Vec<u8>>,

    /// Column encryption keys (column path -> key)
    column_keys: Option<Vec<(String, Vec<u8>)>>,
}

impl NativeEncryptionOutputFile {
    /// Create a new native encryption output file
    pub fn new(inner: OutputFile, key_metadata: KeyMetadata, file_key: Vec<u8>) -> Self {
        let aad_prefix = key_metadata.aad_prefix.clone();

        Self {
            inner,
            key_metadata,
            file_key,
            aad_prefix,
            footer_key: None,
            column_keys: None,
        }
    }

    /// Set the footer encryption key
    pub fn with_footer_key(mut self, footer_key: Vec<u8>) -> Self {
        self.footer_key = Some(footer_key);
        self
    }

    /// Set column-specific encryption keys
    pub fn with_column_keys(mut self, column_keys: Vec<(String, Vec<u8>)>) -> Self {
        self.column_keys = Some(column_keys);
        self
    }

    /// Get the underlying output file
    pub fn plain_output_file(&self) -> &OutputFile {
        &self.inner
    }

    /// Get the file encryption key
    pub fn file_key(&self) -> &[u8] {
        &self.file_key
    }

    /// Get the AAD prefix
    pub fn aad_prefix(&self) -> &[u8] {
        &self.aad_prefix
    }

    /// Get the footer encryption key
    pub fn footer_key(&self) -> Option<&[u8]> {
        self.footer_key.as_deref()
    }

    /// Get column encryption keys
    pub fn column_keys(&self) -> Option<&[(String, Vec<u8>)]> {
        self.column_keys.as_deref()
    }

    /// Get the key metadata
    pub fn key_metadata(&self) -> &KeyMetadata {
        &self.key_metadata
    }

    /// Generate Parquet file encryption properties
    ///
    /// This would be used when the Parquet crate supports native encryption.
    /// For now, it returns a placeholder structure.
    pub fn to_parquet_encryption_properties(&self) -> ParquetEncryptionProperties {
        ParquetEncryptionProperties {
            file_key: self.file_key.clone(),
            aad_prefix: self.aad_prefix.clone(),
            footer_key: self.footer_key.clone(),
            column_keys: self.column_keys.clone(),
            algorithm: self.key_metadata.algorithm.clone(),
        }
    }
}

/// Native encryption input file for Parquet
///
/// This wraps an InputFile with Parquet-native decryption properties.
#[derive(Debug)]
pub struct NativeEncryptionInputFile {
    /// The underlying input file
    inner: InputFile,

    /// Key metadata for decryption
    key_metadata: KeyMetadata,

    /// File decryption key
    file_key: Vec<u8>,

    /// AAD prefix for this file
    aad_prefix: Vec<u8>,

    /// Footer decryption key (optional)
    footer_key: Option<Vec<u8>>,

    /// Column decryption keys
    column_keys: Option<Vec<(String, Vec<u8>)>>,
}

impl NativeEncryptionInputFile {
    /// Create a new native encryption input file
    pub fn new(inner: InputFile, key_metadata: KeyMetadata, file_key: Vec<u8>) -> Self {
        let aad_prefix = key_metadata.aad_prefix.clone();

        Self {
            inner,
            key_metadata,
            file_key,
            aad_prefix,
            footer_key: None,
            column_keys: None,
        }
    }

    /// Set the footer decryption key
    pub fn with_footer_key(mut self, footer_key: Vec<u8>) -> Self {
        self.footer_key = Some(footer_key);
        self
    }

    /// Set column-specific decryption keys
    pub fn with_column_keys(mut self, column_keys: Vec<(String, Vec<u8>)>) -> Self {
        self.column_keys = Some(column_keys);
        self
    }

    /// Get the underlying input file
    pub fn plain_input_file(&self) -> &InputFile {
        &self.inner
    }

    /// Get the file decryption key
    pub fn file_key(&self) -> &[u8] {
        &self.file_key
    }

    /// Get the AAD prefix
    pub fn aad_prefix(&self) -> &[u8] {
        &self.aad_prefix
    }

    /// Get the footer decryption key
    pub fn footer_key(&self) -> Option<&[u8]> {
        self.footer_key.as_deref()
    }

    /// Get column decryption keys
    pub fn column_keys(&self) -> Option<&[(String, Vec<u8>)]> {
        self.column_keys.as_deref()
    }

    /// Get the key metadata
    pub fn key_metadata(&self) -> &KeyMetadata {
        &self.key_metadata
    }

    /// Generate Parquet file decryption properties
    pub fn to_parquet_decryption_properties(&self) -> ParquetDecryptionProperties {
        ParquetDecryptionProperties {
            file_key: self.file_key.clone(),
            aad_prefix: self.aad_prefix.clone(),
            footer_key: self.footer_key.clone(),
            column_keys: self.column_keys.clone(),
        }
    }
}

/// Parquet encryption properties
///
/// This structure would be used to configure the Parquet writer
/// when native encryption support is available in the parquet crate.
#[derive(Clone, Debug)]
pub struct ParquetEncryptionProperties {
    /// File encryption key
    pub file_key: Vec<u8>,

    /// AAD prefix
    pub aad_prefix: Vec<u8>,

    /// Footer encryption key (optional)
    pub footer_key: Option<Vec<u8>>,

    /// Column-specific encryption keys
    pub column_keys: Option<Vec<(String, Vec<u8>)>>,

    /// Encryption algorithm
    pub algorithm: String,
}

impl ParquetEncryptionProperties {
    /// Create new encryption properties
    pub fn new(file_key: Vec<u8>, aad_prefix: Vec<u8>, algorithm: String) -> Self {
        Self {
            file_key,
            aad_prefix,
            footer_key: None,
            column_keys: None,
            algorithm,
        }
    }

    /// Enable footer encryption with the same key as the file
    pub fn enable_footer_encryption(mut self) -> Self {
        self.footer_key = Some(self.file_key.clone());
        self
    }

    /// Enable footer encryption with a different key
    pub fn with_footer_key(mut self, footer_key: Vec<u8>) -> Self {
        self.footer_key = Some(footer_key);
        self
    }

    /// Add column-specific encryption
    pub fn with_column_keys(mut self, column_keys: Vec<(String, Vec<u8>)>) -> Self {
        self.column_keys = Some(column_keys);
        self
    }
}

/// Parquet decryption properties
#[derive(Clone, Debug)]
pub struct ParquetDecryptionProperties {
    /// File decryption key
    pub file_key: Vec<u8>,

    /// AAD prefix
    pub aad_prefix: Vec<u8>,

    /// Footer decryption key (optional)
    pub footer_key: Option<Vec<u8>>,

    /// Column-specific decryption keys
    pub column_keys: Option<Vec<(String, Vec<u8>)>>,
}

impl ParquetDecryptionProperties {
    /// Create new decryption properties
    pub fn new(file_key: Vec<u8>, aad_prefix: Vec<u8>) -> Self {
        Self {
            file_key,
            aad_prefix,
            footer_key: None,
            column_keys: None,
        }
    }

    /// Set footer decryption key
    pub fn with_footer_key(mut self, footer_key: Vec<u8>) -> Self {
        self.footer_key = Some(footer_key);
        self
    }

    /// Set column-specific decryption keys
    pub fn with_column_keys(mut self, column_keys: Vec<(String, Vec<u8>)>) -> Self {
        self.column_keys = Some(column_keys);
        self
    }
}

/// Check if the Parquet crate supports native encryption
///
/// This would check the parquet crate features and version to determine
/// if native encryption is available.
pub fn supports_native_encryption() -> bool {
    // TODO: Check parquet crate features when native encryption is added
    // For now, return false as the parquet crate doesn't support it yet
    false
}

/// Create encryption properties from key metadata
pub fn create_encryption_properties(
    key_metadata: &KeyMetadata,
    file_key: Vec<u8>,
) -> ParquetEncryptionProperties {
    ParquetEncryptionProperties::new(
        file_key,
        key_metadata.aad_prefix.clone(),
        key_metadata.algorithm.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::crypto::{EncryptionAlgorithm, SecureKey};
    use crate::spec::EncryptedKey;

    #[test]
    fn test_parquet_encryption_properties() {
        let file_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let aad_prefix = vec![0; 16];

        let props = ParquetEncryptionProperties::new(
            file_key.clone(),
            aad_prefix.clone(),
            "AES-256-GCM".to_string(),
        );

        assert_eq!(props.file_key, file_key);
        assert_eq!(props.aad_prefix, aad_prefix);
        assert!(props.footer_key.is_none());

        // Test enabling footer encryption
        let props_with_footer = props.clone().enable_footer_encryption();
        assert_eq!(props_with_footer.footer_key, Some(file_key.clone()));

        // Test with column keys
        let column_keys = vec![
            ("column1".to_string(), vec![1; 32]),
            ("column2".to_string(), vec![2; 32]),
        ];

        let props_with_columns = props.with_column_keys(column_keys.clone());
        assert_eq!(props_with_columns.column_keys, Some(column_keys));
    }

    // TODO: Fix this test - OutputFile::from_str doesn't exist
    #[test]
    #[ignore]
    fn test_native_encryption_output_file() {
        // let output_file = OutputFile::from_str("file://test.parquet", None, None).unwrap();

        let encrypted_key = EncryptedKey::builder()
            .key_id("test-key")
            .encrypted_key_metadata(vec![1, 2, 3])
            .build();

        let _key_metadata = KeyMetadata::new(
            "key-1".to_string(),
            encrypted_key,
            "AES-256-GCM".to_string(),
            vec![0; 16],
        );

        let _file_key = vec![1; 32];

        // let native_file =
        //     NativeEncryptionOutputFile::new(output_file, key_metadata, file_key.clone());

        // assert_eq!(native_file.file_key(), &file_key[..]);
        // assert_eq!(native_file.aad_prefix().len(), 16);

        // Test conversion to properties
        // let props = native_file.to_parquet_encryption_properties();
        // assert_eq!(props.file_key, file_key);
        // assert_eq!(props.algorithm, "AES-256-GCM");
    }

    #[test]
    fn test_supports_native_encryption() {
        // Currently should return false
        assert!(!supports_native_encryption());
    }
}

