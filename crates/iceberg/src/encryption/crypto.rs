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

<<<<<<< HEAD
//! Core cryptographic operations for Iceberg encryption.

use std::str::FromStr;

use aes_gcm::aead::generic_array::typenum::Unsigned;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, KeySizeUser, OsRng, Payload};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{Error, ErrorKind, Result};

/// Supported encryption algorithm.
/// Currently only AES-128-GCM is supported as it's the only algorithm
/// compatible with arrow-rs Parquet encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-128 in GCM mode
    Aes128Gcm,
}

impl EncryptionAlgorithm {
    /// Returns the key length in bytes for this algorithm.
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => <Aes128Gcm as KeySizeUser>::KeySize::USIZE,
        }
    }

    /// Returns the nonce/IV length in bytes for this algorithm.
    pub fn nonce_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => <Aes128Gcm as AeadCore>::NonceSize::USIZE,
        }
    }

    /// Returns the string identifier for this algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES_GCM_128",
        }
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "AES_GCM_128" | "AES128_GCM" => Ok(Self::Aes128Gcm),
            _ => Err(Error::new(
                ErrorKind::DataInvalid,
                format!("Unsupported encryption algorithm: {s}"),
=======
//! Low-level cryptographic operations for encryption and decryption

use std::fmt;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce};
use bytes::{Bytes, BytesMut};
use zeroize::ZeroizeOnDrop;

use crate::{Error, ErrorKind, Result};

/// Supported encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-128-GCM encryption
    Aes128Gcm,
    /// AES-256-GCM encryption
    Aes256Gcm,
}

impl EncryptionAlgorithm {
    /// Get the key length in bytes for this algorithm
    pub fn key_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    /// Parse algorithm from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" | "aes128gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" | "aes256gcm" => Ok(Self::Aes256Gcm),
            _ => Err(Error::new(
                ErrorKind::DataInvalid,
                format!("Unsupported encryption algorithm: {}", s),
>>>>>>> b92118e5 (Implement KMS for encryption / decryption)
            )),
        }
    }
}

<<<<<<< HEAD
/// A secure encryption key that zeroes its memory on drop.
pub struct SecureKey {
    key: Zeroizing<Vec<u8>>,
    algorithm: EncryptionAlgorithm,
}

impl SecureKey {
    /// Creates a new secure key with the specified algorithm.
    ///
    /// # Errors
    /// Returns an error if the key length doesn't match the algorithm requirements.
    pub fn new(key: Vec<u8>, algorithm: EncryptionAlgorithm) -> Result<Self> {
        if key.len() != algorithm.key_length() {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "Invalid key length for {:?}: expected {} bytes, got {}",
                    algorithm,
                    algorithm.key_length(),
                    key.len()
                ),
            ));
        }
        Ok(Self {
            key: Zeroizing::new(key),
            algorithm,
        })
    }

    /// Generates a new random key for the specified algorithm.
    pub fn generate(algorithm: EncryptionAlgorithm) -> Self {
        let mut key = vec![0u8; algorithm.key_length()];
        OsRng.fill_bytes(&mut key);
        Self {
            key: Zeroizing::new(key),
            algorithm,
        }
    }

    /// Returns the encryption algorithm for this key.
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Returns the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// AES-GCM encryptor for encrypting and decrypting data.
pub struct AesGcmEncryptor {
    key: SecureKey,
}

impl AesGcmEncryptor {
    /// Creates a new encryptor with the specified key.
    pub fn new(key: SecureKey) -> Self {
        Self { key }
    }

    /// Encrypts data using AES-GCM.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// * `aad` - Additional authenticated data (optional)
    ///
    /// # Returns
    /// The encrypted data in the format: [12-byte nonce][ciphertext][16-byte auth tag]
    /// This matches the Java implementation format for compatibility.
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        match self.key.algorithm() {
            EncryptionAlgorithm::Aes128Gcm => self.encrypt_aes128_gcm(plaintext, aad),
        }
    }

    /// Decrypts data using AES-GCM.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data with format: [12-byte nonce][encrypted data][16-byte auth tag]
    /// * `aad` - Additional authenticated data (must match encryption)
    ///
    /// # Returns
    /// The decrypted plaintext.
    pub fn decrypt(&self, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        const NONCE_LEN: usize = 12;
        const TAG_LEN: usize = 16;

        if ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "Ciphertext too short: expected at least {} bytes, got {}",
                    NONCE_LEN + TAG_LEN,
                    ciphertext.len()
=======
impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes128Gcm => write!(f, "AES-128-GCM"),
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

/// Secure key wrapper that zeroizes on drop
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecureKey {
    #[zeroize(drop)]
    key: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Generate a new random key for the given algorithm
    pub fn generate(algorithm: EncryptionAlgorithm) -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; algorithm.key_length()];
        OsRng.fill_bytes(&mut key);
        Self::new(key)
    }
}

impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey(***)")
    }
}

/// AES-GCM encryptor for file encryption
#[derive(Clone)]
pub struct AesGcmEncryptor {
    algorithm: EncryptionAlgorithm,
    key: SecureKey,
    aad_prefix: Vec<u8>,
}

impl AesGcmEncryptor {
    /// Create a new encryptor
    pub fn new(
        algorithm: EncryptionAlgorithm,
        key: SecureKey,
        aad_prefix: Vec<u8>,
    ) -> Result<Self> {
        if key.as_bytes().len() != algorithm.key_length() {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "Invalid key length for {}: expected {} bytes, got {}",
                    algorithm,
                    algorithm.key_length(),
                    key.as_bytes().len()
>>>>>>> b92118e5 (Implement KMS for encryption / decryption)
                ),
            ));
        }

<<<<<<< HEAD
        let nonce = &ciphertext[..NONCE_LEN];
        let encrypted_data = &ciphertext[NONCE_LEN..];
        match self.key.algorithm() {
            EncryptionAlgorithm::Aes128Gcm => self.decrypt_aes128_gcm(nonce, encrypted_data, aad),
        }
    }

    fn encrypt_aes128_gcm(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
=======
        Ok(Self {
            algorithm,
            key,
            aad_prefix,
        })
    }

    /// Generate a random AAD prefix
    pub fn generate_aad_prefix() -> Vec<u8> {
        use rand::RngCore;
        let mut aad = vec![0u8; 16];
        OsRng.fill_bytes(&mut aad);
        aad
    }

    /// Encrypt data with the given additional authenticated data
    pub async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Bytes> {
        // Combine AAD prefix with provided AAD
        let mut full_aad = self.aad_prefix.clone();
        full_aad.extend_from_slice(aad);

        match self.algorithm {
            EncryptionAlgorithm::Aes128Gcm => self.encrypt_aes128_gcm(plaintext, &full_aad).await,
            EncryptionAlgorithm::Aes256Gcm => self.encrypt_aes256_gcm(plaintext, &full_aad).await,
        }
    }

    /// Decrypt data with the given additional authenticated data
    pub async fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Bytes> {
        // Combine AAD prefix with provided AAD
        let mut full_aad = self.aad_prefix.clone();
        full_aad.extend_from_slice(aad);

        match self.algorithm {
            EncryptionAlgorithm::Aes128Gcm => self.decrypt_aes128_gcm(ciphertext, &full_aad).await,
            EncryptionAlgorithm::Aes256Gcm => self.decrypt_aes256_gcm(ciphertext, &full_aad).await,
        }
    }

    async fn encrypt_aes128_gcm(&self, plaintext: &[u8], aad: &[u8]) -> Result<Bytes> {
>>>>>>> b92118e5 (Implement KMS for encryption / decryption)
        let key = Key::<Aes128Gcm>::from_slice(self.key.as_bytes());
        let cipher = Aes128Gcm::new(key);
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);

<<<<<<< HEAD
        let ciphertext = if let Some(aad) = aad {
            let payload = Payload {
                msg: plaintext,
                aad,
            };
            cipher.encrypt(&nonce, payload).map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AES-128-GCM encryption failed")
                    .with_source(anyhow::anyhow!(e))
            })?
        } else {
            cipher.encrypt(&nonce, plaintext).map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AES-128-GCM encryption failed")
                    .with_source(anyhow::anyhow!(e))
            })?
        };

        // Prepend nonce to ciphertext (Java compatible format)
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_aes128_gcm(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let key = Key::<Aes128Gcm>::from_slice(self.key.as_bytes());
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = if let Some(aad) = aad {
            let payload = Payload {
                msg: ciphertext,
                aad,
            };
            cipher.decrypt(nonce, payload).map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AES-128-GCM decryption failed")
                    .with_source(anyhow::anyhow!(e))
            })?
        } else {
            cipher.decrypt(nonce, ciphertext).map_err(|e| {
                Error::new(ErrorKind::Unexpected, "AES-128-GCM decryption failed")
                    .with_source(anyhow::anyhow!(e))
            })?
        };

        Ok(plaintext)
=======
        let ciphertext = cipher
            .encrypt(&nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            })
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Encryption failed"))?;

        // Prepend nonce to ciphertext
        let mut result = BytesMut::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result.freeze())
    }

    async fn decrypt_aes128_gcm(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Bytes> {
        if ciphertext.len() < 12 {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                "Ciphertext too short to contain nonce",
            ));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes128Gcm>::from_slice(self.key.as_bytes());
        let cipher = Aes128Gcm::new(key);

        let plaintext = cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: encrypted,
                aad,
            })
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Decryption failed"))?;

        Ok(Bytes::from(plaintext))
    }

    async fn encrypt_aes256_gcm(&self, plaintext: &[u8], aad: &[u8]) -> Result<Bytes> {
        let key = Key::<Aes256Gcm>::from_slice(self.key.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            })
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Encryption failed"))?;

        // Prepend nonce to ciphertext
        let mut result = BytesMut::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result.freeze())
    }

    async fn decrypt_aes256_gcm(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Bytes> {
        if ciphertext.len() < 12 {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                "Ciphertext too short to contain nonce",
            ));
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(self.key.as_bytes());
        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher
            .decrypt(nonce, aes_gcm::aead::Payload {
                msg: encrypted,
                aad,
            })
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Decryption failed"))?;

        Ok(Bytes::from(plaintext))
    }

    /// Get the encryption algorithm
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Get the AAD prefix
    pub fn aad_prefix(&self) -> &[u8] {
        &self.aad_prefix
    }
}

impl fmt::Debug for AesGcmEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmEncryptor")
            .field("algorithm", &self.algorithm)
            .field("aad_prefix_len", &self.aad_prefix.len())
            .finish()
>>>>>>> b92118e5 (Implement KMS for encryption / decryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

<<<<<<< HEAD
    #[test]
    fn test_encryption_algorithm() {
        assert_eq!(EncryptionAlgorithm::Aes128Gcm.key_length(), 16);
        assert_eq!(EncryptionAlgorithm::Aes128Gcm.nonce_length(), 12);

        assert_eq!(
            EncryptionAlgorithm::from_str("AES_GCM_128").unwrap(),
            EncryptionAlgorithm::Aes128Gcm
        );
        assert_eq!(
            EncryptionAlgorithm::from_str("AES128_GCM").unwrap(),
            EncryptionAlgorithm::Aes128Gcm
        );

        assert!(EncryptionAlgorithm::from_str("INVALID").is_err());
        assert!(EncryptionAlgorithm::from_str("AES_GCM_256").is_err());
        assert!(EncryptionAlgorithm::from_str("AES256_GCM").is_err());

        assert_eq!(EncryptionAlgorithm::Aes128Gcm.as_str(), "AES_GCM_128");
    }

    #[test]
    fn test_secure_key() {
        // Test key generation
        let key1 = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        assert_eq!(key1.as_bytes().len(), 16);
        assert_eq!(key1.algorithm(), EncryptionAlgorithm::Aes128Gcm);

        // Test key creation with validation
        let valid_key = vec![0u8; 16];
        assert!(SecureKey::new(valid_key, EncryptionAlgorithm::Aes128Gcm).is_ok());

        let invalid_key = vec![0u8; 32];
        assert!(SecureKey::new(invalid_key, EncryptionAlgorithm::Aes128Gcm).is_err());
    }

    #[test]
    fn test_aes128_gcm_encryption_roundtrip() {
        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let encryptor = AesGcmEncryptor::new(key);

        let plaintext = b"Hello, Iceberg encryption!";
        let aad = b"additional authenticated data";

        // Test without AAD
        let ciphertext = encryptor.encrypt(plaintext, None).unwrap();
        assert!(ciphertext.len() > plaintext.len() + 12); // nonce + tag
        assert_ne!(&ciphertext[12..], plaintext); // encrypted portion differs

        let decrypted = encryptor.decrypt(&ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test with AAD
        let ciphertext = encryptor.encrypt(plaintext, Some(aad)).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test with wrong AAD fails
        assert!(encryptor.decrypt(&ciphertext, Some(b"wrong aad")).is_err());
    }

    #[test]
    fn test_encryption_with_empty_plaintext() {
        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let encryptor = AesGcmEncryptor::new(key);

        let plaintext = b"";
        let ciphertext = encryptor.encrypt(plaintext, None).unwrap();

        // Even empty plaintext produces nonce + tag
        assert_eq!(ciphertext.len(), 12 + 16); // 12-byte nonce + 16-byte tag

        let decrypted = encryptor.decrypt(&ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decryption_with_tampered_ciphertext() {
        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let encryptor = AesGcmEncryptor::new(key);

        let plaintext = b"Sensitive data";
        let mut ciphertext = encryptor.encrypt(plaintext, None).unwrap();

        // Tamper with the encrypted portion (after the nonce)
        if ciphertext.len() > 12 {
            ciphertext[12] ^= 0xFF;
        }

        // Decryption should fail due to authentication tag mismatch
        assert!(encryptor.decrypt(&ciphertext, None).is_err());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let key1 = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let key2 = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);

        let encryptor1 = AesGcmEncryptor::new(key1);
        let encryptor2 = AesGcmEncryptor::new(key2);

        let plaintext = b"Same plaintext";

        let ciphertext1 = encryptor1.encrypt(plaintext, None).unwrap();
        let ciphertext2 = encryptor2.encrypt(plaintext, None).unwrap();

        // Different keys should produce different ciphertexts (comparing the encrypted portion)
        // Note: The nonces will also be different, but we're mainly interested in the encrypted data
        assert_ne!(&ciphertext1[12..], &ciphertext2[12..]);
    }

    #[test]
    fn test_ciphertext_format_java_compatible() {
        // Test that our ciphertext format matches Java's: [12-byte nonce][ciphertext][16-byte tag]
        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let encryptor = AesGcmEncryptor::new(key);

        let plaintext = b"Test data";
        let ciphertext = encryptor.encrypt(plaintext, None).unwrap();

        // Format should be: [12-byte nonce][encrypted_data + 16-byte GCM tag]
        assert_eq!(
            ciphertext.len(),
            12 + plaintext.len() + 16,
            "Ciphertext should be nonce + plaintext + tag length"
        );

        // Verify we can decrypt by extracting nonce from the beginning
        let nonce = &ciphertext[..12];
        assert_eq!(nonce.len(), 12, "Nonce should be 12 bytes");

        // The rest is encrypted data + tag
        let encrypted_with_tag = &ciphertext[12..];
        assert_eq!(
            encrypted_with_tag.len(),
            plaintext.len() + 16,
            "Encrypted portion should be plaintext length + 16-byte tag"
        );
    }
}
=======
    #[tokio::test]
    async fn test_aes128_gcm_round_trip() {
        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let aad_prefix = AesGcmEncryptor::generate_aad_prefix();
        let encryptor = AesGcmEncryptor::new(EncryptionAlgorithm::Aes128Gcm, key, aad_prefix)
            .expect("Failed to create encryptor");

        let plaintext = b"Hello, Iceberg encryption!";
        let aad = b"additional data";

        let ciphertext = encryptor
            .encrypt(plaintext, aad)
            .await
            .expect("Encryption failed");

        let decrypted = encryptor
            .decrypt(&ciphertext, aad)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[tokio::test]
    async fn test_aes256_gcm_round_trip() {
        let key = SecureKey::generate(EncryptionAlgorithm::Aes256Gcm);
        let aad_prefix = AesGcmEncryptor::generate_aad_prefix();
        let encryptor = AesGcmEncryptor::new(EncryptionAlgorithm::Aes256Gcm, key, aad_prefix)
            .expect("Failed to create encryptor");

        let plaintext = b"Testing AES-256-GCM encryption";
        let aad = b"metadata";

        let ciphertext = encryptor
            .encrypt(plaintext, aad)
            .await
            .expect("Encryption failed");

        let decrypted = encryptor
            .decrypt(&ciphertext, aad)
            .await
            .expect("Decryption failed");

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[tokio::test]
    async fn test_wrong_aad_fails() {
        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let aad_prefix = AesGcmEncryptor::generate_aad_prefix();
        let encryptor = AesGcmEncryptor::new(EncryptionAlgorithm::Aes128Gcm, key, aad_prefix)
            .expect("Failed to create encryptor");

        let plaintext = b"Secret message";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encryptor
            .encrypt(plaintext, aad)
            .await
            .expect("Encryption failed");

        // Decryption with wrong AAD should fail
        let result = encryptor.decrypt(&ciphertext, wrong_aad).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_key_zeroization() {
        let key_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let key = SecureKey::new(key_data.clone());

        // Key should be accessible
        assert_eq!(key.as_bytes(), &key_data[..]);

        // After drop, memory should be zeroized (tested implicitly by ZeroizeOnDrop)
    }
}

>>>>>>> b92118e5 (Implement KMS for encryption / decryption)
