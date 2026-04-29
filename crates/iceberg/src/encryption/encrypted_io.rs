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

//! Encrypted file wrappers for InputFile / OutputFile.

use std::sync::Arc;

use bytes::Bytes;

use super::file_decryptor::AesGcmFileDecryptor;
use super::file_encryptor::AesGcmFileEncryptor;
use crate::io::{FileMetadata, FileRead, FileWrite, InputFile, OutputFile};

/// An AGS1 stream-encrypted input file wrapping a plain [`InputFile`].
///
/// Transparently decrypts on read.
pub struct EncryptedInputFile {
    inner: InputFile,
    decryptor: Arc<AesGcmFileDecryptor>,
}

impl EncryptedInputFile {
    /// Creates a new encrypted input file.
    pub fn new(inner: InputFile, decryptor: Arc<AesGcmFileDecryptor>) -> Self {
        Self { inner, decryptor }
    }

    /// Absolute path of the file.
    pub fn location(&self) -> &str {
        self.inner.location()
    }

    /// Check if file exists.
    pub async fn exists(&self) -> crate::Result<bool> {
        self.inner.exists().await
    }

    /// Fetch and returns metadata of file.
    ///
    /// The returned size is the **plaintext** size.
    pub async fn metadata(&self) -> crate::Result<FileMetadata> {
        let raw_meta = self.inner.metadata().await?;
        let plaintext_size = self.decryptor.plaintext_length(raw_meta.size)?;
        Ok(FileMetadata {
            size: plaintext_size,
        })
    }

    /// Read and returns whole content of file (decrypted plaintext).
    pub async fn read(&self) -> crate::Result<Bytes> {
        let meta = self.metadata().await?;
        let reader = self.reader().await?;
        reader.read(0..meta.size).await
    }

    /// Creates a reader that transparently decrypts on each read.
    pub async fn reader(&self) -> crate::Result<Box<dyn FileRead>> {
        let raw_meta = self.inner.metadata().await?;
        let raw_reader = self.inner.reader().await?;
        self.decryptor.wrap_reader(raw_reader, raw_meta.size)
    }

    /// Consumes self and returns the underlying plain input file.
    pub fn into_inner(self) -> InputFile {
        self.inner
    }
}

impl std::fmt::Debug for EncryptedInputFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedInputFile")
            .field("path", &self.inner.location())
            .finish_non_exhaustive()
    }
}

/// An AGS1 stream-encrypted output file wrapping a plain [`OutputFile`].
///
/// Transparently encrypts on write.
pub struct EncryptedOutputFile {
    inner: OutputFile,
    key_metadata: Box<[u8]>,
    encryptor: Arc<AesGcmFileEncryptor>,
}

impl EncryptedOutputFile {
    /// Creates a new encrypted output file.
    pub fn new(
        inner: OutputFile,
        key_metadata: Box<[u8]>,
        encryptor: Arc<AesGcmFileEncryptor>,
    ) -> Self {
        Self {
            inner,
            key_metadata,
            encryptor,
        }
    }

    /// Returns the key metadata bytes (for storage in manifest/data files).
    pub fn key_metadata(&self) -> &[u8] {
        &self.key_metadata
    }

    /// Absolute path of the file.
    pub fn location(&self) -> &str {
        self.inner.location()
    }

    /// Creates a writer that transparently encrypts on each write.
    pub async fn writer(&self) -> crate::Result<Box<dyn FileWrite>> {
        let raw_writer = self.inner.writer().await?;
        Ok(self.encryptor.wrap_writer(raw_writer))
    }

    /// Write bytes to file (transparently encrypted).
    pub async fn write(&self, bs: Bytes) -> crate::Result<()> {
        let mut writer = self.writer().await?;
        writer.write(bs).await?;
        writer.close().await
    }

    /// Deletes the underlying file.
    pub async fn delete(&self) -> crate::Result<()> {
        self.inner.delete().await
    }

    /// Consumes self and returns the underlying plain output file.
    pub fn into_inner(self) -> OutputFile {
        self.inner
    }
}

impl std::fmt::Debug for EncryptedOutputFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedOutputFile")
            .field("path", &self.inner.location())
            .finish_non_exhaustive()
    }
}
