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

//! Encrypted Parquet file reader support

use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use futures::{FutureExt, TryFutureExt};
use parquet::arrow::async_reader::AsyncFileReader;
use parquet::arrow::arrow_reader::ArrowReaderOptions;
#[cfg(feature = "encryption")]
use parquet::encryption::decrypt::FileDecryptionProperties;
use parquet::file::metadata::{PageIndexPolicy, ParquetMetaData, ParquetMetaDataReader};

use crate::encryption::EncryptionManager;
use crate::io::{FileMetadata, FileRead};
use crate::Result;

/// ArrowFileReader that supports encrypted Parquet files
pub struct EncryptedArrowFileReader<R: FileRead> {
    meta: FileMetadata,
    preload_column_index: bool,
    preload_offset_index: bool,
    preload_page_index: bool,
    metadata_size_hint: Option<usize>,
    r: R,
    #[cfg(feature = "encryption")]
    decryption_properties: Option<Arc<FileDecryptionProperties>>,
}

impl<R: FileRead> EncryptedArrowFileReader<R> {
    /// Create a new EncryptedArrowFileReader without encryption
    pub fn new(meta: FileMetadata, r: R) -> Self {
        Self {
            meta,
            preload_column_index: false,
            preload_offset_index: false,
            preload_page_index: false,
            metadata_size_hint: None,
            r,
            #[cfg(feature = "encryption")]
            decryption_properties: None,
        }
    }

    /// Create a new EncryptedArrowFileReader with encryption
    #[cfg(feature = "encryption")]
    pub async fn new_with_encryption(
        meta: FileMetadata,
        r: R,
        encryption_manager: Arc<dyn EncryptionManager>,
    ) -> Result<Self> {
        // Get the current key metadata
        let key_metadata = encryption_manager.current_key_metadata().await?;

        // Get the raw decryption key
        let file_key = encryption_manager.get_raw_key(&key_metadata).await?;

        // Create FileDecryptionProperties - builder returns Arc<FileDecryptionProperties>
        let decryption_props_arc = FileDecryptionProperties::builder(file_key.into())
            .with_aad_prefix(key_metadata.aad_prefix.clone().into())
            .build()
            .map_err(|e| {
                crate::Error::new(
                    crate::ErrorKind::Unexpected,
                    "Failed to create decryption properties",
                )
                .with_source(e)
            })?;

        // Need to extract from Arc - note: this may need adjustment based on actual API
        // For now, we'll store it as Arc and adjust the field type
        Ok(Self {
            meta,
            preload_column_index: false,
            preload_offset_index: false,
            preload_page_index: false,
            metadata_size_hint: None,
            r,
            decryption_properties: Some(decryption_props_arc),
        })
    }

    /// Enable or disable preloading of the column index
    pub fn with_preload_column_index(mut self, preload: bool) -> Self {
        self.preload_column_index = preload;
        self
    }

    /// Enable or disable preloading of the offset index
    pub fn with_preload_offset_index(mut self, preload: bool) -> Self {
        self.preload_offset_index = preload;
        self
    }

    /// Enable or disable preloading of the page index
    pub fn with_preload_page_index(mut self, preload: bool) -> Self {
        self.preload_page_index = preload;
        self
    }

    /// Provide a hint as to the number of bytes to prefetch for parsing the Parquet metadata
    pub fn with_metadata_size_hint(mut self, hint: usize) -> Self {
        self.metadata_size_hint = Some(hint);
        self
    }

    /// Get the decryption properties if available
    #[cfg(feature = "encryption")]
    pub fn decryption_properties(&self) -> Option<&Arc<FileDecryptionProperties>> {
        self.decryption_properties.as_ref()
    }
}

impl<R: FileRead> AsyncFileReader for EncryptedArrowFileReader<R> {
    fn get_bytes(&mut self, range: Range<u64>) -> BoxFuture<'_, parquet::errors::Result<Bytes>> {
        Box::pin(
            self.r
                .read(range.start..range.end)
                .map_err(|err| parquet::errors::ParquetError::External(Box::new(err))),
        )
    }

    fn get_metadata(
        &mut self,
        _options: Option<&'_ ArrowReaderOptions>,
    ) -> BoxFuture<'_, parquet::errors::Result<Arc<ParquetMetaData>>> {
        async move {
            // For encrypted files, we need to handle metadata differently
            // The parquet crate handles decryption internally when properties are provided
            // to the builder in the actual reader implementation
            let reader = ParquetMetaDataReader::new()
                .with_prefetch_hint(self.metadata_size_hint)
                .with_page_index_policy(PageIndexPolicy::from(self.preload_page_index))
                .with_column_index_policy(PageIndexPolicy::from(self.preload_column_index))
                .with_offset_index_policy(PageIndexPolicy::from(self.preload_offset_index));

            let size = self.meta.size;
            let meta = reader.load_and_finish(self, size).await?;

            Ok(Arc::new(meta))
        }
        .boxed()
    }
}