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

//! Pluggable resolution of per-file `key_metadata` into usable key material.

use std::fmt::Debug;

use async_trait::async_trait;

use super::StandardKeyMetadata;
use crate::Result;

/// Resolves the raw, format-neutral `key_metadata` bytes carried by a scan
/// task into the key material needed to decrypt a file.
///
/// The spec defines `key_metadata` (field 131) as implementation-specific. The
/// reference *standard* encryption scheme stores a [`StandardKeyMetadata`]
/// whose payload is the plaintext DEK, so resolution is a synchronous decode
/// (see [`StandardFileKeyResolver`]). Other schemes may instead store a key
/// *reference* — for example a wrapped DEK plus a key id resolved from a KMS at
/// read time — which requires an async round-trip. The trait is therefore
/// `async`, and implementations return the resolved [`StandardKeyMetadata`]
/// (plaintext DEK + optional AAD prefix); the per-format conversion into, e.g.,
/// Parquet `FileDecryptionProperties` or an AES-GCM-stream key is the
/// responsibility of the individual file reader, keeping this layer free of any
/// format-specific (arrow / parquet) types.
#[async_trait]
pub trait FileKeyResolver: Debug + Send + Sync {
    /// Resolve the given `key_metadata` blob into [`StandardKeyMetadata`].
    async fn resolve(&self, key_metadata: &[u8]) -> Result<StandardKeyMetadata>;
}

/// Default [`FileKeyResolver`] for the standard encryption scheme.
///
/// `key_metadata` already embeds the plaintext DEK, so resolution is a
/// synchronous [`StandardKeyMetadata::decode`] with no KMS round-trip; it
/// satisfies the async signature trivially.
#[derive(Debug, Default, Clone)]
pub struct StandardFileKeyResolver;

#[async_trait]
impl FileKeyResolver for StandardFileKeyResolver {
    async fn resolve(&self, key_metadata: &[u8]) -> Result<StandardKeyMetadata> {
        StandardKeyMetadata::decode(key_metadata)
    }
}
