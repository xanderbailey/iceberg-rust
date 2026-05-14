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

//! Validated, role-specific views over [`EncryptedKey`].
//!
//! `TableMetadata.encryption_keys` is a single map of [`EncryptedKey`] entries
//! that play two roles: Key Encryption Keys (KEKs) wrapped by the table's
//! master key, and wrapped manifest-list key metadata entries. The wrappers
//! here parse an [`EncryptedKey`] into the appropriate role and fail loudly
//! if classification or required properties are wrong.

use std::ops::Deref;

use chrono::Utc;

use crate::spec::EncryptedKey;
use crate::{Error, ErrorKind, Result};

/// Property holding the KEK creation timestamp (milliseconds since epoch).
/// Matches Java's `StandardEncryptionManager.KEY_TIMESTAMP`.
pub(crate) const KEK_CREATED_AT_PROPERTY: &str = "KEY_TIMESTAMP";

/// Default KEK lifespan in days, per NIST SP 800-57.
const DEFAULT_KEK_LIFESPAN_DAYS: i64 = 730;
const MILLIS_IN_DAY: i64 = 24 * 60 * 60 * 1000;

/// A Key Encryption Key (KEK): a parsed, validated [`EncryptedKey`] whose
/// `encrypted_by_id` references the table's master key id.
///
/// Construct via [`KeyEncryptionKey::try_from_encrypted_key`] — validation is
/// the only way to obtain one, so possessing this type means the underlying
/// entry is well-formed enough to be used as a KEK. KEKs carry a
/// [`KEK_CREATED_AT_PROPERTY`] property used both for rotation (NIST SP 800-57 730-day
/// lifespan) and as AAD when wrapping DEKs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyEncryptionKey(EncryptedKey);

impl KeyEncryptionKey {
    /// Construct a new KEK from validated parts.
    ///
    /// `created_at_ms` is stored as the [`KEK_CREATED_AT_PROPERTY`] property (used for
    /// rotation and as AAD when wrapping DEKs). Use this when the caller has
    /// just produced a fresh KEK locally (e.g. via the KMS); for keys loaded
    /// from table metadata, use [`Self::try_from_encrypted_key`] which
    /// re-validates the same invariants.
    pub(crate) fn new(
        key_id: impl Into<String>,
        wrapped_key_metadata: impl Into<Vec<u8>>,
        master_key_id: impl Into<String>,
        created_at_ms: i64,
    ) -> Self {
        let mut properties = std::collections::HashMap::new();
        properties.insert(
            KEK_CREATED_AT_PROPERTY.to_string(),
            created_at_ms.to_string(),
        );
        Self(
            EncryptedKey::builder()
                .key_id(key_id)
                .encrypted_key_metadata(wrapped_key_metadata)
                .encrypted_by_id(master_key_id)
                .properties(properties)
                .build(),
        )
    }

    /// Validate and wrap an [`EncryptedKey`] as a KEK for `table_key_id`.
    /// Fails with `DataInvalid` if the entry is not encrypted by the table's
    /// master key, or if it is missing/has an unparseable [`KEK_CREATED_AT_PROPERTY`]
    /// property.
    ///
    /// Validating the timestamp here means accessors like
    /// [`Self::created_at_ms`], [`Self::is_expired`], and
    /// [`Self::timestamp_aad`] are infallible — and also surfaces malformed
    /// KEKs loudly at access time rather than silently weakening the
    /// timestamp-as-AAD tampering defense.
    pub(crate) fn try_from_encrypted_key(key: EncryptedKey, table_key_id: &str) -> Result<Self> {
        if key.encrypted_by_id() != Some(table_key_id) {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "EncryptedKey '{}' is not a KEK for master key '{}': encrypted_by_id = {:?}",
                    key.key_id(),
                    table_key_id,
                    key.encrypted_by_id()
                ),
            ));
        }
        let raw = key
            .properties()
            .get(KEK_CREATED_AT_PROPERTY)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::DataInvalid,
                    format!(
                        "KEK '{}' is missing required '{}' property",
                        key.key_id(),
                        KEK_CREATED_AT_PROPERTY
                    ),
                )
            })?;
        raw.parse::<i64>().map_err(|e| {
            Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "KEK '{}' has unparseable '{}' property: {raw}",
                    key.key_id(),
                    KEK_CREATED_AT_PROPERTY
                ),
            )
            .with_source(Error::new(ErrorKind::DataInvalid, e.to_string()))
        })?;
        Ok(Self(key))
    }

    /// The KEK creation timestamp in milliseconds since the Unix epoch.
    pub(crate) fn created_at_ms(&self) -> i64 {
        self.0
            .properties()
            .get(KEK_CREATED_AT_PROPERTY)
            .expect("KEY_TIMESTAMP validated at construction")
            .parse::<i64>()
            .expect("KEY_TIMESTAMP validated at construction")
    }

    /// Whether this KEK has exceeded its 730-day lifespan.
    pub(crate) fn is_expired(&self) -> bool {
        let now_ms = Utc::now().timestamp_millis();
        let lifespan_ms = DEFAULT_KEK_LIFESPAN_DAYS * MILLIS_IN_DAY;
        (now_ms - self.created_at_ms()) >= lifespan_ms
    }

    /// Borrow the KEK's creation timestamp as bytes for use as AAD when
    /// wrapping/unwrapping DEKs.
    pub(crate) fn timestamp_aad(&self) -> &[u8] {
        self.0
            .properties()
            .get(KEK_CREATED_AT_PROPERTY)
            .expect("KEY_TIMESTAMP validated at construction")
            .as_bytes()
    }
}

impl Deref for KeyEncryptionKey {
    type Target = EncryptedKey;
    fn deref(&self) -> &EncryptedKey {
        &self.0
    }
}

impl From<KeyEncryptionKey> for EncryptedKey {
    fn from(kek: KeyEncryptionKey) -> Self {
        kek.0
    }
}

/// A wrapped manifest-list key metadata entry: a parsed, validated
/// [`EncryptedKey`] whose `encrypted_by_id` references a
/// [`KeyEncryptionKey`] (i.e. *not* the table's master key).
///
/// Snapshots reference these by `key_id` via `Snapshot.encryption_key_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestEncryptionKey(EncryptedKey);

impl ManifestEncryptionKey {
    /// Construct a new manifest-list entry from validated parts.
    ///
    /// Use this when the caller has just wrapped a DEK with a known KEK; for
    /// entries loaded from table metadata, use [`Self::try_from_encrypted_key`]
    /// which re-validates the same invariants.
    pub(crate) fn new(
        key_id: impl Into<String>,
        wrapped_key_metadata: impl Into<Vec<u8>>,
        kek_id: impl Into<String>,
    ) -> Self {
        Self(
            EncryptedKey::builder()
                .key_id(key_id)
                .encrypted_key_metadata(wrapped_key_metadata)
                .encrypted_by_id(kek_id)
                .build(),
        )
    }

    /// Validate and wrap an [`EncryptedKey`] as a manifest-list entry. Fails
    /// if the entry is in fact a KEK for `table_key_id`, or if it has no
    /// `encrypted_by_id` (we can't decrypt without one).
    pub(crate) fn try_from_encrypted_key(key: EncryptedKey, table_key_id: &str) -> Result<Self> {
        let kek_id = key.encrypted_by_id().ok_or_else(|| {
            Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "ManifestEncryptionKey '{}' has no encrypted_by_id",
                    key.key_id()
                ),
            )
        })?;
        if kek_id == table_key_id {
            return Err(Error::new(
                ErrorKind::DataInvalid,
                format!(
                    "EncryptedKey '{}' is a KEK, not a manifest entry",
                    key.key_id()
                ),
            ));
        }
        Ok(Self(key))
    }

    /// The id of the [`KeyEncryptionKey`] that wrapped this entry. Always
    /// present (validated at construction).
    pub(crate) fn kek_id(&self) -> &str {
        self.0.encrypted_by_id().expect("validated at construction")
    }
}

impl Deref for ManifestEncryptionKey {
    type Target = EncryptedKey;
    fn deref(&self) -> &EncryptedKey {
        &self.0
    }
}

impl From<ManifestEncryptionKey> for EncryptedKey {
    fn from(entry: ManifestEncryptionKey) -> Self {
        entry.0
    }
}
