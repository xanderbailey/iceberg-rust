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

//! Resolving storage that auto-detects the scheme from a path and delegates
//! to the appropriate [`OpenDalBackend`] variant.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use iceberg::io::{
    FileMetadata, FileRead, FileWrite, InputFile, OutputFile, Storage, StorageConfig,
    StorageFactory,
};
use iceberg::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use url::Url;

#[cfg(feature = "opendal-s3")]
use crate::s3::CustomAwsCredentialLoader;
use crate::{OpenDalBackend, OpenDalStorage, OpenDalStorageSettings};

/// Schemes supported by OpenDalResolvingStorage
pub const SCHEME_MEMORY: &str = "memory";
pub const SCHEME_FILE: &str = "file";
pub const SCHEME_S3: &str = "s3";
pub const SCHEME_S3A: &str = "s3a";
pub const SCHEME_S3N: &str = "s3n";
pub const SCHEME_GS: &str = "gs";
pub const SCHEME_GCS: &str = "gcs";
pub const SCHEME_OSS: &str = "oss";
pub const SCHEME_ABFSS: &str = "abfss";
pub const SCHEME_ABFS: &str = "abfs";
pub const SCHEME_WASBS: &str = "wasbs";
pub const SCHEME_WASB: &str = "wasb";
pub const SCHEME_HF: &str = "hf";

/// Parse a URL scheme string.
fn parse_scheme(scheme: &str) -> Result<&'static str> {
    match scheme {
        SCHEME_MEMORY => Ok("memory"),
        SCHEME_FILE | "" => Ok("file"),
        SCHEME_S3 | SCHEME_S3A | SCHEME_S3N => Ok("s3"),
        SCHEME_GS | SCHEME_GCS => Ok("gcs"),
        SCHEME_OSS => Ok("oss"),
        SCHEME_ABFSS | SCHEME_ABFS | SCHEME_WASBS | SCHEME_WASB => Ok("azdls"),
        SCHEME_HF => Ok("hf"),
        s => Err(Error::new(
            ErrorKind::FeatureUnsupported,
            format!("Unsupported storage scheme: {s}"),
        )),
    }
}

/// Extract the scheme from a path URL.
fn extract_scheme(path: &str) -> Result<&'static str> {
    let url = Url::parse(path).map_err(|e| {
        Error::new(
            ErrorKind::DataInvalid,
            format!("Invalid path: {path}, failed to parse URL: {e}"),
        )
    })?;
    parse_scheme(url.scheme())
}

/// Build an [`OpenDalBackend`] variant for the given scheme and config properties.
fn build_backend_for_scheme(
    scheme: &'static str,
    props: &HashMap<String, String>,
    #[cfg(feature = "opendal-s3")] customized_credential_load: &Option<CustomAwsCredentialLoader>,
) -> Result<OpenDalBackend> {
    match scheme {
        #[cfg(feature = "opendal-s3")]
        "s3" => {
            let config = crate::s3::s3_config_parse(props.clone())?;
            Ok(OpenDalBackend::S3 {
                config: Arc::new(config),
                customized_credential_load: customized_credential_load.clone(),
            })
        }
        #[cfg(feature = "opendal-gcs")]
        "gcs" => {
            let config = crate::gcs::gcs_config_parse(props.clone())?;
            Ok(OpenDalBackend::Gcs {
                config: Arc::new(config),
            })
        }
        #[cfg(feature = "opendal-oss")]
        "oss" => {
            let config = crate::oss::oss_config_parse(props.clone())?;
            Ok(OpenDalBackend::Oss {
                config: Arc::new(config),
            })
        }
        #[cfg(feature = "opendal-azdls")]
        "azdls" => {
            let config = crate::azdls::azdls_config_parse(props.clone())?;
            Ok(OpenDalBackend::Azdls {
                config: Arc::new(config),
            })
        }
        #[cfg(feature = "opendal-fs")]
        "file" => Ok(OpenDalBackend::LocalFs),
        #[cfg(feature = "opendal-memory")]
        "memory" => Ok(OpenDalBackend::Memory(crate::memory::memory_config_build()?)),
        #[cfg(feature = "opendal-hf")]
        "hf" => {
            let config = crate::hf::hf_config_parse(props.clone())?;
            Ok(OpenDalBackend::Hf {
                config: Arc::new(config),
            })
        }
        unsupported => Err(Error::new(
            ErrorKind::FeatureUnsupported,
            format!("Unsupported storage scheme: {unsupported}"),
        )),
    }
}

/// A resolving storage factory that creates [`OpenDalResolvingStorage`] instances.
///
/// This factory accepts paths from any supported storage system and dynamically
/// delegates operations to the appropriate [`OpenDalBackend`] variant based on
/// the path scheme.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
/// use iceberg::io::FileIOBuilder;
/// use iceberg_storage_opendal::OpenDalResolvingStorageFactory;
///
/// let factory = OpenDalResolvingStorageFactory::new();
/// let file_io = FileIOBuilder::new(Arc::new(factory))
///     .with_prop("s3.region", "us-east-1")
///     .build();
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenDalResolvingStorageFactory {
    /// Custom AWS credential loader for S3 storage.
    #[cfg(feature = "opendal-s3")]
    #[serde(skip)]
    customized_credential_load: Option<CustomAwsCredentialLoader>,
}

impl Default for OpenDalResolvingStorageFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenDalResolvingStorageFactory {
    /// Create a new resolving storage factory.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "opendal-s3")]
            customized_credential_load: None,
        }
    }

    /// Set a custom AWS credential loader for S3 storage.
    #[cfg(feature = "opendal-s3")]
    pub fn with_s3_credential_loader(mut self, loader: CustomAwsCredentialLoader) -> Self {
        self.customized_credential_load = Some(loader);
        self
    }
}

#[typetag::serde]
impl StorageFactory for OpenDalResolvingStorageFactory {
    fn build(&self, config: &StorageConfig) -> Result<Arc<dyn Storage>> {
        Ok(Arc::new(OpenDalResolvingStorage {
            // Parsed here rather than per scheme so invalid values are reported
            // when the storage is built, not on the first operation.
            settings: OpenDalStorageSettings::from_props(config.props())?,
            props: config.props().clone(),
            storages: RwLock::new(HashMap::new()),
            #[cfg(feature = "opendal-s3")]
            customized_credential_load: self.customized_credential_load.clone(),
        }))
    }
}

/// A resolving storage that auto-detects the scheme from a path and delegates
/// to the appropriate [`OpenDalBackend`] variant.
///
/// Sub-storages are lazily created on first use for each scheme and cached
/// for subsequent operations. Scheme aliases like `s3`/`s3a`/`s3n` map to
/// the same canonical scheme, so they share a storage instance.
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenDalResolvingStorage {
    /// Configuration properties shared across all backends.
    props: HashMap<String, String>,
    /// Timeout and retry settings shared across all backends.
    #[serde(default)]
    settings: OpenDalStorageSettings,
    /// Cache of canonical scheme to storage mappings.
    #[serde(skip, default)]
    storages: RwLock<HashMap<&'static str, Arc<OpenDalStorage>>>,
    /// Custom AWS credential loader for S3 storage.
    #[cfg(feature = "opendal-s3")]
    #[serde(skip)]
    customized_credential_load: Option<CustomAwsCredentialLoader>,
}

impl OpenDalResolvingStorage {
    /// Resolve the storage for the given path by extracting the canonical scheme and
    /// returning the cached or newly-created [`OpenDalStorage`].
    fn resolve(&self, path: &str) -> Result<Arc<OpenDalStorage>> {
        let scheme = extract_scheme(path)?;

        // Fast path: check read lock first.
        {
            let cache = self
                .storages
                .read()
                .map_err(|_| Error::new(ErrorKind::Unexpected, "Storage cache lock poisoned"))?;
            if let Some(storage) = cache.get(&scheme) {
                return Ok(storage.clone());
            }
        }

        // Slow path: build and insert under write lock.
        let mut cache = self
            .storages
            .write()
            .map_err(|_| Error::new(ErrorKind::Unexpected, "Storage cache lock poisoned"))?;

        // Double-check after acquiring write lock.
        if let Some(storage) = cache.get(&scheme) {
            return Ok(storage.clone());
        }

        let backend = build_backend_for_scheme(
            scheme,
            &self.props,
            #[cfg(feature = "opendal-s3")]
            &self.customized_credential_load,
        )?;
        let storage = Arc::new(OpenDalStorage {
            backend,
            settings: self.settings,
        });
        cache.insert(scheme, storage.clone());
        Ok(storage)
    }
}

#[async_trait]
#[typetag::serde]
impl Storage for OpenDalResolvingStorage {
    async fn exists(&self, path: &str) -> Result<bool> {
        self.resolve(path)?.exists(path).await
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        self.resolve(path)?.metadata(path).await
    }

    async fn read(&self, path: &str) -> Result<Bytes> {
        self.resolve(path)?.read(path).await
    }

    async fn reader(&self, path: &str) -> Result<Box<dyn FileRead>> {
        self.resolve(path)?.reader(path).await
    }

    async fn write(&self, path: &str, bs: Bytes) -> Result<()> {
        self.resolve(path)?.write(path, bs).await
    }

    async fn writer(&self, path: &str) -> Result<Box<dyn FileWrite>> {
        self.resolve(path)?.writer(path).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.resolve(path)?.delete(path).await
    }

    async fn delete_prefix(&self, path: &str) -> Result<()> {
        self.resolve(path)?.delete_prefix(path).await
    }

    async fn delete_stream(&self, mut paths: BoxStream<'static, String>) -> Result<()> {
        // Group paths by canonical scheme so each resolved storage receives a batch,
        // avoiding repeated operator creation per path.
        let mut grouped: HashMap<&'static str, Vec<String>> = HashMap::new();
        while let Some(path) = paths.next().await {
            let scheme = extract_scheme(&path)?;
            grouped.entry(scheme).or_default().push(path);
        }

        for (_, paths) in grouped {
            let storage = self.resolve(&paths[0])?;
            storage
                .delete_stream(futures::stream::iter(paths).boxed())
                .await?;
        }
        Ok(())
    }

    fn new_input(&self, path: &str) -> Result<InputFile> {
        Ok(InputFile::new(self.resolve(path)?, path.to_string()))
    }

    fn new_output(&self, path: &str) -> Result<OutputFile> {
        Ok(OutputFile::new(self.resolve(path)?, path.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a resolving storage with empty props, suitable for `resolve()`
    /// calls that don't actually hit any backend.
    fn empty_resolving_storage() -> OpenDalResolvingStorage {
        OpenDalResolvingStorage {
            props: HashMap::new(),
            settings: OpenDalStorageSettings::default(),
            storages: RwLock::new(HashMap::new()),
            #[cfg(feature = "opendal-s3")]
            customized_credential_load: None,
        }
    }

    #[test]
    fn test_factory_rejects_invalid_settings() {
        let config = StorageConfig::new().with_prop(crate::OPENDAL_RETRY_FACTOR, "0.5");
        let error = OpenDalResolvingStorageFactory::new()
            .build(&config)
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DataInvalid);
        assert!(format!("{error}").contains(crate::OPENDAL_RETRY_FACTOR));
    }

    #[cfg(feature = "opendal-memory")]
    #[test]
    fn test_resolve_applies_settings_to_each_scheme() {
        let props = HashMap::from([(crate::OPENDAL_RETRY_MAX_TIMES.to_string(), "7".to_string())]);
        let storage = OpenDalResolvingStorage {
            settings: OpenDalStorageSettings::from_props(&props).unwrap(),
            props,
            storages: RwLock::new(HashMap::new()),
            #[cfg(feature = "opendal-s3")]
            customized_credential_load: None,
        };

        let resolved = storage.resolve("memory:/file").unwrap();
        assert_eq!(resolved.settings.retry_max_times, Some(7));
    }

    #[cfg(feature = "opendal-s3")]
    #[test]
    fn test_resolve_s3_aliases_share_instance() {
        let storage = empty_resolving_storage();

        // All three S3-family schemes must collapse to a single cached
        // `Arc<OpenDalStorage>` so that catalogs handing the resolver a mix
        // of `s3://`, `s3a://`, `s3n://` paths don't rebuild operators.
        let a = storage.resolve("s3://bucket/key").unwrap();
        let b = storage.resolve("s3a://bucket/key").unwrap();
        let c = storage.resolve("s3n://bucket/key").unwrap();

        assert!(Arc::ptr_eq(&a, &b), "s3 and s3a should share one instance");
        assert!(Arc::ptr_eq(&a, &c), "s3 and s3n should share one instance");
    }

    #[cfg(feature = "opendal-azdls")]
    #[test]
    fn test_resolve_azdls_aliases_share_instance() {
        let storage = empty_resolving_storage();

        let path_for = |scheme: &str| {
            format!("{scheme}://myfs@myaccount.dfs.core.windows.net/path/to/file.parquet")
        };

        // All Azure schemes collapse onto one cached instance.
        let abfss = storage.resolve(&path_for("abfss")).unwrap();
        let abfs = storage.resolve(&path_for("abfs")).unwrap();

        assert!(
            Arc::ptr_eq(&abfss, &abfs),
            "abfss and abfs should share one instance"
        );
    }
}
