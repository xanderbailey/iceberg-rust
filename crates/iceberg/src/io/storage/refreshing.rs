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

//! A [`Storage`] wrapper that lazily re-vends credentials before they expire.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use futures::stream::BoxStream;
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::sync::RwLock;

use super::{Storage, StorageConfig, StorageFactory};
use crate::Result;
use crate::io::{FileMetadata, FileRead, FileWrite, InputFile, OutputFile};

/// Property key carrying credential expiry, matching the Iceberg Java client.
pub(crate) const SESSION_TOKEN_EXPIRES_AT_MS: &str = "s3.session-token-expires-at-ms";

/// Refresh once the credentials are within this window of expiring, so a fresh
/// token is in hand before the old one is rejected (matches Java's 5 minutes).
const PREFETCH_WINDOW_MS: i64 = 5 * 60 * 1000;

/// Hook that re-vends fresh credential properties for a location `prefix`.
///
/// Implemented by a catalog (e.g. the REST catalog) so that [`FileIO`] can obtain
/// replacement credentials once the current vended ones approach expiry, without
/// [`FileIO`] itself knowing how credentials are fetched.
///
/// A hook is a *live* object (it may hold an authenticated HTTP client), so it is
/// not itself serializable. To let a [`RefreshingStorage`] round-trip through
/// serde — as distributed engines such as DataFusion Ballista require — a hook is
/// always produced from a serializable [`CredentialRefreshFactory`].
///
/// [`FileIO`]: crate::io::FileIO
#[async_trait]
pub trait CredentialRefresh: std::fmt::Debug + Send + Sync {
    /// Fetch fresh credential properties for the storage location `prefix`.
    ///
    /// The returned map is merged over the prefix's non-credential base config to
    /// rebuild its storage, so it should include a fresh
    /// `s3.session-token-expires-at-ms` for refresh to recur.
    async fn refresh(&self, prefix: &str) -> Result<HashMap<String, String>>;
}

/// A serializable recipe for building a [`CredentialRefresh`] hook.
///
/// The hook itself holds live, non-serializable state (an authenticated client),
/// so a [`RefreshingStorage`] stores the *factory* instead and builds the hook on
/// demand. Because the factory carries only serializable configuration (endpoints,
/// OAuth credentials, …), it round-trips through serde like [`StorageFactory`],
/// letting a refreshing storage be reconstructed on a distributed executor which
/// then re-establishes its own client and re-fetches tokens as needed.
///
/// Implementors register with `#[typetag::serde]` exactly like [`StorageFactory`].
#[typetag::serde(tag = "type")]
pub trait CredentialRefreshFactory: std::fmt::Debug + Send + Sync {
    /// Build a live credential-refresh hook from this factory's configuration.
    fn build(&self) -> Result<Arc<dyn CredentialRefresh>>;
}

/// Mutable state guarded so a refresh can swap in the rebuilt storage atomically.
#[derive(Debug)]
struct RefreshState {
    storage: Arc<dyn Storage>,
    /// Epoch millis when the current credentials expire, if known.
    expires_at_ms: Option<i64>,
}

/// Shared inner state so cloned handles (created via `new_input`/`new_output`)
/// observe the same refreshed storage as the `FileIO` they came from.
#[derive(Debug)]
struct Inner {
    prefix: String,
    factory: Arc<dyn StorageFactory>,
    base_config: StorageConfig,
    /// Serializable recipe for the refresh hook; kept so this storage can itself
    /// be re-serialized as part of a `FileIO` recipe.
    refresh_factory: Arc<dyn CredentialRefreshFactory>,
    /// The live hook built from `refresh_factory`.
    refresh: Arc<dyn CredentialRefresh>,
    state: RwLock<RefreshState>,
}

/// A [`Storage`] that rebuilds itself with freshly vended credentials once the
/// current credentials enter the prefetch window.
///
/// All I/O flows through the async [`Storage`] methods, so the refresh check
/// happens per operation without changing any `FileIO` signatures. `new_input`
/// and `new_output` hand back handles wrapping a clone of this storage (sharing
/// the same [`Inner`]), so deferred reads/writes also refresh on demand.
///
/// The wrapper holds a serializable [`CredentialRefreshFactory`] rather than a
/// live hook, so it serializes and deserializes as a genuine recipe (see the
/// [`Serialize`]/[`Deserialize`] impls). Deserialization rebuilds the underlying
/// storage and the refresh hook; the freshly built storage starts from the
/// (possibly stale) credentials in `base_config` and refreshes on first use if
/// they are already within the prefetch window.
#[derive(Debug, Clone)]
pub(crate) struct RefreshingStorage {
    inner: Arc<Inner>,
}

impl RefreshingStorage {
    /// Wrap a storage for `prefix`, refreshing its credentials via a hook built
    /// from `refresh_factory` once they enter the prefetch window. `base_config`
    /// holds the props (including the initial vended credentials and their
    /// expiry) that every rebuild starts from; fresh creds are layered on top.
    pub(crate) fn new(
        prefix: impl Into<String>,
        factory: Arc<dyn StorageFactory>,
        base_config: StorageConfig,
        refresh_factory: Arc<dyn CredentialRefreshFactory>,
    ) -> Result<Self> {
        let refresh = refresh_factory.build()?;
        let storage = factory.build(&base_config)?;
        let expires_at_ms = parse_expires_at_ms(base_config.props());
        Ok(Self {
            inner: Arc::new(Inner {
                prefix: prefix.into(),
                factory,
                base_config,
                refresh_factory,
                refresh,
                state: RwLock::new(RefreshState {
                    storage,
                    expires_at_ms,
                }),
            }),
        })
    }

    /// Return the current storage, rebuilding it with freshly vended credentials
    /// first if the current ones are within the prefetch window.
    async fn ensure_fresh(&self) -> Result<Arc<dyn Storage>> {
        // Fast path: still fresh, only a read lock needed.
        {
            let state = self.inner.state.read().await;
            if !within_prefetch_window(state.expires_at_ms) {
                return Ok(state.storage.clone());
            }
        }

        let mut state = self.inner.state.write().await;
        // Re-check under the write lock: another task may have refreshed while we
        // waited, so we don't re-vend needlessly.
        if !within_prefetch_window(state.expires_at_ms) {
            return Ok(state.storage.clone());
        }

        // Refresh-or-fail: propagate errors rather than serve stale credentials.
        let fresh = self.inner.refresh.refresh(&self.inner.prefix).await?;
        let expires_at_ms = parse_expires_at_ms(&fresh);
        let config = self.inner.base_config.clone().with_props(fresh);
        let storage = self.inner.factory.build(&config)?;
        state.storage = storage.clone();
        state.expires_at_ms = expires_at_ms;
        Ok(storage)
    }
}

/// Whether credentials should be refreshed now: true when they carry an expiry
/// that is at or within [`PREFETCH_WINDOW_MS`] of the current time. Credentials
/// with no expiry are treated as non-expiring (never refreshed).
fn within_prefetch_window(expires_at_ms: Option<i64>) -> bool {
    match expires_at_ms {
        Some(expires_at_ms) => Utc::now().timestamp_millis() >= expires_at_ms - PREFETCH_WINDOW_MS,
        None => false,
    }
}

/// Parse the credential expiry (epoch millis) from a vended config, if present.
pub(crate) fn parse_expires_at_ms(config: &HashMap<String, String>) -> Option<i64> {
    config
        .get(SESSION_TOKEN_EXPIRES_AT_MS)
        .and_then(|v| v.parse().ok())
}

// A `RefreshingStorage` serializes as a recipe — the storage factory, its base
// config, and the credential-refresh factory — mirroring how `FileIO` persists a
// `StorageFactory` + `StorageConfig`. The live pieces (the built storage and the
// refresh hook) are not serialized: deserialization rebuilds them from the recipe,
// so a distributed executor reconstructs its own client and re-fetches credentials
// on first use. `typetag` gives `dyn StorageFactory` / `dyn CredentialRefreshFactory`
// their `Serialize` (and `Box<dyn _>` their `Deserialize`) impls.
impl Serialize for RefreshingStorage {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("RefreshingStorage", 4)?;
        st.serialize_field("prefix", &self.inner.prefix)?;
        st.serialize_field("factory", &*self.inner.factory)?;
        st.serialize_field("base_config", &self.inner.base_config)?;
        st.serialize_field("refresh_factory", &*self.inner.refresh_factory)?;
        st.end()
    }
}

/// The wire form of a [`RefreshingStorage`]: purely the serializable recipe.
#[derive(Deserialize)]
struct RefreshingStorageRecipe {
    prefix: String,
    factory: Box<dyn StorageFactory>,
    base_config: StorageConfig,
    refresh_factory: Box<dyn CredentialRefreshFactory>,
}

impl<'de> Deserialize<'de> for RefreshingStorage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let recipe = RefreshingStorageRecipe::deserialize(deserializer)?;
        RefreshingStorage::new(
            recipe.prefix,
            Arc::from(recipe.factory),
            recipe.base_config,
            Arc::from(recipe.refresh_factory),
        )
        .map_err(D::Error::custom)
    }
}

#[async_trait]
#[typetag::serde]
impl Storage for RefreshingStorage {
    async fn exists(&self, path: &str) -> Result<bool> {
        self.ensure_fresh().await?.exists(path).await
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        self.ensure_fresh().await?.metadata(path).await
    }

    async fn read(&self, path: &str) -> Result<Bytes> {
        self.ensure_fresh().await?.read(path).await
    }

    async fn reader(&self, path: &str) -> Result<Box<dyn FileRead>> {
        self.ensure_fresh().await?.reader(path).await
    }

    async fn write(&self, path: &str, bs: Bytes) -> Result<()> {
        self.ensure_fresh().await?.write(path, bs).await
    }

    async fn writer(&self, path: &str) -> Result<Box<dyn FileWrite>> {
        self.ensure_fresh().await?.writer(path).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        self.ensure_fresh().await?.delete(path).await
    }

    async fn delete_prefix(&self, path: &str) -> Result<()> {
        self.ensure_fresh().await?.delete_prefix(path).await
    }

    async fn delete_stream(&self, paths: BoxStream<'static, String>) -> Result<()> {
        self.ensure_fresh().await?.delete_stream(paths).await
    }

    fn new_input(&self, path: &str) -> Result<InputFile> {
        // Sync: cannot refresh here (no I/O happens yet). The handle wraps a clone
        // of this storage, so refresh runs when the handle's async I/O executes.
        Ok(InputFile::new(
            Arc::new(self.clone()) as Arc<dyn Storage>,
            path.to_string(),
        ))
    }

    fn new_output(&self, path: &str) -> Result<OutputFile> {
        Ok(OutputFile::new(
            Arc::new(self.clone()) as Arc<dyn Storage>,
            path.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::io::MemoryStorageFactory;
    use crate::{Error, ErrorKind};

    /// A refresh hook that counts calls and hands back a configurable result.
    #[derive(Debug)]
    struct FakeRefresh {
        calls: AtomicUsize,
        /// Props returned on success; if `None`, refresh fails.
        result: Option<HashMap<String, String>>,
    }

    impl FakeRefresh {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl CredentialRefresh for FakeRefresh {
        async fn refresh(&self, _prefix: &str) -> Result<HashMap<String, String>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.result {
                Some(props) => Ok(props.clone()),
                None => Err(Error::new(ErrorKind::Unexpected, "refresh failed")),
            }
        }
    }

    /// A factory that hands out a shared [`FakeRefresh`] so a test can inspect the
    /// call count of the hook the storage actually uses. This test double holds a
    /// live counter and is therefore not serializable; its serde impls error,
    /// which is fine because behavior tests never serialize it. Round-tripping is
    /// covered separately by [`StaticRefreshFactory`].
    #[derive(Debug)]
    struct SharedRefreshFactory {
        hook: Arc<FakeRefresh>,
    }

    impl SharedRefreshFactory {
        fn ok(props: HashMap<String, String>) -> Arc<Self> {
            Arc::new(Self {
                hook: Arc::new(FakeRefresh {
                    calls: AtomicUsize::new(0),
                    result: Some(props),
                }),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                hook: Arc::new(FakeRefresh {
                    calls: AtomicUsize::new(0),
                    result: None,
                }),
            })
        }
    }

    impl Serialize for SharedRefreshFactory {
        fn serialize<S: Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom(
                "SharedRefreshFactory is a non-serializable test double",
            ))
        }
    }

    impl<'de> Deserialize<'de> for SharedRefreshFactory {
        fn deserialize<D: Deserializer<'de>>(_: D) -> std::result::Result<Self, D::Error> {
            Err(D::Error::custom(
                "SharedRefreshFactory is a non-serializable test double",
            ))
        }
    }

    #[typetag::serde(name = "shared-refresh-test")]
    impl CredentialRefreshFactory for SharedRefreshFactory {
        fn build(&self) -> Result<Arc<dyn CredentialRefresh>> {
            Ok(self.hook.clone())
        }
    }

    /// A fully serializable factory whose hook always returns fixed props. Used to
    /// exercise a genuine serde round-trip of [`RefreshingStorage`].
    #[derive(Debug, Serialize, Deserialize)]
    struct StaticRefreshFactory {
        props: HashMap<String, String>,
    }

    #[derive(Debug)]
    struct StaticRefresh {
        props: HashMap<String, String>,
    }

    #[async_trait]
    impl CredentialRefresh for StaticRefresh {
        async fn refresh(&self, _prefix: &str) -> Result<HashMap<String, String>> {
            Ok(self.props.clone())
        }
    }

    #[typetag::serde(name = "static-refresh-test")]
    impl CredentialRefreshFactory for StaticRefreshFactory {
        fn build(&self) -> Result<Arc<dyn CredentialRefresh>> {
            Ok(Arc::new(StaticRefresh {
                props: self.props.clone(),
            }))
        }
    }

    fn now_ms() -> i64 {
        Utc::now().timestamp_millis()
    }

    /// Build a [`RefreshingStorage`] whose initial credentials expire at
    /// `expires_at_ms`, refreshing via `factory`.
    fn build(
        expires_at_ms: Option<i64>,
        factory: Arc<dyn CredentialRefreshFactory>,
    ) -> RefreshingStorage {
        let storage_factory = Arc::new(MemoryStorageFactory);
        let mut base = HashMap::new();
        if let Some(ms) = expires_at_ms {
            base.insert(SESSION_TOKEN_EXPIRES_AT_MS.to_string(), ms.to_string());
        }
        RefreshingStorage::new(
            "memory://",
            storage_factory,
            StorageConfig::from_props(base),
            factory,
        )
        .unwrap()
    }

    #[test]
    fn within_prefetch_window_treats_missing_expiry_as_fresh() {
        assert!(!within_prefetch_window(None));
    }

    #[test]
    fn within_prefetch_window_true_inside_window_false_outside() {
        // Well beyond the window: fresh.
        assert!(!within_prefetch_window(Some(
            now_ms() + PREFETCH_WINDOW_MS * 10
        )));
        // Inside the prefetch window (expires in 1 min < 5 min window): refresh.
        assert!(within_prefetch_window(Some(now_ms() + 60_000)));
        // Already expired: refresh.
        assert!(within_prefetch_window(Some(now_ms() - 60_000)));
    }

    #[test]
    fn parse_expires_at_ms_reads_the_session_token_key() {
        let mut props = HashMap::new();
        props.insert(
            SESSION_TOKEN_EXPIRES_AT_MS.to_string(),
            "1730000000000".to_string(),
        );
        assert_eq!(parse_expires_at_ms(&props), Some(1730000000000));
        assert_eq!(parse_expires_at_ms(&HashMap::new()), None);
    }

    #[tokio::test]
    async fn fresh_credentials_do_not_trigger_refresh() {
        let factory = SharedRefreshFactory::ok(HashMap::new());
        let hook = factory.hook.clone();
        let storage = build(Some(now_ms() + PREFETCH_WINDOW_MS * 10), factory);

        // A fresh credential is used as-is; the hook is never called.
        storage.exists("memory://a.txt").await.unwrap();
        assert_eq!(hook.calls(), 0);
    }

    #[tokio::test]
    async fn expiring_credentials_trigger_a_single_refresh() {
        // Fresh creds carry an expiry far in the future, so exactly one refresh runs.
        let mut fresh_props = HashMap::new();
        fresh_props.insert(
            SESSION_TOKEN_EXPIRES_AT_MS.to_string(),
            (now_ms() + PREFETCH_WINDOW_MS * 10).to_string(),
        );
        let factory = SharedRefreshFactory::ok(fresh_props);
        let hook = factory.hook.clone();
        let storage = build(Some(now_ms() + 60_000), factory);

        storage.exists("memory://a.txt").await.unwrap();
        storage.exists("memory://b.txt").await.unwrap();
        // First op refreshed; the refreshed creds are fresh, so the second does not.
        assert_eq!(hook.calls(), 1);
    }

    #[tokio::test]
    async fn refresh_failure_propagates_and_does_not_serve_stale() {
        let factory = SharedRefreshFactory::failing();
        let hook = factory.hook.clone();
        let storage = build(Some(now_ms() - 60_000), factory);

        // Refresh-or-fail: an expired credential whose refresh fails errors out.
        let err = storage.exists("memory://a.txt").await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unexpected);
        assert_eq!(hook.calls(), 1);
    }

    #[tokio::test]
    async fn deferred_handle_refreshes_at_io_time() {
        // A handle created via new_output before expiry still refreshes when its
        // async write runs, because it shares the wrapper's state.
        let mut fresh_props = HashMap::new();
        fresh_props.insert(
            SESSION_TOKEN_EXPIRES_AT_MS.to_string(),
            (now_ms() + PREFETCH_WINDOW_MS * 10).to_string(),
        );
        let factory = SharedRefreshFactory::ok(fresh_props);
        let hook = factory.hook.clone();
        let storage = build(Some(now_ms() - 60_000), factory);

        let output = storage.new_output("memory://a.txt").unwrap();
        assert_eq!(hook.calls(), 0, "new_output must not do I/O or refresh");

        output.write("data".into()).await.unwrap();
        assert_eq!(hook.calls(), 1, "write triggers the deferred refresh");
    }

    #[tokio::test]
    async fn round_trips_through_serde_as_a_recipe() {
        // A refreshing storage serializes to its recipe and deserializes back into
        // a working storage: no live state is required to reconstruct it.
        let mut fresh_props = HashMap::new();
        fresh_props.insert(
            SESSION_TOKEN_EXPIRES_AT_MS.to_string(),
            (now_ms() + PREFETCH_WINDOW_MS * 10).to_string(),
        );
        let factory = Arc::new(StaticRefreshFactory { props: fresh_props });
        // Initial creds are already expired, so the rebuilt storage must refresh.
        let storage = build(Some(now_ms() - 60_000), factory);

        let json = serde_json::to_string(&storage).unwrap();
        let restored: RefreshingStorage = serde_json::from_str(&json).unwrap();

        // The reconstructed storage refreshes from its rebuilt hook and works.
        restored
            .write("memory://a.txt", "data".into())
            .await
            .unwrap();
        assert!(restored.exists("memory://a.txt").await.unwrap());
    }
}
