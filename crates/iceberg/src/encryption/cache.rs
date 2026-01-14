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

//! Key caching with time-to-live (TTL) support

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

use crate::encryption::crypto::SecureKey;
use crate::Result;

/// Entry in the key cache
#[derive(Clone, Debug)]
struct CacheEntry {
    /// The cached key
    key: SecureKey,
    /// When the entry expires
    expires_at: DateTime<Utc>,
    /// Number of times this entry has been accessed
    access_count: u64,
}

impl CacheEntry {
    /// Create a new cache entry with the given TTL in seconds
    fn new(key: SecureKey, ttl_seconds: i64) -> Self {
        Self {
            key,
            expires_at: Utc::now() + Duration::seconds(ttl_seconds),
            access_count: 0,
        }
    }

    /// Check if the entry has expired
    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Cache for encryption keys with TTL support
#[derive(Clone, Debug)]
pub struct KeyCache {
    /// The cache storage
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Default TTL in seconds (1 hour)
    default_ttl_seconds: i64,
    /// Maximum number of entries in the cache
    max_entries: usize,
}

impl KeyCache {
    /// Create a new key cache with default settings (1 hour TTL, 1000 max entries)
    pub fn new() -> Self {
        Self::with_config(3600, 1000)
    }

    /// Create a new key cache with custom configuration
    pub fn with_config(default_ttl_seconds: i64, max_entries: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl_seconds,
            max_entries,
        }
    }

    /// Store a key in the cache
    pub async fn put(&self, key_id: String, key: SecureKey) -> Result<()> {
        self.put_with_ttl(key_id, key, self.default_ttl_seconds)
            .await
    }

    /// Store a key in the cache with custom TTL
    pub async fn put_with_ttl(
        &self,
        key_id: String,
        key: SecureKey,
        ttl_seconds: i64,
    ) -> Result<()> {
        let mut cache = self.cache.write().await;

        // Check if we need to evict entries
        if cache.len() >= self.max_entries {
            self.evict_expired_or_lru(&mut cache);
        }

        // Add the new entry
        cache.insert(key_id, CacheEntry::new(key, ttl_seconds));

        Ok(())
    }

    /// Get a key from the cache
    pub async fn get(&self, key_id: &str) -> Option<SecureKey> {
        let mut cache = self.cache.write().await;

        if let Some(entry) = cache.get_mut(key_id) {
            if entry.is_expired() {
                // Remove expired entry
                cache.remove(key_id);
                return None;
            }

            // Update access count
            entry.access_count += 1;

            Some(entry.key.clone())
        } else {
            None
        }
    }

    /// Remove a key from the cache
    pub async fn remove(&self, key_id: &str) -> Option<SecureKey> {
        let mut cache = self.cache.write().await;
        cache.remove(key_id).map(|entry| entry.key)
    }

    /// Clear all entries from the cache
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get the number of entries in the cache
    pub async fn size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }

    /// Remove all expired entries from the cache
    pub async fn evict_expired(&self) -> usize {
        let mut cache = self.cache.write().await;
        let initial_size = cache.len();

        cache.retain(|_, entry| !entry.is_expired());

        initial_size - cache.len()
    }

    /// Evict expired entries or the least recently used entry if no expired entries
    fn evict_expired_or_lru(&self, cache: &mut HashMap<String, CacheEntry>) {
        // First try to remove expired entries
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        if !expired_keys.is_empty() {
            for key in expired_keys {
                cache.remove(&key);
            }
            return;
        }

        // If no expired entries, remove the least recently used
        if let Some(lru_key) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.access_count)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&lru_key);
        }
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;

        let total_entries = cache.len();
        let expired_entries = cache.values().filter(|entry| entry.is_expired()).count();
        let total_accesses: u64 = cache.values().map(|entry| entry.access_count).sum();

        CacheStats {
            total_entries,
            expired_entries,
            total_accesses,
            hit_rate: 0.0, // Would need to track hits/misses for accurate rate
        }
    }
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of entries in the cache
    pub total_entries: usize,
    /// Number of expired entries still in cache
    pub expired_entries: usize,
    /// Total number of cache accesses
    pub total_accesses: u64,
    /// Cache hit rate (if tracked)
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::crypto::{EncryptionAlgorithm, SecureKey};

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let cache = KeyCache::with_config(60, 10);

        let key = SecureKey::generate(EncryptionAlgorithm::Aes256Gcm);
        let key_id = "test-key-1";

        // Put key in cache
        cache.put(key_id.to_string(), key.clone()).await.unwrap();

        // Get key from cache
        let retrieved = cache.get(key_id).await;
        assert!(retrieved.is_some());

        // Remove key from cache
        let removed = cache.remove(key_id).await;
        assert!(removed.is_some());

        // Key should no longer be in cache
        let retrieved_after_remove = cache.get(key_id).await;
        assert!(retrieved_after_remove.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = KeyCache::with_config(1, 10); // 1 second TTL

        let key = SecureKey::generate(EncryptionAlgorithm::Aes128Gcm);
        let key_id = "expiring-key";

        // Put key with very short TTL
        cache
            .put_with_ttl(key_id.to_string(), key.clone(), 0)
            .await
            .unwrap();

        // Key should be expired immediately
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let retrieved = cache.get(key_id).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cache_max_entries() {
        let cache = KeyCache::with_config(3600, 3); // Max 3 entries

        // Add 4 keys
        for i in 0..4 {
            let key = SecureKey::generate(EncryptionAlgorithm::Aes256Gcm);
            cache.put(format!("key-{}", i), key).await.unwrap();
        }

        // Cache should have at most 3 entries
        assert!(cache.size().await <= 3);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = KeyCache::new();

        // Add multiple keys
        for i in 0..5 {
            let key = SecureKey::generate(EncryptionAlgorithm::Aes256Gcm);
            cache.put(format!("key-{}", i), key).await.unwrap();
        }

        assert_eq!(cache.size().await, 5);

        // Clear cache
        cache.clear().await;
        assert_eq!(cache.size().await, 0);
    }

    #[tokio::test]
    async fn test_evict_expired() {
        let cache = KeyCache::with_config(1, 10);

        // Add keys with different TTLs
        let key1 = SecureKey::generate(EncryptionAlgorithm::Aes256Gcm);
        let key2 = SecureKey::generate(EncryptionAlgorithm::Aes256Gcm);

        cache
            .put_with_ttl("short-ttl".to_string(), key1, 0)
            .await
            .unwrap();
        cache
            .put_with_ttl("long-ttl".to_string(), key2, 3600)
            .await
            .unwrap();

        // Wait a bit for first key to expire
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Evict expired entries
        let evicted = cache.evict_expired().await;
        assert_eq!(evicted, 1);
        assert_eq!(cache.size().await, 1);
    }
}

