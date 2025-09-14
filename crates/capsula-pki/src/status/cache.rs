//! 状态缓存模块

use std::collections::HashMap;

/// 缓存项
#[derive(Debug, Clone)]
pub struct CacheItem {
    /// 缓存的数据
    pub data: String,
    /// 缓存时间
    pub cached_at: time::OffsetDateTime,
    /// TTL（秒）
    pub ttl_seconds: u64,
}

/// 状态缓存
pub struct StatusCache {
    /// 缓存存储
    cache: HashMap<String, CacheItem>,
}

impl StatusCache {
    /// 创建新的状态缓存
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// 获取缓存项
    pub fn get(&self, key: &str) -> Option<&str> {
        if let Some(item) = self.cache.get(key) {
            let now = time::OffsetDateTime::now_utc();
            let age = (now - item.cached_at).whole_seconds() as u64;
            
            if age < item.ttl_seconds {
                Some(&item.data)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 设置缓存项
    pub fn set(&mut self, key: String, data: String, ttl_seconds: u64) {
        let item = CacheItem {
            data,
            cached_at: time::OffsetDateTime::now_utc(),
            ttl_seconds,
        };
        self.cache.insert(key, item);
    }

    /// 清理过期缓存
    pub fn cleanup_expired(&mut self) {
        let now = time::OffsetDateTime::now_utc();
        self.cache.retain(|_, item| {
            let age = (now - item.cached_at).whole_seconds() as u64;
            age < item.ttl_seconds
        });
    }
}