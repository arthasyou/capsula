//! 状态缓存模块

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::StatusResponse;

/// 缓存项
#[derive(Debug, Clone)]
pub struct CacheItem {
    /// 缓存的响应数据
    pub response: StatusResponse,
    /// 缓存时间
    pub cached_at: OffsetDateTime,
    /// TTL（秒）
    pub ttl_seconds: u64,
}

/// 缓存统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// 总缓存项数量
    pub total_items: usize,
    /// 缓存命中次数
    pub hit_count: u64,
    /// 缓存未命中次数
    pub miss_count: u64,
    /// 缓存命中率
    pub hit_rate: f64,
}

/// 状态缓存
pub struct StatusCache {
    /// 缓存存储
    cache: HashMap<String, CacheItem>,
    /// 默认TTL（秒）
    default_ttl_seconds: u64,
    /// 统计信息
    stats: CacheStats,
}

impl StatusCache {
    /// 创建新的状态缓存
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            default_ttl_seconds: 3600, // 1小时
            stats: CacheStats {
                total_items: 0,
                hit_count: 0,
                miss_count: 0,
                hit_rate: 0.0,
            },
        }
    }

    /// 创建带自定义TTL的状态缓存
    pub fn with_ttl(default_ttl_seconds: u64) -> Self {
        Self {
            cache: HashMap::new(),
            default_ttl_seconds,
            stats: CacheStats {
                total_items: 0,
                hit_count: 0,
                miss_count: 0,
                hit_rate: 0.0,
            },
        }
    }

    /// 获取缓存的状态响应
    pub fn get(&mut self, key: &str) -> Option<StatusResponse> {
        let result = if let Some(item) = self.cache.get(key) {
            let now = OffsetDateTime::now_utc();
            let age = (now - item.cached_at).whole_seconds() as u64;
            
            if age < item.ttl_seconds {
                Some((true, item.response.clone()))
            } else {
                // 过期项会在cleanup时清理
                Some((false, item.response.clone()))
            }
        } else {
            None
        };
        
        match result {
            Some((true, response)) => {
                self.stats.hit_count += 1;
                self.update_hit_rate();
                Some(response)
            },
            Some((false, _)) => {
                self.stats.miss_count += 1;
                self.update_hit_rate();
                None
            },
            None => {
                self.stats.miss_count += 1;
                self.update_hit_rate();
                None
            }
        }
    }

    /// 缓存状态响应
    pub fn put(&mut self, response: StatusResponse) {
        self.put_with_ttl(response, self.default_ttl_seconds);
    }

    /// 使用指定TTL缓存状态响应
    pub fn put_with_ttl(&mut self, response: StatusResponse, ttl_seconds: u64) {
        let key = response.serial_number.clone();
        let item = CacheItem {
            response,
            cached_at: OffsetDateTime::now_utc(),
            ttl_seconds,
        };
        
        let is_new = !self.cache.contains_key(&key);
        self.cache.insert(key, item);
        
        if is_new {
            self.stats.total_items += 1;
        }
    }

    /// 清理过期缓存
    pub fn cleanup_expired(&mut self) {
        let now = OffsetDateTime::now_utc();
        let initial_count = self.cache.len();
        
        self.cache.retain(|_, item| {
            let age = (now - item.cached_at).whole_seconds() as u64;
            age < item.ttl_seconds
        });
        
        let removed_count = initial_count - self.cache.len();
        if removed_count > 0 {
            self.stats.total_items = self.cache.len();
        }
    }

    /// 获取缓存统计信息
    pub fn get_stats(&self) -> CacheStats {
        self.stats.clone()
    }

    /// 清空缓存
    pub fn clear(&mut self) {
        self.cache.clear();
        self.stats.total_items = 0;
    }

    /// 更新命中率
    fn update_hit_rate(&mut self) {
        let total_queries = self.stats.hit_count + self.stats.miss_count;
        if total_queries > 0 {
            self.stats.hit_rate = self.stats.hit_count as f64 / total_queries as f64;
        }
    }
}