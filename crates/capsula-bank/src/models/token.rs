use serde::{Deserialize, Serialize};

/// 令牌状态
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenStatus {
    Active,   // 活跃可用
    Expired,  // 已过期
    Revoked,  // 已撤销
    Exhausted, // 使用次数耗尽
}

/// 令牌类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,      // 访问令牌
    Refresh,     // 刷新令牌
    ApiKey,      // API密钥
    SessionToken, // 会话令牌
}

/// 令牌模型
/// 用于存储和验证各种类型的令牌
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// 令牌唯一标识符
    pub token_id: String,
    
    /// 令牌哈希值（不存储明文）
    pub token_hash: String,
    
    /// 令牌类型
    pub token_type: TokenType,
    
    /// 关联的数据胶囊ID
    pub capsule_id: String,
    
    /// 关联的权限授权ID（可以是分子权限ID）
    pub grant_id: String,
    
    /// 令牌持有者ID（用户或设备）
    pub subject_id: String,
    
    /// 令牌颁发者
    pub issuer: String,
    
    /// 绑定的客户端公钥指纹（用于防止令牌被盗用）
    pub bind_pubkey_fpr: Option<String>,
    
    /// 令牌创建时间（Unix时间戳）
    pub created_at: i64,
    
    /// 令牌过期时间（Unix时间戳）
    pub expires_at: i64,
    
    /// 最后使用时间（Unix时间戳）
    pub last_used_at: Option<i64>,
    
    /// 剩余可用次数（None表示无限制）
    pub remaining_uses: Option<i32>,
    
    /// 令牌状态
    pub status: TokenStatus,
    
    /// 额外的元数据（JSON格式）
    pub metadata: Option<serde_json::Value>,
    
    /// 令牌作用域（分子权限ID列表）
    pub scopes: Vec<String>,
}

impl Token {
    /// 创建新的令牌记录
    pub fn new(
        token_id: impl Into<String>,
        token_hash: impl Into<String>,
        token_type: TokenType,
        capsule_id: impl Into<String>,
        grant_id: impl Into<String>,
        subject_id: impl Into<String>,
        issuer: impl Into<String>,
        expires_at: i64,
    ) -> Self {
        Self {
            token_id: token_id.into(),
            token_hash: token_hash.into(),
            token_type,
            capsule_id: capsule_id.into(),
            grant_id: grant_id.into(),
            subject_id: subject_id.into(),
            issuer: issuer.into(),
            bind_pubkey_fpr: None,
            created_at: chrono::Utc::now().timestamp(),
            expires_at,
            last_used_at: None,
            remaining_uses: None,
            status: TokenStatus::Active,
            metadata: None,
            scopes: Vec::new(),
        }
    }
    
    /// 设置绑定的公钥指纹
    pub fn with_pubkey_binding(mut self, pubkey_fpr: impl Into<String>) -> Self {
        self.bind_pubkey_fpr = Some(pubkey_fpr.into());
        self
    }
    
    /// 设置使用次数限制
    pub fn with_use_limit(mut self, uses: i32) -> Self {
        self.remaining_uses = Some(uses);
        self
    }
    
    /// 添加作用域（分子权限ID）
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }
    
    /// 检查令牌是否已过期
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() > self.expires_at
    }
    
    /// 检查令牌是否可用
    pub fn is_valid(&self) -> bool {
        matches!(self.status, TokenStatus::Active) 
            && !self.is_expired()
            && self.remaining_uses.map_or(true, |uses| uses > 0)
    }
    
    /// 使用令牌（减少剩余次数）
    pub fn use_token(&mut self) -> bool {
        if !self.is_valid() {
            return false;
        }
        
        self.last_used_at = Some(chrono::Utc::now().timestamp());
        
        if let Some(uses) = self.remaining_uses.as_mut() {
            if *uses > 0 {
                *uses -= 1;
                if *uses == 0 {
                    self.status = TokenStatus::Exhausted;
                }
                true
            } else {
                false
            }
        } else {
            true
        }
    }
    
    /// 撤销令牌
    pub fn revoke(&mut self) {
        self.status = TokenStatus::Revoked;
    }
}