use crate::{
    db::get_db,
    error::{AppError, Result},
    models::token::Token,
};

/// 创建令牌表
/// 存储各种类型的认证/授权令牌，包含完整的验证上下文
pub async fn create_token_table() -> Result<()> {
    let query = r#"
        -- ---------------------
        -- 令牌表定义
        -- ---------------------
        DEFINE TABLE IF NOT EXISTS tokens SCHEMAFULL;
        
        -- 字段定义
        DEFINE FIELD IF NOT EXISTS token_id         ON TABLE tokens TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS token_hash       ON TABLE tokens TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS token_type       ON TABLE tokens TYPE string 
            ASSERT $value IN ['access', 'refresh', 'api_key', 'session_token'];
        DEFINE FIELD IF NOT EXISTS capsule_id       ON TABLE tokens TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS grant_id         ON TABLE tokens TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS subject_id       ON TABLE tokens TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS issuer           ON TABLE tokens TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS bind_pubkey_fpr  ON TABLE tokens TYPE option<string>;
        DEFINE FIELD IF NOT EXISTS created_at       ON TABLE tokens TYPE int DEFAULT time::unix();
        DEFINE FIELD IF NOT EXISTS expires_at       ON TABLE tokens TYPE int ASSERT $value > time::unix();
        DEFINE FIELD IF NOT EXISTS last_used_at     ON TABLE tokens TYPE option<int>;
        DEFINE FIELD IF NOT EXISTS remaining_uses   ON TABLE tokens TYPE option<int>;
        DEFINE FIELD IF NOT EXISTS status           ON TABLE tokens TYPE string 
            ASSERT $value IN ['active', 'expired', 'revoked', 'exhausted'] DEFAULT 'active';
        DEFINE FIELD IF NOT EXISTS metadata         ON TABLE tokens TYPE option<object>;
        DEFINE FIELD IF NOT EXISTS scopes           ON TABLE tokens TYPE array<string> DEFAULT [];
        
        -- ---------------------
        -- 索引定义
        -- ---------------------
        DEFINE INDEX IF NOT EXISTS token_id_idx         ON TABLE tokens COLUMNS token_id UNIQUE;
        DEFINE INDEX IF NOT EXISTS token_hash_idx       ON TABLE tokens COLUMNS token_hash UNIQUE;
        DEFINE INDEX IF NOT EXISTS capsule_id_idx       ON TABLE tokens COLUMNS capsule_id;
        DEFINE INDEX IF NOT EXISTS subject_id_idx       ON TABLE tokens COLUMNS subject_id;
        DEFINE INDEX IF NOT EXISTS grant_id_idx         ON TABLE tokens COLUMNS grant_id;
        DEFINE INDEX IF NOT EXISTS expires_at_idx       ON TABLE tokens COLUMNS expires_at;
        DEFINE INDEX IF NOT EXISTS status_idx           ON TABLE tokens COLUMNS status;
        DEFINE INDEX IF NOT EXISTS token_type_idx       ON TABLE tokens COLUMNS token_type;
        
        -- 复合索引：用于查询特定用户的有效令牌
        DEFINE INDEX IF NOT EXISTS subject_status_idx   ON TABLE tokens COLUMNS subject_id, status;
        DEFINE INDEX IF NOT EXISTS grant_status_idx     ON TABLE tokens COLUMNS grant_id, status;
        DEFINE INDEX IF NOT EXISTS capsule_status_idx  ON TABLE tokens COLUMNS capsule_id, status;
        DEFINE INDEX IF NOT EXISTS subject_capsule_idx ON TABLE tokens COLUMNS subject_id, capsule_id;
    "#;

    let db = get_db();
    db.query(query).await?;
    Ok(())
}

/// 创建新令牌
pub async fn create_token(token: Token) -> Result<Token> {
    let db = get_db();
    let token_id = token.token_id.clone();
    let created: Option<Token> = db
        .create(("tokens", token_id))
        .content(token)
        .await?;
    
    created.ok_or_else(|| AppError::Internal("Failed to create token".into()))
}

/// 根据令牌ID查询
pub async fn get_token_by_id(token_id: &str) -> Result<Option<Token>> {
    let db = get_db();
    let token: Option<Token> = db.select(("tokens", token_id)).await?;
    Ok(token)
}

/// 根据令牌哈希查询
pub async fn get_token_by_hash(token_hash: &str) -> Result<Option<Token>> {
    let db = get_db();
    let query = "SELECT * FROM tokens WHERE token_hash = $token_hash AND status = 'active'";
    let mut response = db
        .query(query)
        .bind(("token_hash", token_hash.to_string()))
        .await?;
    let tokens: Vec<Token> = response.take(0)?;
    Ok(tokens.into_iter().next())
}

/// 查询用户的所有活跃令牌
pub async fn get_active_tokens_by_subject(subject_id: &str) -> Result<Vec<Token>> {
    let db = get_db();
    let query = "SELECT * FROM tokens WHERE subject_id = $subject_id AND status = 'active' AND expires_at > time::unix()";
    let mut response = db
        .query(query)
        .bind(("subject_id", subject_id.to_string()))
        .await?;
    let tokens: Vec<Token> = response.take(0)?;
    Ok(tokens)
}

/// 查询特定授权的所有令牌
pub async fn get_tokens_by_grant(grant_id: &str) -> Result<Vec<Token>> {
    let db = get_db();
    let query = "SELECT * FROM tokens WHERE grant_id = $grant_id";
    let mut response = db
        .query(query)
        .bind(("grant_id", grant_id.to_string()))
        .await?;
    let tokens: Vec<Token> = response.take(0)?;
    Ok(tokens)
}

/// 查询特定胶囊的所有令牌
pub async fn get_tokens_by_capsule(capsule_id: &str) -> Result<Vec<Token>> {
    let db = get_db();
    let query = "SELECT * FROM tokens WHERE capsule_id = $capsule_id";
    let mut response = db
        .query(query)
        .bind(("capsule_id", capsule_id.to_string()))
        .await?;
    let tokens: Vec<Token> = response.take(0)?;
    Ok(tokens)
}

/// 查询用户对特定胶囊的令牌
pub async fn get_token_for_capsule_access(subject_id: &str, capsule_id: &str) -> Result<Option<Token>> {
    let db = get_db();
    let query = "SELECT * FROM tokens WHERE subject_id = $subject_id AND capsule_id = $capsule_id AND status = 'active' AND expires_at > time::unix()";
    let mut response = db
        .query(query)
        .bind(("subject_id", subject_id.to_string()))
        .bind(("capsule_id", capsule_id.to_string()))
        .await?;
    let tokens: Vec<Token> = response.take(0)?;
    Ok(tokens.into_iter().next())
}

/// 更新令牌（使用后更新）
pub async fn update_token(token: &Token) -> Result<Token> {
    let db = get_db();
    let updated: Option<Token> = db
        .update(("tokens", token.token_id.clone()))
        .content(token.clone())
        .await?;
    
    updated.ok_or_else(|| AppError::Internal("Failed to update token".into()))
}

/// 使用令牌（减少使用次数并更新最后使用时间）
pub async fn use_token(token_id: &str) -> Result<bool> {
    // 获取令牌
    let mut token = match get_token_by_id(token_id).await? {
        Some(t) => t,
        None => return Ok(false),
    };
    
    // 使用令牌
    if !token.use_token() {
        return Ok(false);
    }
    
    // 更新数据库
    update_token(&token).await?;
    Ok(true)
}

/// 撤销令牌
pub async fn revoke_token(token_id: &str) -> Result<()> {
    let db = get_db();
    let query = "UPDATE tokens SET status = 'revoked' WHERE token_id = $token_id";
    db.query(query)
        .bind(("token_id", token_id.to_string()))
        .await?;
    Ok(())
}

/// 撤销用户的所有令牌
pub async fn revoke_all_tokens_for_subject(subject_id: &str) -> Result<()> {
    let db = get_db();
    let query = "UPDATE tokens SET status = 'revoked' WHERE subject_id = $subject_id";
    db.query(query)
        .bind(("subject_id", subject_id.to_string()))
        .await?;
    Ok(())
}

/// 撤销特定授权的所有令牌
pub async fn revoke_all_tokens_for_grant(grant_id: &str) -> Result<()> {
    let db = get_db();
    let query = "UPDATE tokens SET status = 'revoked' WHERE grant_id = $grant_id";
    db.query(query)
        .bind(("grant_id", grant_id.to_string()))
        .await?;
    Ok(())
}

/// 撤销特定胶囊的所有令牌
pub async fn revoke_all_tokens_for_capsule(capsule_id: &str) -> Result<()> {
    let db = get_db();
    let query = "UPDATE tokens SET status = 'revoked' WHERE capsule_id = $capsule_id";
    db.query(query)
        .bind(("capsule_id", capsule_id.to_string()))
        .await?;
    Ok(())
}

/// 清理过期令牌
pub async fn cleanup_expired_tokens() -> Result<u64> {
    let db = get_db();
    let query = "DELETE tokens WHERE expires_at < time::unix() OR status IN ['expired', 'exhausted']";
    let _response = db.query(query).await?;
    
    // 返回删除的记录数
    Ok(0) // SurrealDB doesn't easily return affected rows, would need custom implementation
}

/// 验证令牌的完整性
/// 包括：哈希匹配、过期检查、状态检查、公钥指纹检查等
pub async fn validate_token(
    token_hash: &str,
    client_pubkey_fpr: Option<&str>,
) -> Result<Option<Token>> {
    // 1. 根据哈希获取令牌
    let token = match get_token_by_hash(token_hash).await? {
        Some(t) => t,
        None => return Ok(None),
    };
    
    // 2. 检查令牌是否有效
    if !token.is_valid() {
        return Ok(None);
    }
    
    // 3. 检查公钥指纹绑定
    if let Some(expected_fpr) = &token.bind_pubkey_fpr {
        if let Some(actual_fpr) = client_pubkey_fpr {
            if expected_fpr != actual_fpr {
                return Ok(None);
            }
        } else {
            // 如果令牌绑定了公钥但客户端没有提供，拒绝
            return Ok(None);
        }
    }
    
    Ok(Some(token))
}