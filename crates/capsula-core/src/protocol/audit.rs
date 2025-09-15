use serde::{Deserialize, Serialize};

/// 审计事件（结构可按你后续规范扩展）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,     // 时间戳
    pub actor: String,  // 执行者
    pub action: String, // "open" / "grant" / "revoke" 等
    #[serde(default)]
    pub target: Option<String>, // 目标对象（可空）
    pub result: String, // "ok" / "deny" / 错误码
    #[serde(default)]
    pub sig: Option<String>, // 事件签名（可空）
}
