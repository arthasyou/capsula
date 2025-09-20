use serde::{Deserialize, Serialize};

use crate::CapsulaGranted;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub producer: String, // 数据采集者
    pub owner: String,    // 数据拥有者
    #[serde(default)]
    pub grants: Vec<CapsulaGranted>, // 授权向量，如 ["read","use"]
}
