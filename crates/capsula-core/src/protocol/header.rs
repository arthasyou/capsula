use serde::{Deserialize, Serialize};

use crate::CapsulaStage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub id: String,
    pub version: String,
    pub stage: CapsulaStage,
    pub created_at: String,
}
