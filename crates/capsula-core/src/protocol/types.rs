use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapsulaStage {
    First,
    Second,
    Third,
    Fourth,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapsulaGranted {
    Read,
    Write,
    Execute,
}
