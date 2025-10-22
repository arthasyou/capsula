//! BNF 解析服务
//!
//! 从文本内容中提取结构化的 BNF 语法数据

use std::io;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod simple;

pub use simple::SimpleBnfParser;

/// BNF 解析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnfData {
    /// 语法规则列表
    pub rules: Vec<BnfRule>,
    /// 原始文本（可选）
    pub raw_text: Option<String>,
    /// 元数据
    pub metadata: std::collections::HashMap<String, String>,
}

/// BNF 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BnfRule {
    /// 规则名称（非终结符）
    pub name: String,
    /// 规则定义
    pub definition: String,
    /// 行号（如果可用）
    pub line_number: Option<usize>,
}

impl BnfData {
    /// 创建空的 BNF 数据
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            raw_text: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// 添加规则
    pub fn add_rule(&mut self, rule: BnfRule) {
        self.rules.push(rule);
    }

    /// 设置原始文本
    pub fn set_raw_text(&mut self, text: String) {
        self.raw_text = Some(text);
    }

    /// 添加元数据
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// 转换为 JSON
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// 转换为字节数组
    pub fn to_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }
}

/// BNF 解析器 trait
///
/// 定义统一的 BNF 解析接口
#[async_trait]
pub trait BnfParser: Send + Sync {
    /// 从文本中解析 BNF
    ///
    /// # 参数
    /// - `text`: 输入文本
    ///
    /// # 返回
    /// BNF 解析结果
    async fn parse(&self, text: &str) -> io::Result<BnfData>;

    /// 验证 BNF 语法是否有效
    ///
    /// # 参数
    /// - `text`: 输入文本
    ///
    /// # 返回
    /// 如果语法有效则返回 true
    async fn validate(&self, text: &str) -> io::Result<bool>;
}

/// BNF 解析错误
#[derive(Debug)]
pub enum ParseError {
    /// IO 错误
    Io(io::Error),
    /// 语法错误
    SyntaxError { line: usize, message: String },
    /// 无效规则
    InvalidRule(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "IO error: {}", e),
            ParseError::SyntaxError { line, message } => {
                write!(f, "Syntax error at line {}: {}", line, message)
            }
            ParseError::InvalidRule(msg) => write!(f, "Invalid rule: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<io::Error> for ParseError {
    fn from(error: io::Error) -> Self {
        ParseError::Io(error)
    }
}
