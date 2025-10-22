//! 简单 BNF 解析器实现
//!
//! 支持基本的 BNF 语法解析

use std::io;

use async_trait::async_trait;

use super::{BnfData, BnfParser, BnfRule};

/// 简单 BNF 解析器
///
/// 支持基本的 BNF 语法：
/// - `<rule> ::= definition`
/// - `<rule> = definition`
/// - 注释：以 `//` 或 `#` 开头的行
#[derive(Debug, Clone, Default)]
pub struct SimpleBnfParser {
    /// 是否保存原始文本
    keep_raw_text: bool,
}

impl SimpleBnfParser {
    /// 创建新的简单 BNF 解析器
    pub fn new() -> Self {
        Self {
            keep_raw_text: true,
        }
    }

    /// 设置是否保存原始文本
    pub fn with_raw_text(mut self, keep: bool) -> Self {
        self.keep_raw_text = keep;
        self
    }

    /// 解析单行 BNF 规则
    ///
    /// # 参数
    /// - `line`: 输入行
    /// - `line_number`: 行号
    ///
    /// # 返回
    /// 解析的规则（如果有效）
    fn parse_line(&self, line: &str, line_number: usize) -> Option<BnfRule> {
        let line = line.trim();

        // 跳过空行和注释
        if line.is_empty() || line.starts_with("//") || line.starts_with("#") {
            return None;
        }

        // 查找分隔符 ::= 或 =
        let separator = if line.contains("::=") {
            "::="
        } else if line.contains("=") {
            "="
        } else {
            return None;
        };

        // 分割规则名和定义
        let parts: Vec<&str> = line.splitn(2, separator).collect();
        if parts.len() != 2 {
            return None;
        }

        let name = parts[0].trim();
        let definition = parts[1].trim();

        // 提取规则名（去除尖括号）
        let name = if name.starts_with('<') && name.ends_with('>') {
            &name[1 .. name.len() - 1]
        } else {
            name
        };

        if name.is_empty() || definition.is_empty() {
            return None;
        }

        Some(BnfRule {
            name: name.to_string(),
            definition: definition.to_string(),
            line_number: Some(line_number),
        })
    }

    /// 提取元数据
    ///
    /// # 参数
    /// - `text`: 输入文本
    ///
    /// # 返回
    /// 元数据映射
    fn extract_metadata(&self, text: &str) -> std::collections::HashMap<String, String> {
        let mut metadata = std::collections::HashMap::new();

        // 统计规则数量
        let rule_count = text
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty()
                    && !line.starts_with("//")
                    && !line.starts_with("#")
                    && (line.contains("::=") || line.contains("="))
            })
            .count();

        metadata.insert("rule_count".to_string(), rule_count.to_string());
        metadata.insert("line_count".to_string(), text.lines().count().to_string());

        metadata
    }
}

#[async_trait]
impl BnfParser for SimpleBnfParser {
    async fn parse(&self, text: &str) -> io::Result<BnfData> {
        let mut data = BnfData::empty();

        // 解析每一行
        for (line_number, line) in text.lines().enumerate() {
            if let Some(rule) = self.parse_line(line, line_number + 1) {
                data.add_rule(rule);
            }
        }

        // 保存原始文本
        if self.keep_raw_text {
            data.set_raw_text(text.to_string());
        }

        // 提取元数据
        let metadata = self.extract_metadata(text);
        for (key, value) in metadata {
            data.add_metadata(key, value);
        }

        Ok(data)
    }

    async fn validate(&self, text: &str) -> io::Result<bool> {
        // 尝试解析
        let data = self.parse(text).await?;

        // 如果至少有一条规则，则认为有效
        Ok(!data.rules.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_simple_bnf() {
        let input = r#"
            <expr> ::= <term> + <expr> | <term>
            <term> ::= <factor> * <term> | <factor>
            <factor> ::= ( <expr> ) | <number>
        "#;

        let parser = SimpleBnfParser::new();
        let result = parser.parse(input).await.unwrap();

        assert_eq!(result.rules.len(), 3);
        assert_eq!(result.rules[0].name, "expr");
        assert_eq!(result.rules[1].name, "term");
        assert_eq!(result.rules[2].name, "factor");
    }

    #[tokio::test]
    async fn test_parse_with_equals() {
        let input = r#"
            expr = term + expr | term
            term = factor * term | factor
        "#;

        let parser = SimpleBnfParser::new();
        let result = parser.parse(input).await.unwrap();

        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.rules[0].name, "expr");
        assert_eq!(result.rules[1].name, "term");
    }

    #[tokio::test]
    async fn test_parse_with_comments() {
        let input = r#"
            // This is a comment
            <expr> ::= <term> + <expr>
            # Another comment
            <term> ::= <factor> * <term>
        "#;

        let parser = SimpleBnfParser::new();
        let result = parser.parse(input).await.unwrap();

        assert_eq!(result.rules.len(), 2);
    }

    #[tokio::test]
    async fn test_parse_empty_input() {
        let input = "";

        let parser = SimpleBnfParser::new();
        let result = parser.parse(input).await.unwrap();

        assert_eq!(result.rules.len(), 0);
    }

    #[tokio::test]
    async fn test_validate() {
        let valid_input = "<expr> ::= <term> + <expr>";
        let invalid_input = "// Just a comment";

        let parser = SimpleBnfParser::new();

        assert!(parser.validate(valid_input).await.unwrap());
        assert!(!parser.validate(invalid_input).await.unwrap());
    }

    #[tokio::test]
    async fn test_metadata() {
        let input = r#"
            <expr> ::= <term> + <expr>
            <term> ::= <factor> * <term>
            <factor> ::= ( <expr> )
        "#;

        let parser = SimpleBnfParser::new();
        let result = parser.parse(input).await.unwrap();

        assert_eq!(result.metadata.get("rule_count").unwrap(), "3");
    }

    #[tokio::test]
    async fn test_raw_text_preservation() {
        let input = "<expr> ::= <term>";

        let parser = SimpleBnfParser::new().with_raw_text(true);
        let result = parser.parse(input).await.unwrap();

        assert!(result.raw_text.is_some());
        assert_eq!(result.raw_text.unwrap(), input);
    }

    #[tokio::test]
    async fn test_to_json() {
        let input = "<expr> ::= <term>";

        let parser = SimpleBnfParser::new();
        let result = parser.parse(input).await.unwrap();
        let json = result.to_json().unwrap();

        assert!(json.contains("expr"));
        assert!(json.contains("term"));
    }
}
