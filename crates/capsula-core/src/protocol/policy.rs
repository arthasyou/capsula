use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub x509_req: Option<X509Req>, // 证书/属性要求（可选）
    #[serde(default)]
    pub rego: Option<String>, // OPA Rego 策略（可选）
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509Req {
    #[serde(default)]
    pub eku: Vec<String>, // 扩展密钥用法 OID 列表
}
