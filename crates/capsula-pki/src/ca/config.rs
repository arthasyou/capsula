//! CA配置管理
//!
//! 提供CA配置结构和默认值管理

use serde::{Deserialize, Serialize};

/// CA配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// CA名称
    pub name: String,
    /// 国家
    pub country: String,
    /// 省/州
    pub state: String,
    /// 城市
    pub locality: String,
    /// 组织
    pub organization: String,
    /// 组织单位
    pub organizational_unit: Option<String>,
    /// 邮箱
    pub email: Option<String>,
    /// 证书有效期（天）
    pub validity_days: u32,
    /// 默认签发证书有效期（天）
    pub default_cert_validity_days: u32,
    /// 最大证书链深度
    pub max_path_length: Option<u8>,
    /// CA密钥算法
    pub key_algorithm: KeyAlgorithm,
    /// CRL更新间隔（小时）
    pub crl_update_interval_hours: u32,
    /// 下次CRL更新的缓冲时间（小时）
    pub crl_next_update_hours: u32,
}

/// 支持的密钥算法
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// Ed25519 (默认)
    Ed25519,
    /// RSA with specified key size
    RSA { key_size: u32 },
    /// ECDSA with specified curve
    ECDSA { curve: String },
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            name: "Root CA".to_string(),
            country: "CN".to_string(),
            state: "Shanghai".to_string(),
            locality: "Shanghai".to_string(),
            organization: "Data Capsule PKI".to_string(),
            organizational_unit: Some("Certificate Authority".to_string()),
            email: None,
            validity_days: 3650,             // 10年
            default_cert_validity_days: 365, // 1年
            max_path_length: Some(3),        // 允许3级证书链
            key_algorithm: KeyAlgorithm::default(),
            crl_update_interval_hours: 24,   // 每天更新CRL
            crl_next_update_hours: 168,      // CRL有效期1周
        }
    }
}

impl Config {
    /// 创建根CA配置
    pub fn root_ca(name: &str, organization: &str) -> Self {
        Self {
            name: name.to_string(),
            organization: organization.to_string(),
            ..Default::default()
        }
    }

    /// 创建中间CA配置
    pub fn intermediate_ca(name: &str, organization: &str) -> Self {
        Self {
            name: name.to_string(),
            organization: organization.to_string(),
            validity_days: 1825,             // 5年
            default_cert_validity_days: 365, // 1年
            max_path_length: Some(1),        // 中间CA通常只能再创建1级
            ..Default::default()
        }
    }

    /// 创建签发服务器证书的CA配置
    pub fn server_ca(name: &str, organization: &str) -> Self {
        Self {
            name: name.to_string(),
            organization: organization.to_string(),
            validity_days: 730,              // 2年
            default_cert_validity_days: 90,  // 3个月
            max_path_length: Some(0),        // 不能再创建下级CA
            ..Default::default()
        }
    }

    /// 设置地理位置信息
    pub fn with_location(mut self, country: &str, state: &str, locality: &str) -> Self {
        self.country = country.to_string();
        self.state = state.to_string();
        self.locality = locality.to_string();
        self
    }

    /// 设置组织单位
    pub fn with_organizational_unit(mut self, ou: &str) -> Self {
        self.organizational_unit = Some(ou.to_string());
        self
    }

    /// 设置邮箱
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    /// 设置有效期
    pub fn with_validity(mut self, ca_days: u32, cert_days: u32) -> Self {
        self.validity_days = ca_days;
        self.default_cert_validity_days = cert_days;
        self
    }

    /// 设置证书链最大深度
    pub fn with_max_path_length(mut self, length: Option<u8>) -> Self {
        self.max_path_length = length;
        self
    }

    /// 设置密钥算法
    pub fn with_key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = algorithm;
        self
    }

    /// 设置CRL配置
    pub fn with_crl_config(mut self, update_hours: u32, next_update_hours: u32) -> Self {
        self.crl_update_interval_hours = update_hours;
        self.crl_next_update_hours = next_update_hours;
        self
    }

    /// 验证配置有效性
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("CA name cannot be empty".to_string());
        }

        if self.organization.is_empty() {
            return Err("Organization cannot be empty".to_string());
        }

        if self.validity_days == 0 {
            return Err("CA validity days must be greater than 0".to_string());
        }

        if self.default_cert_validity_days == 0 {
            return Err("Default certificate validity days must be greater than 0".to_string());
        }

        if self.validity_days < self.default_cert_validity_days {
            return Err("CA validity must be longer than default certificate validity".to_string());
        }

        if let Some(max_path) = self.max_path_length {
            if max_path > 10 {
                return Err("Maximum path length should not exceed 10".to_string());
            }
        }

        match &self.key_algorithm {
            KeyAlgorithm::RSA { key_size } => {
                if *key_size < 2048 {
                    return Err("RSA key size must be at least 2048 bits".to_string());
                }
                if *key_size > 8192 {
                    return Err("RSA key size should not exceed 8192 bits".to_string());
                }
            }
            KeyAlgorithm::ECDSA { curve } => {
                let valid_curves = ["P-256", "P-384", "P-521"];
                if !valid_curves.contains(&curve.as_str()) {
                    return Err(format!("Unsupported ECDSA curve: {}", curve));
                }
            }
            KeyAlgorithm::Ed25519 => {
                // Ed25519 always valid
            }
        }

        if self.crl_update_interval_hours == 0 {
            return Err("CRL update interval must be greater than 0".to_string());
        }

        if self.crl_next_update_hours <= self.crl_update_interval_hours {
            return Err("CRL next update time must be longer than update interval".to_string());
        }

        Ok(())
    }
}

/// CA配置模板
pub struct ConfigTemplates;

impl ConfigTemplates {
    /// 企业根CA配置
    pub fn enterprise_root() -> Config {
        Config::root_ca("Enterprise Root CA", "Enterprise Corp")
            .with_validity(7300, 365) // 20年CA，1年证书
            .with_max_path_length(Some(5))
    }

    /// 测试根CA配置
    pub fn test_root() -> Config {
        Config::root_ca("Test Root CA", "Test Organization")
            .with_validity(365, 30) // 1年CA，1个月证书
            .with_max_path_length(Some(2))
    }

    /// TLS服务器证书CA配置
    pub fn tls_server() -> Config {
        Config::server_ca("TLS Server CA", "Web Services")
            .with_validity(1095, 90) // 3年CA，3个月证书
            .with_crl_config(12, 168) // 每12小时更新CRL，1周有效期
    }

    /// 代码签名CA配置
    pub fn code_signing() -> Config {
        Config::intermediate_ca("Code Signing CA", "Development Team")
            .with_validity(2190, 1095) // 6年CA，3年证书
            .with_key_algorithm(KeyAlgorithm::RSA { key_size: 4096 })
    }

    /// IoT设备CA配置
    pub fn iot_device() -> Config {
        Config::intermediate_ca("IoT Device CA", "IoT Division")
            .with_validity(1825, 730) // 5年CA，2年证书
            .with_crl_config(168, 336) // 每周更新CRL，2周有效期
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.name, "Root CA");
        assert_eq!(config.organization, "Data Capsule PKI");
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        
        // 测试空名称
        config.name = String::new();
        assert!(config.validate().is_err());
        
        // 测试有效期问题
        config.name = "Test CA".to_string();
        config.validity_days = 30;
        config.default_cert_validity_days = 365;
        assert!(config.validate().is_err());
        
        // 测试RSA密钥大小
        config.validity_days = 365;
        config.default_cert_validity_days = 30;
        config.key_algorithm = KeyAlgorithm::RSA { key_size: 1024 };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_templates() {
        assert!(ConfigTemplates::enterprise_root().validate().is_ok());
        assert!(ConfigTemplates::test_root().validate().is_ok());
        assert!(ConfigTemplates::tls_server().validate().is_ok());
        assert!(ConfigTemplates::code_signing().validate().is_ok());
        assert!(ConfigTemplates::iot_device().validate().is_ok());
    }

    #[test]
    fn test_fluent_builder() {
        let config = Config::root_ca("Custom CA", "Custom Org")
            .with_location("US", "CA", "San Francisco")
            .with_organizational_unit("Security")
            .with_email("ca@example.com")
            .with_validity(1825, 90)
            .with_key_algorithm(KeyAlgorithm::RSA { key_size: 4096 });

        assert!(config.validate().is_ok());
        assert_eq!(config.name, "Custom CA");
        assert_eq!(config.country, "US");
        assert_eq!(config.email, Some("ca@example.com".to_string()));
    }
}