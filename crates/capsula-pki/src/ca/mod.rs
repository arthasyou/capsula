//! CA (Certificate Authority) 模块
//!
//! 提供完整的证书颁发机构功能，包括：
//! - CA创建和管理 (根CA、中间CA)
//! - 证书签发流程
//! - 证书链构建和验证
//! - CA配置管理

pub mod authority;
pub mod chain;
pub mod config;
pub mod manager;

// 重新导出主要类型
pub use authority::{Authority, CAType};
pub use chain::{Chain, ChainBuilder, ValidationIssue, ValidationResult as ChainValidationResult};
// 向后兼容的类型别名
pub use config::Config as CAConfig;
pub use config::{Config, ConfigTemplates, KeyAlgorithm};
pub use manager::{
    CAInfo, IssuanceRequest, IssuanceResult, Manager, Manager as CAManager, ManagerStatistics,
};

/// CA模块的Result类型
pub type Result<T> = crate::error::Result<T>;

/// CA工厂 - 便捷的CA创建接口
pub struct CAFactory;

impl CAFactory {
    /// 快速创建测试环境的CA管理器
    pub fn create_test_environment() -> Result<Manager> {
        let mut manager = Manager::new();

        // 创建测试根CA
        let root_config = ConfigTemplates::test_root();
        manager.create_root_ca("test-root-ca".to_string(), root_config)?;

        // 创建TLS服务器中间CA
        let tls_config = ConfigTemplates::tls_server();
        manager.create_intermediate_ca("test-root-ca", "tls-server-ca".to_string(), tls_config)?;

        Ok(manager)
    }

    /// 创建企业级CA环境
    pub fn create_enterprise_environment(organization: &str) -> Result<Manager> {
        let mut manager = Manager::new();

        // 创建企业根CA
        let root_config = Config::root_ca("Enterprise Root CA", organization)
            .with_validity(7300, 365) // 20年CA，1年证书
            .with_max_path_length(Some(5));

        manager.create_root_ca("enterprise-root-ca".to_string(), root_config)?;

        // 创建各种用途的中间CA
        let tls_config = ConfigTemplates::tls_server().with_location("US", "CA", "San Francisco");
        manager.create_intermediate_ca(
            "enterprise-root-ca",
            "tls-server-ca".to_string(),
            tls_config,
        )?;

        let code_signing_config = ConfigTemplates::code_signing();
        manager.create_intermediate_ca(
            "enterprise-root-ca",
            "code-signing-ca".to_string(),
            code_signing_config,
        )?;

        Ok(manager)
    }

    /// 创建单一根CA实例
    pub fn create_simple_root_ca(name: &str, organization: &str) -> Result<Authority> {
        let config = Config::root_ca(name, organization);
        Authority::new_root(config)
    }

    /// 从配置模板创建CA
    pub fn create_from_template(template_name: &str) -> Result<Authority> {
        let config = match template_name {
            "enterprise_root" => ConfigTemplates::enterprise_root(),
            "test_root" => ConfigTemplates::test_root(),
            "tls_server" => ConfigTemplates::tls_server(),
            "code_signing" => ConfigTemplates::code_signing(),
            "iot_device" => ConfigTemplates::iot_device(),
            _ => {
                return Err(crate::error::PkiError::CAError(format!(
                    "Unknown template: {}",
                    template_name
                )))
            }
        };

        Authority::new_root(config)
    }
}

/// CA模块统一错误处理
pub mod error {
    pub use crate::error::{PkiError as CAError, Result as CAResult};
}

/// CA模块工具函数
pub mod utils {
    use super::*;

    /// 验证CA配置的兼容性
    pub fn validate_ca_hierarchy(parent_config: &Config, child_config: &Config) -> Result<()> {
        // 检查有效期
        if child_config.validity_days >= parent_config.validity_days {
            return Err(crate::error::PkiError::CAError(
                "Child CA validity period must be shorter than parent CA".to_string(),
            ));
        }

        // 检查证书链长度限制
        if let (Some(parent_max), Some(child_max)) =
            (parent_config.max_path_length, child_config.max_path_length)
        {
            if child_max >= parent_max {
                return Err(crate::error::PkiError::CAError(
                    "Child CA max path length must be less than parent CA".to_string(),
                ));
            }
        }

        // 检查组织信息一致性
        if parent_config.organization != child_config.organization {
            // 这是警告，不是错误，但可以记录
        }

        Ok(())
    }

    /// 计算CA的推荐有效期
    pub fn calculate_recommended_validity(ca_level: u8) -> u32 {
        match ca_level {
            0 => 7300, // 根CA: 20年
            1 => 3650, // 一级中间CA: 10年
            2 => 1825, // 二级中间CA: 5年
            3 => 730,  // 三级中间CA: 2年
            _ => 365,  // 更深层级: 1年
        }
    }

    /// 检查CA名称冲突
    pub fn check_ca_name_conflicts(manager: &Manager, proposed_name: &str) -> bool {
        manager.list_cas().iter().any(|ca| ca.name == proposed_name)
    }
}

/// CA批量操作支持
pub mod batch {
    use std::collections::HashMap;

    use super::*;

    /// 批量CA创建配置
    pub struct BatchCAConfig {
        pub ca_configs: Vec<(String, Config)>,
        pub parent_child_relationships: Vec<(String, String)>, // (parent_id, child_id)
    }

    /// 批量创建CA层次结构
    pub fn create_ca_hierarchy(batch_config: BatchCAConfig) -> Result<Manager> {
        let mut manager = Manager::new();
        let mut created_cas = HashMap::new();

        // 首先创建所有根CA
        for (ca_id, config) in &batch_config.ca_configs {
            if !batch_config
                .parent_child_relationships
                .iter()
                .any(|(_, child)| child == ca_id)
            {
                // 这是根CA
                manager.create_root_ca(ca_id.clone(), config.clone())?;
                created_cas.insert(ca_id.clone(), true);
            }
        }

        // 然后按层级创建中间CA
        let mut remaining_relationships = batch_config.parent_child_relationships;
        while !remaining_relationships.is_empty() {
            let mut progress_made = false;

            remaining_relationships.retain(|(parent_id, child_id)| {
                if created_cas.contains_key(parent_id) {
                    // 找到子CA的配置
                    if let Some((_, config)) = batch_config
                        .ca_configs
                        .iter()
                        .find(|(id, _)| id == child_id)
                    {
                        if manager
                            .create_intermediate_ca(parent_id, child_id.clone(), config.clone())
                            .is_ok()
                        {
                            created_cas.insert(child_id.clone(), true);
                            progress_made = true;
                            return false; // 移除这个关系
                        }
                    }
                }
                true // 保留这个关系
            });

            if !progress_made && !remaining_relationships.is_empty() {
                return Err(crate::error::PkiError::CAError(
                    "Cannot create CA hierarchy: circular dependencies or missing parents"
                        .to_string(),
                ));
            }
        }

        Ok(manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_factory_test_environment() {
        let result = CAFactory::create_test_environment();
        assert!(result.is_ok());

        let manager = result.unwrap();
        let cas = manager.list_cas();
        assert_eq!(cas.len(), 2); // 根CA + 中间CA

        let stats = manager.get_statistics();
        assert_eq!(stats.root_cas, 1);
        assert_eq!(stats.intermediate_cas, 1);
    }

    #[test]
    fn test_ca_factory_enterprise_environment() {
        let result = CAFactory::create_enterprise_environment("Test Corp");
        assert!(result.is_ok());

        let manager = result.unwrap();
        let cas = manager.list_cas();
        assert_eq!(cas.len(), 3); // 根CA + 2个中间CA

        let stats = manager.get_statistics();
        assert_eq!(stats.root_cas, 1);
        assert_eq!(stats.intermediate_cas, 2);
    }

    #[test]
    fn test_ca_factory_simple_root() {
        let result = CAFactory::create_simple_root_ca("Test Root CA", "Test Org");
        assert!(result.is_ok());

        let ca = result.unwrap();
        assert!(ca.is_root());
        assert_eq!(ca.config().name, "Test Root CA");
    }

    #[test]
    fn test_ca_factory_from_template() {
        let templates = [
            "enterprise_root",
            "test_root",
            "tls_server",
            "code_signing",
            "iot_device",
        ];

        for template in &templates {
            let result = CAFactory::create_from_template(template);
            assert!(
                result.is_ok(),
                "Failed to create CA from template: {}",
                template
            );
        }

        // 测试无效模板
        let result = CAFactory::create_from_template("invalid_template");
        assert!(result.is_err());
    }

    #[test]
    fn test_utils_validate_ca_hierarchy() {
        let parent_config = Config::root_ca("Parent CA", "Test Org")
            .with_validity(3650, 365)
            .with_max_path_length(Some(3));

        let valid_child_config = Config::intermediate_ca("Child CA", "Test Org")
            .with_validity(1825, 90)
            .with_max_path_length(Some(2));

        let result = utils::validate_ca_hierarchy(&parent_config, &valid_child_config);
        assert!(result.is_ok());

        // 测试无效配置
        let invalid_child_config =
            Config::intermediate_ca("Invalid Child CA", "Test Org").with_validity(5000, 365); // 比父CA有效期长

        let result = utils::validate_ca_hierarchy(&parent_config, &invalid_child_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_utils_calculate_recommended_validity() {
        assert_eq!(utils::calculate_recommended_validity(0), 7300); // 根CA
        assert_eq!(utils::calculate_recommended_validity(1), 3650); // 一级中间CA
        assert_eq!(utils::calculate_recommended_validity(2), 1825); // 二级中间CA
        assert_eq!(utils::calculate_recommended_validity(5), 365); // 深层级CA
    }
}
