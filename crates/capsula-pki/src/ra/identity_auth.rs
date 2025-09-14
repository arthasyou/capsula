//! 数据胶囊实体信任评估模块
//!
//! 提供通用的数据胶囊实体信任评估功能，包括：
//! - 实体层级定义和信任等级策略 (Authority → Member, Independent)
//! - 验证方法枚举和结果标准化（简化版，无域名验证）
//! - 信任等级计算和层级关系评估
//! - 支持权威机构-成员实体证书链，独立实体自管理

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::error::Result;

/// 数据胶囊实体类型 - 层级关系设计
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdentityType {
    /// 权威机构 - 可作为根CA或中间CA (如：医院、公司、政府机构)
    /// 具有签发其他证书的权限
    Authority,
    /// 成员实体 - 由权威机构签发证书 (如：医生、员工、设备)
    /// 形成Authority → Member的证书链关系
    Member,
    /// 独立实体 - 自主管理证书 (如：病人、个人用户、独立设备)
    /// 不依赖其他机构，可以自签名或独立CA
    Independent,
}

/// 验证方法类型 - 简化版，适用于数据胶囊场景
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VerificationMethod {
    /// 证书链验证 (通过权威机构证书验证)
    CertificateChain,
    /// 手动验证 (人工审核)
    Manual,
    /// 自动批准 (基于策略的自动批准)
    AutoApproval,
    /// 外部系统验证 (集成外部身份验证系统)
    External(String),
}

/// 数据胶囊实体验证上下文
#[derive(Debug, Clone)]
pub struct IdentityContext {
    /// 实体类型 (Authority/Member/Independent)
    pub identity_type: IdentityType,
    /// 实体标识符 (不是域名，而是业务标识符)
    pub subject_identifier: String,
    /// 申请者信息
    pub applicant_info: Option<String>,
    /// 组织/权威机构信息 (Member类型需要关联的Authority)
    pub organization: Option<String>,
    /// 地区信息 (可选)
    pub country: Option<String>,
    /// 权威机构标识 (Member实体的上级Authority)
    pub authority_identifier: Option<String>,
}

/// 验证凭证（抽象）
#[derive(Debug, Clone)]
pub struct VerificationCredential {
    /// 验证方法
    pub method: VerificationMethod,
    /// 验证数据 (具体内容由上层定义)
    pub credential_data: String,
    /// 验证时间
    pub verified_at: OffsetDateTime,
    /// 验证有效期
    pub expires_at: Option<OffsetDateTime>,
}

/// 身份验证结果
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// 身份验证是否通过
    pub is_authenticated: bool,
    /// 信任等级 (0-100)
    pub trust_level: u8,
    /// 使用的验证方法
    pub verification_method: VerificationMethod,
    /// 验证时间
    pub auth_time: OffsetDateTime,
    /// 验证详情
    pub verification_details: Vec<String>,
    /// 警告信息
    pub warnings: Vec<String>,
    /// 验证凭证
    pub credentials: Vec<VerificationCredential>,
}

impl AuthResult {
    /// 创建成功的验证结果
    pub fn success(
        trust_level: u8,
        method: VerificationMethod,
        credentials: Vec<VerificationCredential>,
    ) -> Self {
        Self {
            is_authenticated: true,
            trust_level,
            verification_method: method,
            auth_time: OffsetDateTime::now_utc(),
            verification_details: vec![],
            warnings: vec![],
            credentials,
        }
    }

    /// 创建失败的验证结果
    pub fn failure(method: VerificationMethod, reason: String) -> Self {
        Self {
            is_authenticated: false,
            trust_level: 0,
            verification_method: method,
            auth_time: OffsetDateTime::now_utc(),
            verification_details: vec![reason],
            warnings: vec![],
            credentials: vec![],
        }
    }

    /// 添加验证详情
    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.verification_details = details;
        self
    }

    /// 添加警告
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

/// 信任策略配置
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    /// 不同身份类型的基础信任等级
    pub base_trust_levels: HashMap<IdentityType, u8>,
    /// 不同验证方法的信任加成
    pub method_trust_bonus: HashMap<VerificationMethod, i8>,
    /// 最低信任等级要求
    pub minimum_trust_level: u8,
    /// 是否要求多重验证
    pub require_multi_verification: bool,
    /// 验证凭证有效期（小时）
    pub credential_validity_hours: u32,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        let mut base_trust_levels = HashMap::new();
        base_trust_levels.insert(IdentityType::Authority, 85); // 权威机构基础信任度最高
        base_trust_levels.insert(IdentityType::Member, 70); // 成员实体中等信任度
        base_trust_levels.insert(IdentityType::Independent, 60); // 独立实体较低基础信任度

        let mut method_trust_bonus = HashMap::new();
        method_trust_bonus.insert(VerificationMethod::CertificateChain, 20); // 证书链验证最可靠
        method_trust_bonus.insert(VerificationMethod::Manual, 25); // 手动验证最高加成
        method_trust_bonus.insert(VerificationMethod::AutoApproval, -10); // 自动批准有风险
        method_trust_bonus.insert(VerificationMethod::External("default".to_string()), 15); // 外部系统验证

        Self {
            base_trust_levels,
            method_trust_bonus,
            minimum_trust_level: 70,
            require_multi_verification: false,
            credential_validity_hours: 24,
        }
    }
}

/// 抽象身份信任评估器
pub struct TrustEvaluator {
    /// 信任策略
    policy: TrustPolicy,
    /// 是否启用评估
    enabled: bool,
}

impl TrustEvaluator {
    /// 创建新的信任评估器
    pub fn new() -> Self {
        Self {
            policy: TrustPolicy::default(),
            enabled: true,
        }
    }

    /// 使用自定义策略创建评估器
    pub fn with_policy(policy: TrustPolicy) -> Self {
        Self {
            policy,
            enabled: true,
        }
    }

    /// 禁用评估（开发/测试模式）
    pub fn disabled() -> Self {
        Self {
            policy: TrustPolicy::default(),
            enabled: false,
        }
    }

    /// 更新信任策略
    pub fn set_policy(&mut self, policy: TrustPolicy) {
        self.policy = policy;
    }

    /// 获取当前策略
    pub fn get_policy(&self) -> &TrustPolicy {
        &self.policy
    }

    /// 评估身份信任等级
    ///
    /// 这是一个抽象方法，基于身份上下文和验证凭证计算信任等级
    /// 具体的验证逻辑由上层服务器实现
    pub fn evaluate_trust(
        &self,
        context: &IdentityContext,
        credentials: &[VerificationCredential],
    ) -> Result<AuthResult> {
        if !self.enabled {
            return Ok(AuthResult::success(
                100,
                VerificationMethod::AutoApproval,
                credentials.to_vec(),
            )
            .with_details(vec!["Trust evaluation disabled".to_string()]));
        }

        // 获取身份类型的基础信任等级
        let base_trust = self
            .policy
            .base_trust_levels
            .get(&context.identity_type)
            .cloned()
            .unwrap_or(50);

        let mut total_trust = base_trust as i16;
        let mut verification_details = vec![];
        let mut warnings = vec![];
        let mut primary_method = VerificationMethod::AutoApproval;

        // 验证凭证有效性并计算信任加成
        for credential in credentials {
            // 检查凭证是否过期
            if let Some(expires_at) = credential.expires_at {
                if OffsetDateTime::now_utc() > expires_at {
                    warnings.push(format!(
                        "Credential using {:?} method has expired",
                        credential.method
                    ));
                    continue;
                }
            }

            // 检查凭证年龄
            let credential_age = OffsetDateTime::now_utc() - credential.verified_at;
            if credential_age.whole_hours() > self.policy.credential_validity_hours as i64 {
                warnings.push(format!(
                    "Credential using {:?} method is too old ({} hours)",
                    credential.method,
                    credential_age.whole_hours()
                ));
                continue;
            }

            // 应用验证方法的信任加成
            if let Some(bonus) = self.policy.method_trust_bonus.get(&credential.method) {
                total_trust += *bonus as i16;
                verification_details.push(format!(
                    "Applied {:+} trust bonus for {:?} verification",
                    bonus, credential.method
                ));
            }

            // 记录主要验证方法
            primary_method = credential.method.clone();
        }

        // 检查是否需要多重验证
        if self.policy.require_multi_verification && credentials.len() < 2 {
            warnings.push("Policy requires multiple verification methods".to_string());
            total_trust -= 15;
        }

        // 应用信任等级边界
        let final_trust = (total_trust as u8).min(100);

        // 检查是否满足最低信任要求
        let is_authenticated = final_trust >= self.policy.minimum_trust_level;

        if !is_authenticated {
            verification_details.push(format!(
                "Trust level {} below minimum requirement {}",
                final_trust, self.policy.minimum_trust_level
            ));
        }

        Ok(AuthResult {
            is_authenticated,
            trust_level: final_trust,
            verification_method: primary_method,
            auth_time: OffsetDateTime::now_utc(),
            verification_details,
            warnings,
            credentials: credentials.to_vec(),
        })
    }

    /// 简化的身份类型评估（向后兼容）
    pub fn evaluate_identity_type(&self, identity_type: IdentityType) -> Result<AuthResult> {
        let context = IdentityContext {
            identity_type,
            subject_identifier: "unknown".to_string(),
            applicant_info: None,
            organization: None,
            country: None,
            authority_identifier: None,
        };

        // 创建一个默认的验证凭证
        let credential = VerificationCredential {
            method: VerificationMethod::AutoApproval,
            credential_data: "legacy_evaluation".to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        };

        self.evaluate_trust(&context, &[credential])
    }

    /// 检查验证方法组合的有效性
    pub fn validate_verification_methods(&self, methods: &[VerificationMethod]) -> Vec<String> {
        let mut issues = vec![];

        if methods.is_empty() {
            issues.push("No verification methods provided".to_string());
            return issues;
        }

        // 检查是否有冲突的验证方法
        if methods.contains(&VerificationMethod::AutoApproval) && methods.len() > 1 {
            issues.push("Auto-approval should not be combined with other methods".to_string());
        }

        // 检查多重验证要求
        if self.policy.require_multi_verification && methods.len() < 2 {
            issues.push("Policy requires multiple verification methods".to_string());
        }

        issues
    }
}

impl Default for TrustEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// 重新导出为旧名称以保持向后兼容
pub type IdentityAuth = TrustEvaluator;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn create_test_context(identity_type: IdentityType, subject: &str) -> IdentityContext {
        let authority_id = if matches!(identity_type, IdentityType::Member) {
            Some("TestAuthority_001".to_string())
        } else {
            None
        };

        IdentityContext {
            identity_type,
            subject_identifier: subject.to_string(),
            applicant_info: Some("test_applicant".to_string()),
            organization: Some("Test Corp".to_string()),
            country: Some("US".to_string()),
            authority_identifier: authority_id,
        }
    }

    fn create_test_credential(method: VerificationMethod) -> VerificationCredential {
        VerificationCredential {
            method,
            credential_data: "test_data".to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        }
    }

    #[test]
    fn test_default_trust_policy() {
        let policy = TrustPolicy::default();

        assert_eq!(policy.base_trust_levels[&IdentityType::Authority], 85);
        assert_eq!(policy.base_trust_levels[&IdentityType::Member], 70);
        assert_eq!(policy.base_trust_levels[&IdentityType::Independent], 60);

        assert_eq!(
            policy.method_trust_bonus[&VerificationMethod::CertificateChain],
            20
        );
        assert_eq!(policy.method_trust_bonus[&VerificationMethod::Manual], 25);

        assert_eq!(policy.minimum_trust_level, 70);
        assert!(!policy.require_multi_verification);
        assert_eq!(policy.credential_validity_hours, 24);
    }

    #[test]
    fn test_trust_evaluator_creation() {
        let evaluator = TrustEvaluator::new();
        assert_eq!(evaluator.policy.minimum_trust_level, 70);

        let disabled = TrustEvaluator::disabled();
        assert!(!disabled.enabled);

        let mut custom_policy = TrustPolicy::default();
        custom_policy.minimum_trust_level = 90;
        let custom_evaluator = TrustEvaluator::with_policy(custom_policy);
        assert_eq!(custom_evaluator.policy.minimum_trust_level, 90);
    }

    #[test]
    fn test_auth_result_creation() {
        let credential = create_test_credential(VerificationMethod::CertificateChain);

        let success =
            AuthResult::success(85, VerificationMethod::CertificateChain, vec![credential]);
        assert!(success.is_authenticated);
        assert_eq!(success.trust_level, 85);
        assert_eq!(
            success.verification_method,
            VerificationMethod::CertificateChain
        );

        let failure = AuthResult::failure(
            VerificationMethod::Manual,
            "Manual verification failed".to_string(),
        );
        assert!(!failure.is_authenticated);
        assert_eq!(failure.trust_level, 0);
        assert_eq!(
            failure.verification_details[0],
            "Manual verification failed"
        );
    }

    #[test]
    fn test_basic_trust_evaluation() {
        let evaluator = TrustEvaluator::new();
        let context = create_test_context(IdentityType::Authority, "AUTHORITY_001");
        let credentials = vec![create_test_credential(VerificationMethod::CertificateChain)];

        let result = evaluator.evaluate_trust(&context, &credentials).unwrap();

        // Authority base (85) + CertificateChain bonus (20) = 105, capped at 100
        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 100);
        assert_eq!(
            result.verification_method,
            VerificationMethod::CertificateChain
        );
    }

    #[test]
    fn test_trust_evaluation_below_threshold() {
        let mut policy = TrustPolicy::default();
        policy.minimum_trust_level = 90;
        let evaluator = TrustEvaluator::with_policy(policy);

        let context = create_test_context(IdentityType::Independent, "USER_001");
        let credentials = vec![create_test_credential(VerificationMethod::AutoApproval)];

        let result = evaluator.evaluate_trust(&context, &credentials).unwrap();

        // Independent base (60) + AutoApproval penalty (-10) = 50, below threshold (90)
        assert!(!result.is_authenticated);
        assert_eq!(result.trust_level, 50);
        assert!(!result.verification_details.is_empty());
    }

    #[test]
    fn test_multi_verification_bonus() {
        let evaluator = TrustEvaluator::new();
        let context = create_test_context(IdentityType::Member, "DOCTOR_001");
        let credentials = vec![
            create_test_credential(VerificationMethod::CertificateChain),
            create_test_credential(VerificationMethod::Manual),
        ];

        let result = evaluator.evaluate_trust(&context, &credentials).unwrap();

        // Member base (70) + CertificateChain (20) + Manual (25) = 115, capped at 100
        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 100);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_multi_verification_requirement() {
        let mut policy = TrustPolicy::default();
        policy.require_multi_verification = true;
        let evaluator = TrustEvaluator::with_policy(policy);

        let context = create_test_context(IdentityType::Authority, "AUTHORITY_001");
        let credentials = vec![create_test_credential(VerificationMethod::CertificateChain)];

        let result = evaluator.evaluate_trust(&context, &credentials).unwrap();

        // Authority base (85) + CertificateChain (20) - multi_verification_penalty (15) = 90
        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 90);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("multiple verification methods"));
    }

    #[test]
    fn test_expired_credentials() {
        let evaluator = TrustEvaluator::new();
        let context = create_test_context(IdentityType::Member, "MEMBER_001");

        let mut expired_credential = create_test_credential(VerificationMethod::CertificateChain);
        expired_credential.expires_at = Some(OffsetDateTime::now_utc() - time::Duration::hours(1));

        let result = evaluator
            .evaluate_trust(&context, &[expired_credential])
            .unwrap();

        // Only base trust (70), no bonus from expired credential
        assert!(result.is_authenticated); // 70 >= 70 (default threshold)
        assert_eq!(result.trust_level, 70);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("expired"));
    }

    #[test]
    fn test_old_credentials() {
        let mut policy = TrustPolicy::default();
        policy.credential_validity_hours = 1; // Very short validity
        let evaluator = TrustEvaluator::with_policy(policy);

        let context = create_test_context(IdentityType::Member, "device.example.com");

        let mut old_credential = create_test_credential(VerificationMethod::CertificateChain);
        old_credential.verified_at = OffsetDateTime::now_utc() - time::Duration::hours(2);

        let result = evaluator
            .evaluate_trust(&context, &[old_credential])
            .unwrap();

        // Only base trust (70), no bonus from old credential
        assert!(result.is_authenticated); // 70 >= 70 (exact threshold)
        assert_eq!(result.trust_level, 70);
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("too old"));
    }

    #[test]
    fn test_disabled_evaluator() {
        let evaluator = TrustEvaluator::disabled();
        let context = create_test_context(IdentityType::Independent, "test.com");
        let credentials = vec![];

        let result = evaluator.evaluate_trust(&context, &credentials).unwrap();

        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 100);
        assert_eq!(result.verification_method, VerificationMethod::AutoApproval);
        assert!(result.verification_details[0].contains("disabled"));
    }

    #[test]
    fn test_backward_compatibility() {
        let evaluator = TrustEvaluator::new();

        let result = evaluator
            .evaluate_identity_type(IdentityType::Authority)
            .unwrap();

        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 75); // Authority base (85) + AutoApproval penalty (-10) = 75
        assert_eq!(result.verification_method, VerificationMethod::AutoApproval);
    }

    #[test]
    fn test_verification_method_validation() {
        let evaluator = TrustEvaluator::new();

        // Valid single method
        let issues =
            evaluator.validate_verification_methods(&[VerificationMethod::CertificateChain]);
        assert!(issues.is_empty());

        // Empty methods
        let issues = evaluator.validate_verification_methods(&[]);
        assert!(!issues.is_empty());
        assert!(issues[0].contains("No verification methods"));

        // Auto-approval with other methods (conflict)
        let issues = evaluator.validate_verification_methods(&[
            VerificationMethod::AutoApproval,
            VerificationMethod::CertificateChain,
        ]);
        assert!(!issues.is_empty());
        assert!(issues[0].contains("Auto-approval"));
    }

    #[test]
    fn test_verification_method_validation_multi_required() {
        let mut policy = TrustPolicy::default();
        policy.require_multi_verification = true;
        let evaluator = TrustEvaluator::with_policy(policy);

        // Single method when multi required
        let issues =
            evaluator.validate_verification_methods(&[VerificationMethod::CertificateChain]);
        assert!(!issues.is_empty());
        assert!(issues[0].contains("multiple verification methods"));

        // Multiple methods (valid)
        let issues = evaluator.validate_verification_methods(&[
            VerificationMethod::CertificateChain,
            VerificationMethod::Manual,
        ]);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_auth_result_methods() {
        let result = AuthResult::success(80, VerificationMethod::CertificateChain, vec![])
            .with_details(vec!["Test detail".to_string()])
            .with_warnings(vec!["Test warning".to_string()]);

        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 80);
        assert_eq!(result.verification_details[0], "Test detail");
        assert_eq!(result.warnings[0], "Test warning");
    }
}
