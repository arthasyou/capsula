//! 数据胶囊实体信任评估模块
//!
//! 提供通用的数据胶囊实体信任评估功能，包括：
//! - 实体层级定义和信任等级策略 (Authority → Member, Independent)
//! - 验证方法枚举和结果标准化（简化版，无域名验证）
//! - 信任等级计算和层级关系评估
//! - 支持权威机构-成员实体证书链，独立实体自管理

use std::collections::HashMap;

use time::OffsetDateTime;

use crate::{
    error::{PkiError, Result},
    ra::cert::X509Certificate,
};

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
pub struct Context {
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
pub struct Credential {
    /// 验证方法
    pub method: VerificationMethod,
    /// 验证数据 (具体内容由上层定义)
    pub credential_data: String,
    /// 验证时间
    pub verified_at: OffsetDateTime,
    /// 验证有效期
    pub expires_at: Option<OffsetDateTime>,
}

/// 证书链验证凭证
#[derive(Debug, Clone)]
pub struct Credentials {
    /// 证书链（从叶子证书到根证书）
    pub certificates: Vec<X509Certificate>,
    /// 验证时间
    pub verified_at: OffsetDateTime,
    /// 可信根证书列表（可选）
    pub trusted_roots: Option<Vec<X509Certificate>>,
}

/// 身份验证结果
#[derive(Debug, Clone)]
pub struct AuthOutcome {
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
    pub credentials: Vec<Credential>,
}

impl AuthOutcome {
    /// 创建成功的验证结果
    pub fn success(
        trust_level: u8,
        method: VerificationMethod,
        credentials: Vec<Credential>,
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
pub struct Policy {
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

impl Default for Policy {
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
pub struct Evaluator {
    /// 信任策略
    policy: Policy,
    /// 是否启用评估
    enabled: bool,
}

impl Evaluator {
    /// 创建新的信任评估器
    pub fn new() -> Self {
        Self {
            policy: TrustPolicy::default(),
            enabled: true,
        }
    }

    /// 使用自定义策略创建评估器
    pub fn with_policy(policy: Policy) -> Self {
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
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// 获取当前策略
    pub fn get_policy(&self) -> &Policy {
        &self.policy
    }

    /// 评估身份信任等级
    ///
    /// 这是一个抽象方法，基于身份上下文和验证凭证计算信任等级
    /// 具体的验证逻辑由上层服务器实现
    pub fn evaluate_trust(
        &self,
        context: &Context,
        credentials: &[Credential],
    ) -> Result<AuthOutcome> {
        if !self.enabled {
            return Ok(AuthOutcome::success(
                100,
                VerificationMethod::AutoApproval,
                credentials.to_vec(),
            )
            .with_details(vec!["Trust evaluation disabled".to_string()]));
        }

        // 1. 验证实体层级关系
        self.validate_entity_hierarchy(context)?;

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

        Ok(AuthOutcome {
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
    pub fn evaluate_identity_type(&self, identity_type: IdentityType) -> Result<AuthOutcome> {
        let context = Context {
            identity_type,
            subject_identifier: "unknown".to_string(),
            applicant_info: None,
            organization: None,
            country: None,
            authority_identifier: None,
        };

        // 创建一个默认的验证凭证
        let credential = Credential {
            method: VerificationMethod::AutoApproval,
            credential_data: "legacy_evaluation".to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        };

        self.evaluate_trust(&context, &[credential])
    }

    /// 验证实体层级关系
    ///
    /// 确保Member类型实体有正确的Authority关系
    fn validate_entity_hierarchy(&self, context: &IdentityContext) -> Result<()> {
        match context.identity_type {
            IdentityType::Member => {
                // Member实体必须指定authority_identifier
                if context.authority_identifier.is_none() {
                    return Err(crate::error::PkiError::AuthError(
                        "Member entity must specify authority_identifier for certificate chain"
                            .to_string(),
                    )
                    .into());
                }

                let authority_id = context.authority_identifier.as_ref().unwrap();

                // 基本格式检查
                if authority_id.is_empty() {
                    return Err(crate::error::PkiError::AuthError(
                        "Authority identifier cannot be empty".to_string(),
                    )
                    .into());
                }

                // 检查authority_identifier格式是否合法
                if !self.is_valid_authority_identifier(authority_id) {
                    return Err(crate::error::PkiError::AuthError(format!(
                        "Invalid authority identifier format: {}",
                        authority_id
                    ))
                    .into());
                }
            }
            IdentityType::Authority => {
                // Authority实体不应该有authority_identifier
                if context.authority_identifier.is_some() {
                    return Err(crate::error::PkiError::AuthError(
                        "Authority entity should not have authority_identifier".to_string(),
                    )
                    .into());
                }
            }
            IdentityType::Independent => {
                // Independent实体不应该有authority_identifier
                if context.authority_identifier.is_some() {
                    return Err(crate::error::PkiError::AuthError(
                        "Independent entity should not have authority_identifier".to_string(),
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    /// 验证Authority标识符格式
    fn is_valid_authority_identifier(&self, authority_id: &str) -> bool {
        // Authority标识符应该符合特定格式，比如：HOSPITAL_001, COMPANY_CA等
        if authority_id.is_empty() || authority_id.len() > 128 {
            return false;
        }

        // 只允许字母、数字、下划线、点号和短横线
        authority_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
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

    /// 验证证书链
    pub fn verify_certificate_chain(&self, credentials: &Credentials) -> Result<()> {
        if credentials.certificates.is_empty() {
            return Err(PkiError::AuthError(
                "No certificates provided for chain verification".to_string(),
            ));
        }

        // 验证每个证书的有效性
        for cert in &credentials.certificates {
            if !self.is_certificate_valid(cert)? {
                return Err(PkiError::AuthError(
                    "Invalid certificate in chain".to_string(),
                ));
            }
        }

        // 验证证书链的完整性
        if credentials.certificates.len() > 1 {
            self.validate_certificate_chain_integrity(&credentials.certificates)?;
        }

        // 验证根证书或权威机构证书
        self.validate_trust_anchor(&credentials.certificates)?;

        Ok(())
    }

    /// 验证单个证书的有效性
    fn is_certificate_valid(&self, cert: &X509Certificate) -> Result<bool> {
        // 验证证书格式和基本字段
        let subject = cert
            .subject()
            .map_err(|_| PkiError::AuthError("Failed to parse certificate subject".to_string()))?;

        if subject.common_name.trim().is_empty() {
            return Err(PkiError::AuthError(
                "Certificate has empty common name".to_string(),
            ));
        }

        // 验证证书时间有效性
        if !cert.is_currently_valid() {
            return Err(PkiError::AuthError(
                "Certificate is not currently valid (expired or not yet valid)".to_string(),
            ));
        }

        // 验证证书是否为自签名（如果是根证书）
        if let Ok(()) = cert.verify_self_signed() {
            // 这是一个有效的自签名证书（根证书）
            return Ok(true);
        }

        // TODO: 更多证书验证逻辑可以在此处添加
        Ok(true)
    }

    /// 验证证书链的完整性
    fn validate_certificate_chain_integrity(&self, certificates: &[X509Certificate]) -> Result<()> {
        if certificates.len() < 2 {
            return Ok(());
        }

        // 验证证书链顺序：叶子证书 -> 中间证书 -> 根证书
        for i in 0 .. certificates.len() - 1 {
            let child_cert = &certificates[i];
            let parent_cert = &certificates[i + 1];

            // 验证父证书签名子证书
            if let Err(_) = self.verify_certificate_signature(child_cert, parent_cert) {
                return Err(PkiError::AuthError(format!(
                    "Certificate chain broken between position {} and {}",
                    i,
                    i + 1
                )));
            }

            // 验证父证书是CA证书（通过检查基本约束）
            if !self.is_ca_certificate(parent_cert) {
                return Err(PkiError::AuthError(format!(
                    "Certificate at position {} is not a CA certificate",
                    i + 1
                )));
            }
        }

        Ok(())
    }

    /// 验证证书签名
    fn verify_certificate_signature(
        &self,
        child: &X509Certificate,
        parent: &X509Certificate,
    ) -> Result<()> {
        // 获取父证书的公钥
        let parent_public_key = parent.ed25519_public_key_bytes().map_err(|_| {
            PkiError::AuthError("Failed to extract parent certificate public key".to_string())
        })?;

        // 使用父证书公钥验证子证书签名
        child.verify_signature(&parent_public_key).map_err(|_| {
            PkiError::AuthError("Certificate signature verification failed".to_string())
        })
    }

    /// 验证信任锚点（根证书或权威机构证书）
    fn validate_trust_anchor(&self, certificates: &[X509Certificate]) -> Result<()> {
        let root_cert = certificates.last().unwrap();

        // 检查是否为自签名证书（根证书）
        if root_cert.verify_self_signed().is_ok() {
            return Ok(());
        }

        // 检查是否在可信证书列表中
        if self.is_trusted_authority(root_cert) {
            return Ok(());
        }

        Err(PkiError::AuthError(
            "Certificate chain does not end with a trusted root or authority".to_string(),
        ))
    }

    /// 检查是否为CA证书
    fn is_ca_certificate(&self, cert: &X509Certificate) -> bool {
        // 简单实现：检查主体信息中是否包含CA相关标识
        if let Ok(subject) = cert.subject() {
            if let Some(org) = &subject.organization {
                return org.to_lowercase().contains("ca")
                    || org.to_lowercase().contains("authority")
                    || org.to_lowercase().contains("certification");
            }
        }

        // 默认情况下，如果不能确定，返回false以保证安全
        false
    }

    /// 检查是否为可信权威机构
    fn is_trusted_authority(&self, cert: &X509Certificate) -> bool {
        // TODO: 实现可信权威机构列表检查
        // 这里应该检查预配置的可信权威机构列表

        // 临时实现：检查是否为CA证书且具有特定标识
        if !self.is_ca_certificate(cert) {
            return false;
        }

        if let Ok(subject) = cert.subject() {
            if let Some(org) = &subject.organization {
                return org.contains("Authority")
                    || org.contains("Trusted")
                    || org.contains("Root");
            }
        }

        false
    }

    /// 增强的验证凭证处理 - 支持多种验证方法
    pub fn process_verification_credentials(
        &self,
        context: &Context,
        method: &VerificationMethod,
        credential_data: &str,
    ) -> Result<AuthOutcome> {
        match method {
            VerificationMethod::CertificateChain => {
                self.process_certificate_chain_credential(context, credential_data)
            }
            VerificationMethod::Manual => self.process_manual_credential(context, credential_data),
            VerificationMethod::AutoApproval => {
                self.process_auto_approval_credential(context, credential_data)
            }
            VerificationMethod::External(system_name) => {
                self.process_external_credential(context, system_name, credential_data)
            }
        }
    }

    /// 处理证书链验证凭证
    fn process_certificate_chain_credential(
        &self,
        context: &Context,
        credential_data: &str,
    ) -> Result<AuthOutcome> {
        // 这里假设credential_data包含证书链的PEM格式数据
        // 在实际实现中，这可能是JSON格式或其他结构化数据

        // 简单解析逻辑 - 实际实现应该更加健壮
        if credential_data.is_empty() || !credential_data.contains("BEGIN CERTIFICATE") {
            return Ok(AuthOutcome::failure(
                VerificationMethod::CertificateChain,
                "Invalid certificate data provided".to_string(),
            ));
        }

        // 验证实体层级关系
        self.validate_entity_hierarchy(context)?;

        // TODO: 实际解析证书并进行验证
        // 这里应该：
        // 1. 解析PEM格式的证书链
        // 2. 创建VerificationCredentials结构
        // 3. 调用verify_certificate_chain方法

        // 临时实现：基于数据格式简单判断
        let trust_level = if credential_data.contains("ROOT CA") {
            95
        } else if credential_data.contains("INTERMEDIATE CA") {
            85
        } else {
            75
        };

        let credential = Credential {
            method: VerificationMethod::CertificateChain,
            credential_data: credential_data.to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: None,
        };

        Ok(AuthOutcome::success(
            trust_level,
            VerificationMethod::CertificateChain,
            vec![credential],
        ))
    }

    /// 处理手动验证凭证
    fn process_manual_credential(
        &self,
        context: &Context,
        credential_data: &str,
    ) -> Result<AuthOutcome> {
        // 验证实体层级关系
        self.validate_entity_hierarchy(context)?;

        // 手动验证通常需要人工审核记录
        // credential_data可能包含审核员信息、审核时间、审核结果等

        let trust_level =
            if credential_data.contains("approved") && credential_data.contains("auditor") {
                90 // 手动验证通过，高信任度
            } else if credential_data.contains("pending") {
                0 // 等待审核
            } else {
                50 // 部分信息，中等信任度
            };

        let credential = Credential {
            method: VerificationMethod::Manual,
            credential_data: credential_data.to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(24)),
        };

        Ok(AuthOutcome::success(
            trust_level,
            VerificationMethod::Manual,
            vec![credential],
        ))
    }

    /// 处理自动批准凭证
    fn process_auto_approval_credential(
        &self,
        context: &Context,
        credential_data: &str,
    ) -> Result<AuthOutcome> {
        // 验证实体层级关系
        self.validate_entity_hierarchy(context)?;

        // 自动批准通常基于预定义的规则
        let base_trust = self
            .policy
            .base_trust_levels
            .get(&context.identity_type)
            .cloned()
            .unwrap_or(50);

        // 检查是否满足自动批准条件
        let meets_criteria = self.check_auto_approval_criteria(context, credential_data);

        let trust_level = if meets_criteria {
            (base_trust as i16 - 10).max(0) as u8 // 自动批准降低信任度
        } else {
            0 // 不满足条件，拒绝
        };

        let credential = Credential {
            method: VerificationMethod::AutoApproval,
            credential_data: credential_data.to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(12)), // 较短有效期
        };

        Ok(AuthOutcome::success(
            trust_level,
            VerificationMethod::AutoApproval,
            vec![credential],
        ))
    }

    /// 检查自动批准条件
    fn check_auto_approval_criteria(&self, context: &Context, credential_data: &str) -> bool {
        // 基本的自动批准条件检查
        // 实际实现应该基于更复杂的规则引擎

        // 检查实体标识符格式
        if context.subject_identifier.is_empty() || context.subject_identifier.len() > 128 {
            return false;
        }

        // 检查凭证数据有效性
        if credential_data.is_empty() {
            return false;
        }

        // 根据实体类型应用不同的批准条件
        match context.identity_type {
            IdentityType::Independent => {
                // 独立实体相对宽松的条件
                !credential_data.contains("high_risk")
            }
            IdentityType::Member => {
                // 成员实体需要authority_identifier
                context.authority_identifier.is_some() && credential_data.contains("pre_approved")
            }
            IdentityType::Authority => {
                // 权威机构需要更严格的条件
                credential_data.contains("verified_authority") && context.organization.is_some()
            }
        }
    }

    /// 处理外部系统验证凭证（留给外部系统验证接口实现）
    fn process_external_credential(
        &self,
        context: &Context,
        system_name: &str,
        credential_data: &str,
    ) -> Result<AuthOutcome> {
        // 验证实体层级关系
        self.validate_entity_hierarchy(context)?;

        // TODO: 这里应该调用具体的外部系统接口
        // 目前提供一个基础的框架实现

        let trust_level = match system_name {
            "ldap" => self.process_ldap_credential(context, credential_data)?,
            "oauth" => self.process_oauth_credential(context, credential_data)?,
            "saml" => self.process_saml_credential(context, credential_data)?,
            _ => {
                return Ok(AuthOutcome::failure(
                    VerificationMethod::External(system_name.to_string()),
                    format!("Unsupported external system: {}", system_name),
                ));
            }
        };

        let credential = Credential {
            method: VerificationMethod::External(system_name.to_string()),
            credential_data: credential_data.to_string(),
            verified_at: OffsetDateTime::now_utc(),
            expires_at: Some(OffsetDateTime::now_utc() + time::Duration::hours(6)), /* 外部系统验证较短有效期 */
        };

        Ok(AuthOutcome::success(
            trust_level,
            VerificationMethod::External(system_name.to_string()),
            vec![credential],
        ))
    }

    /// LDAP系统验证处理（占位实现）
    fn process_ldap_credential(&self, _context: &Context, credential_data: &str) -> Result<u8> {
        // TODO: 实现LDAP验证逻辑
        if credential_data.contains("ldap_verified") {
            Ok(80)
        } else {
            Ok(0)
        }
    }

    /// OAuth系统验证处理（占位实现）
    fn process_oauth_credential(&self, _context: &Context, credential_data: &str) -> Result<u8> {
        // TODO: 实现OAuth验证逻辑
        if credential_data.contains("oauth_token") && credential_data.contains("valid") {
            Ok(75)
        } else {
            Ok(0)
        }
    }

    /// SAML系统验证处理（占位实现）
    fn process_saml_credential(&self, _context: &Context, credential_data: &str) -> Result<u8> {
        // TODO: 实现SAML验证逻辑
        if credential_data.contains("saml_assertion") && credential_data.contains("signature_valid")
        {
            Ok(85)
        } else {
            Ok(0)
        }
    }

    /// 外部系统验证接口特征定义
    ///
    /// 该接口允许集成各种外部身份验证系统
    pub fn register_external_verifier<F>(&mut self, system_name: String, _verifier: F)
    where
        F: Fn(&Context, &str) -> std::result::Result<u8, String> + 'static,
    {
        // TODO: 实现外部验证器注册机制
        // 这里需要存储验证器函数，可能需要修改结构体以支持动态验证器
        // 外部验证器已注册（日志记录可在上层实现）
        let _ = system_name; // 避免未使用警告
    }

    /// 获取支持的外部验证系统列表
    pub fn get_supported_external_systems(&self) -> Vec<String> {
        vec![
            "ldap".to_string(),
            "oauth".to_string(),
            "saml".to_string(),
            "oidc".to_string(),     // OpenID Connect
            "x509".to_string(),     // X.509 证书验证
            "kerberos".to_string(), // Kerberos认证
            "radius".to_string(),   // RADIUS认证
            "custom".to_string(),   // 自定义系统
        ]
    }

    /// 验证外部系统凭证的通用接口
    pub fn validate_external_credential(
        &self,
        system_name: &str,
        credential_data: &str,
    ) -> Result<bool> {
        match system_name {
            "ldap" => {
                // LDAP凭证格式验证
                Ok(credential_data.contains("dn=") && credential_data.len() > 10)
            }
            "oauth" => {
                // OAuth token格式验证
                Ok(credential_data.starts_with("Bearer ")
                    || credential_data.contains("access_token"))
            }
            "saml" => {
                // SAML断言格式验证
                Ok(credential_data.contains("<saml:Assertion")
                    || credential_data.contains("saml_response"))
            }
            "oidc" => {
                // OpenID Connect JWT格式验证
                Ok(credential_data.matches('.').count() == 2) // JWT has 3 parts separated by dots
            }
            "x509" => {
                // X.509证书格式验证
                Ok(credential_data.contains("BEGIN CERTIFICATE")
                    || credential_data.starts_with("MIIC"))
            }
            "kerberos" => {
                // Kerberos票据格式验证
                Ok(credential_data.contains("krb5_") || credential_data.contains("ticket"))
            }
            "radius" => {
                // RADIUS响应格式验证
                Ok(credential_data.contains("Access-Accept")
                    || credential_data.contains("radius_response"))
            }
            "custom" => {
                // 自定义系统的基础验证
                Ok(!credential_data.is_empty() && credential_data.len() < 4096)
            }
            _ => Err(PkiError::AuthError(format!(
                "Unknown external system: {}",
                system_name
            ))),
        }
    }

    /// 外部系统连接状态检查
    pub fn check_external_system_health(&self, system_name: &str) -> Result<bool> {
        // TODO: 实现实际的外部系统健康检查
        // 这里应该包括网络连接、认证状态、服务可用性等检查

        match system_name {
            "ldap" => {
                // 检查LDAP服务器连接状态
                // TODO: 实现实际的LDAP健康检查
                Ok(true) // 临时返回true
            }
            "oauth" => {
                // 检查OAuth服务器状态
                // TODO: 实现实际的OAuth健康检查
                Ok(true) // 临时返回true
            }
            "saml" => {
                // 检查SAML IdP状态
                // TODO: 实现实际的SAML健康检查
                Ok(true) // 临时返回true
            }
            _ => Ok(true), // 默认假设系统健康
        }
    }

    /// 外部系统集成配置验证
    pub fn validate_external_system_config(
        &self,
        system_name: &str,
        config: &str,
    ) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        match system_name {
            "ldap" => {
                if !config.contains("server") {
                    issues.push("LDAP server address is required".to_string());
                }
                if !config.contains("base_dn") {
                    issues.push("LDAP base DN is required".to_string());
                }
                if !config.contains("bind_dn") {
                    issues.push("LDAP bind DN is required".to_string());
                }
            }
            "oauth" => {
                if !config.contains("client_id") {
                    issues.push("OAuth client ID is required".to_string());
                }
                if !config.contains("authorization_endpoint") {
                    issues.push("OAuth authorization endpoint is required".to_string());
                }
                if !config.contains("token_endpoint") {
                    issues.push("OAuth token endpoint is required".to_string());
                }
            }
            "saml" => {
                if !config.contains("idp_url") {
                    issues.push("SAML IdP URL is required".to_string());
                }
                if !config.contains("certificate") {
                    issues.push("SAML IdP certificate is required".to_string());
                }
            }
            _ => {
                // 对于其他系统，进行基础配置检查
                if config.is_empty() {
                    issues.push(format!("Configuration for {} cannot be empty", system_name));
                }
            }
        }

        Ok(issues)
    }

    /// 外部系统信任等级映射配置
    pub fn configure_external_trust_mapping(
        &mut self,
        system_name: &str,
        base_trust: u8,
        bonus: i8,
    ) {
        // TODO: 实现动态信任等级配置
        // 这里应该更新policy中的method_trust_bonus

        let method = VerificationMethod::External(system_name.to_string());
        self.policy.method_trust_bonus.insert(method, bonus);

        // 信任等级映射已配置（日志记录可在上层实现）
        let _ = base_trust; // 避免未使用警告
    }

    /// 批量外部系统验证
    pub fn verify_multiple_external_systems(
        &self,
        context: &Context,
        credentials: &[(String, String)],
    ) -> Result<AuthOutcome> {
        let mut total_trust = 0i16;
        let mut verification_details = Vec::new();
        let mut warnings = Vec::new();
        let mut processed_credentials = Vec::new();

        // 验证实体层级关系
        self.validate_entity_hierarchy(context)?;

        for (system_name, credential_data) in credentials {
            // 验证凭证格式
            if let Err(e) = self.validate_external_credential(system_name, credential_data) {
                warnings.push(format!("Invalid credential for {}: {}", system_name, e));
                continue;
            }

            // 检查系统健康状态
            match self.check_external_system_health(system_name) {
                Ok(false) => {
                    warnings.push(format!("External system {} is not healthy", system_name));
                    continue;
                }
                Err(e) => {
                    warnings.push(format!("Health check failed for {}: {}", system_name, e));
                    continue;
                }
                Ok(true) => {} // 系统健康，继续处理
            }

            // 处理验证
            match self.process_external_credential(context, system_name, credential_data) {
                Ok(result) => {
                    if result.is_authenticated {
                        total_trust += result.trust_level as i16;
                        verification_details.push(format!(
                            "Verified via {}: trust level {}",
                            system_name, result.trust_level
                        ));
                        processed_credentials.extend(result.credentials);
                    } else {
                        warnings.push(format!("Verification failed for {}", system_name));
                    }
                }
                Err(e) => {
                    warnings.push(format!("Error processing {}: {}", system_name, e));
                }
            }
        }

        // 计算平均信任等级
        let final_trust = if !processed_credentials.is_empty() {
            (total_trust / processed_credentials.len() as i16)
                .min(100)
                .max(0) as u8
        } else {
            0
        };

        let is_authenticated = final_trust >= self.policy.minimum_trust_level;

        Ok(AuthOutcome {
            is_authenticated,
            trust_level: final_trust,
            verification_method: VerificationMethod::External("multiple".to_string()),
            auth_time: OffsetDateTime::now_utc(),
            verification_details,
            warnings,
            credentials: processed_credentials,
        })
    }
}

impl Default for Evaluator {
    fn default() -> Self {
        Self::new()
    }
}

// 重新导出为旧名称以保持向后兼容
pub type TrustEvaluator = Evaluator;
pub type IdentityAuth = Evaluator;
pub type IdentityContext = Context;
pub type VerificationCredential = Credential;
pub type VerificationCredentials = Credentials;
pub type TrustPolicy = Policy;
pub type AuthResult = AuthOutcome;

#[cfg(test)]
mod tests {

    use super::*;

    fn create_test_context(identity_type: IdentityType, subject: &str) -> Context {
        let authority_id = if matches!(identity_type, IdentityType::Member) {
            Some("TestAuthority_001".to_string())
        } else {
            None
        };

        Context {
            identity_type,
            subject_identifier: subject.to_string(),
            applicant_info: Some("test_applicant".to_string()),
            organization: Some("Test Corp".to_string()),
            country: Some("US".to_string()),
            authority_identifier: authority_id,
        }
    }

    fn create_test_credential(method: VerificationMethod) -> Credential {
        Credential {
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
            AuthOutcome::success(85, VerificationMethod::CertificateChain, vec![credential]);
        assert!(success.is_authenticated);
        assert_eq!(success.trust_level, 85);
        assert_eq!(
            success.verification_method,
            VerificationMethod::CertificateChain
        );

        let failure = AuthOutcome::failure(
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
        let result = AuthOutcome::success(80, VerificationMethod::CertificateChain, vec![])
            .with_details(vec!["Test detail".to_string()])
            .with_warnings(vec!["Test warning".to_string()]);

        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 80);
        assert_eq!(result.verification_details[0], "Test detail");
        assert_eq!(result.warnings[0], "Test warning");
    }

    // 新增测试用例 - 验证Authority-Member关系
    #[test]
    fn test_authority_member_hierarchy_validation() {
        let evaluator = TrustEvaluator::new();

        // 测试Member实体必须有authority_identifier
        let member_context_without_authority = IdentityContext {
            identity_type: IdentityType::Member,
            subject_identifier: "DOCTOR_001".to_string(),
            applicant_info: Some("test_doctor".to_string()),
            organization: Some("Test Hospital".to_string()),
            country: Some("CN".to_string()),
            authority_identifier: None, // 缺少authority_identifier
        };

        let result = evaluator.evaluate_trust(&member_context_without_authority, &[]);
        assert!(result.is_err());

        // 测试Member实体有正确的authority_identifier
        let member_context_with_authority = IdentityContext {
            identity_type: IdentityType::Member,
            subject_identifier: "DOCTOR_001".to_string(),
            applicant_info: Some("test_doctor".to_string()),
            organization: Some("Test Hospital".to_string()),
            country: Some("CN".to_string()),
            authority_identifier: Some("HOSPITAL_CA_001".to_string()),
        };

        let credential = create_test_credential(VerificationMethod::AutoApproval);
        let result = evaluator.evaluate_trust(&member_context_with_authority, &[credential]);
        assert!(result.is_ok());

        // 测试Authority实体不应该有authority_identifier
        let authority_context_with_identifier = IdentityContext {
            identity_type: IdentityType::Authority,
            subject_identifier: "AUTHORITY_001".to_string(),
            applicant_info: Some("test_authority".to_string()),
            organization: Some("Test Authority".to_string()),
            country: Some("CN".to_string()),
            authority_identifier: Some("INVALID".to_string()), // Authority不应该有这个字段
        };

        let result = evaluator.evaluate_trust(&authority_context_with_identifier, &[]);
        assert!(result.is_err());

        // 测试Independent实体不应该有authority_identifier
        let independent_context_with_identifier = IdentityContext {
            identity_type: IdentityType::Independent,
            subject_identifier: "USER_001".to_string(),
            applicant_info: Some("test_user".to_string()),
            organization: None,
            country: Some("CN".to_string()),
            authority_identifier: Some("INVALID".to_string()), // Independent不应该有这个字段
        };

        let result = evaluator.evaluate_trust(&independent_context_with_identifier, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_identifier_format_validation() {
        let evaluator = TrustEvaluator::new();

        // 测试有效的authority_identifier格式
        assert!(evaluator.is_valid_authority_identifier("HOSPITAL_001"));
        assert!(evaluator.is_valid_authority_identifier("COMPANY-CA"));
        assert!(evaluator.is_valid_authority_identifier("AUTH.SYSTEM"));
        assert!(evaluator.is_valid_authority_identifier("test_ca_123"));

        // 测试无效的authority_identifier格式
        assert!(!evaluator.is_valid_authority_identifier(""));
        assert!(!evaluator.is_valid_authority_identifier("invalid space"));
        assert!(!evaluator.is_valid_authority_identifier("invalid@symbol"));
        assert!(!evaluator.is_valid_authority_identifier("invalid#hash"));

        // 测试过长的identifier
        let long_id = "a".repeat(129);
        assert!(!evaluator.is_valid_authority_identifier(&long_id));
    }

    #[test]
    fn test_process_verification_credentials() {
        let evaluator = TrustEvaluator::new();
        let context = create_test_context(IdentityType::Authority, "AUTH_001");

        // 测试证书链凭证处理
        let cert_result = evaluator.process_verification_credentials(
            &context,
            &VerificationMethod::CertificateChain,
            "-----BEGIN CERTIFICATE-----\nROOT CA\n-----END CERTIFICATE-----",
        );
        assert!(cert_result.is_ok());
        let result = cert_result.unwrap();
        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 95); // ROOT CA应该有95的信任度

        // 测试手动验证凭证处理
        let manual_result = evaluator.process_verification_credentials(
            &context,
            &VerificationMethod::Manual,
            "approved by auditor John Doe at 2023-12-01",
        );
        assert!(manual_result.is_ok());
        let result = manual_result.unwrap();
        assert!(result.is_authenticated);
        assert_eq!(result.trust_level, 90);

        // 测试无效证书数据
        let invalid_result = evaluator.process_verification_credentials(
            &context,
            &VerificationMethod::CertificateChain,
            "invalid data",
        );
        assert!(invalid_result.is_ok());
        let result = invalid_result.unwrap();
        assert!(!result.is_authenticated);
    }

    #[test]
    fn test_external_system_credential_validation() {
        let evaluator = TrustEvaluator::new();

        // 测试LDAP凭证验证
        assert!(evaluator
            .validate_external_credential("ldap", "dn=cn=user,ou=people,dc=example,dc=com")
            .unwrap());
        assert!(!evaluator
            .validate_external_credential("ldap", "invalid")
            .unwrap());

        // 测试OAuth凭证验证
        assert!(evaluator
            .validate_external_credential("oauth", "Bearer abc123token")
            .unwrap());
        assert!(evaluator
            .validate_external_credential("oauth", "access_token=xyz789")
            .unwrap());
        assert!(!evaluator
            .validate_external_credential("oauth", "invalid")
            .unwrap());

        // 测试SAML凭证验证
        assert!(evaluator
            .validate_external_credential("saml", "<saml:Assertion>content</saml:Assertion>")
            .unwrap());
        assert!(evaluator
            .validate_external_credential("saml", "saml_response=encoded_response")
            .unwrap());
        assert!(!evaluator
            .validate_external_credential("saml", "invalid")
            .unwrap());

        // 测试OIDC JWT验证
        assert!(evaluator
            .validate_external_credential("oidc", "header.payload.signature")
            .unwrap());
        assert!(!evaluator
            .validate_external_credential("oidc", "invalid.jwt")
            .unwrap());

        // 测试X.509证书验证
        assert!(evaluator
            .validate_external_credential("x509", "-----BEGIN CERTIFICATE-----")
            .unwrap());
        assert!(evaluator
            .validate_external_credential("x509", "MIIC...")
            .unwrap());
        assert!(!evaluator
            .validate_external_credential("x509", "invalid")
            .unwrap());

        // 测试未知系统
        let unknown_result = evaluator.validate_external_credential("unknown", "data");
        assert!(unknown_result.is_err());
    }

    #[test]
    fn test_external_system_configuration_validation() {
        let evaluator = TrustEvaluator::new();

        // 测试LDAP配置验证
        let ldap_config = "server=ldap.example.com;base_dn=dc=example,dc=com;bind_dn=admin";
        let ldap_issues = evaluator
            .validate_external_system_config("ldap", ldap_config)
            .unwrap();
        assert!(ldap_issues.is_empty());

        let invalid_ldap_config = "server=ldap.example.com";
        let ldap_issues = evaluator
            .validate_external_system_config("ldap", invalid_ldap_config)
            .unwrap();
        assert_eq!(ldap_issues.len(), 2); // 缺少base_dn和bind_dn

        // 测试OAuth配置验证
        let oauth_config = "client_id=123;authorization_endpoint=auth;token_endpoint=token";
        let oauth_issues = evaluator
            .validate_external_system_config("oauth", oauth_config)
            .unwrap();
        assert!(oauth_issues.is_empty());

        let invalid_oauth_config = "client_id=123";
        let oauth_issues = evaluator
            .validate_external_system_config("oauth", invalid_oauth_config)
            .unwrap();
        assert_eq!(oauth_issues.len(), 2); // 缺少endpoints

        // 测试SAML配置验证
        let saml_config = "idp_url=https://idp.example.com;certificate=cert_data";
        let saml_issues = evaluator
            .validate_external_system_config("saml", saml_config)
            .unwrap();
        assert!(saml_issues.is_empty());
    }

    #[test]
    fn test_auto_approval_criteria() {
        let evaluator = TrustEvaluator::new();

        // 测试Independent实体的自动批准
        let independent_context = IdentityContext {
            identity_type: IdentityType::Independent,
            subject_identifier: "USER_001".to_string(),
            applicant_info: Some("test_user".to_string()),
            organization: None,
            country: Some("CN".to_string()),
            authority_identifier: None,
        };

        assert!(evaluator.check_auto_approval_criteria(&independent_context, "normal_request"));
        assert!(!evaluator.check_auto_approval_criteria(&independent_context, "high_risk_request"));

        // 测试Member实体的自动批准
        let member_context = IdentityContext {
            identity_type: IdentityType::Member,
            subject_identifier: "DOCTOR_001".to_string(),
            applicant_info: Some("test_doctor".to_string()),
            organization: Some("Test Hospital".to_string()),
            country: Some("CN".to_string()),
            authority_identifier: Some("HOSPITAL_CA".to_string()),
        };

        assert!(evaluator.check_auto_approval_criteria(&member_context, "pre_approved_request"));
        assert!(!evaluator.check_auto_approval_criteria(&member_context, "normal_request"));

        // 测试Authority实体的自动批准
        let authority_context = IdentityContext {
            identity_type: IdentityType::Authority,
            subject_identifier: "AUTH_001".to_string(),
            applicant_info: Some("test_authority".to_string()),
            organization: Some("Test Authority".to_string()),
            country: Some("CN".to_string()),
            authority_identifier: None,
        };

        assert!(evaluator
            .check_auto_approval_criteria(&authority_context, "verified_authority_request"));
        assert!(!evaluator.check_auto_approval_criteria(&authority_context, "normal_request"));
    }

    #[test]
    fn test_supported_external_systems() {
        let evaluator = TrustEvaluator::new();
        let systems = evaluator.get_supported_external_systems();

        assert!(systems.contains(&"ldap".to_string()));
        assert!(systems.contains(&"oauth".to_string()));
        assert!(systems.contains(&"saml".to_string()));
        assert!(systems.contains(&"oidc".to_string()));
        assert!(systems.contains(&"x509".to_string()));
        assert!(systems.contains(&"kerberos".to_string()));
        assert!(systems.contains(&"radius".to_string()));
        assert!(systems.contains(&"custom".to_string()));

        assert_eq!(systems.len(), 8);
    }

    #[test]
    fn test_external_system_health_check() {
        let evaluator = TrustEvaluator::new();

        // 测试已知系统的健康检查
        assert!(evaluator.check_external_system_health("ldap").unwrap());
        assert!(evaluator.check_external_system_health("oauth").unwrap());
        assert!(evaluator.check_external_system_health("saml").unwrap());
        assert!(evaluator.check_external_system_health("unknown").unwrap()); // 未知系统默认返回true
    }

    #[test]
    fn test_trust_mapping_configuration() {
        let mut evaluator = TrustEvaluator::new();

        // 配置外部系统信任映射
        evaluator.configure_external_trust_mapping("custom_system", 80, 25);

        // 验证配置是否生效
        let method = VerificationMethod::External("custom_system".to_string());
        assert_eq!(evaluator.policy.method_trust_bonus.get(&method), Some(&25));
    }
}
