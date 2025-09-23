use serde::{Deserialize, Serialize};

use crate::block::SealedBlock;
use crate::keyring::Keyring;
use crate::ContentType;
use capsula_key::key::{Key, KeyEncDec, KeySign};

/// 1阶数据胶囊：解释层
///
/// 1阶数据胶囊是在0阶数据胶囊基础上的解释层，包含：
/// 1. cap0_id: 关联的0阶数据胶囊ID
/// 2. meta: 元数据的加密密文（6元素向量：采集者、拥有者、摘要、期限等）
/// 3. bnf_extract: BNF解析提取的结构化内容（BNF→JSON结构化数据）
/// 4. zkp: 零知识证明（暂时可选，未来用于证明摘要片段来自原始数据）
///
/// 设计原则：
/// - 不直接暴露0阶原始数据，只通过ID关联
/// - 元数据和摘要都经过加密，保护隐私
/// - 摘要提供结构化信息，便于检索和ZKP证明
/// - 支持独立验证，不依赖解密0阶数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap1 {
    /// 关联的0阶数据胶囊ID
    /// 用于定位对应的原始数据和文字注释
    pub cap0_id: String,

    /// 元数据的加密密文
    /// 包含6元素向量的部分信息：
    /// - 数据采集者信息
    /// - 数据拥有者信息
    /// - 其他敏感元数据
    /// 注意：使用者、授权向量、期限等可能存储在外层策略中
    pub meta: SealedBlock,

    /// BNF语法解析提取的结构化内容（加密密文）
    /// 包含从原始数据通过BNF语法规则提取并转换的结构化内容：
    /// - BNF解析器处理后的JSON格式数据
    /// - 关键字段和指标的标准化表示
    /// - 标准化的医疗/业务术语和数值
    /// - 这是1阶胶囊的核心价值：将非结构化数据转为可理解的结构化数据
    /// 这部分数据为ZKP证明和业务应用提供基础
    pub bnf_extract: SealedBlock,

    /// 零知识证明（可选，暂未实现）
    /// 用于证明摘要中的特定片段确实来自原始数据
    /// 例如："血糖值 > 7.0 mmol/L" 的证明
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zkp: Option<ZkpProof>,
}

/// 零知识证明结构（占位符定义）
///
/// 这是一个占位符结构，实际的ZKP实现需要：
/// 1. 选择合适的ZKP系统（如zk-SNARKs、zk-STARKs）
/// 2. 设计电路来证明摘要片段与原始数据的关系
/// 3. 实现证明生成和验证逻辑
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpProof {
    /// 证明的类型（如"field_value"、"range_proof"等）
    pub proof_type: String,

    /// 被证明的声明（如"blood_glucose > 7.0"）
    pub claim: String,

    /// ZKP证明数据（具体格式取决于ZKP系统）
    pub proof_data: String,

    /// 验证密钥或公共参数的引用
    pub verification_key: Option<String>,

    /// 证明生成时间
    pub generated_at: String,
}

impl Cap1 {
    /// 检查是否包含ZKP证明
    pub fn has_zkp_proof(&self) -> bool {
        self.zkp.is_some()
    }

    /// 验证1阶胶囊的完整性
    ///
    /// 检查：
    /// 1. 元数据封装块的完整性
    /// 2. 摘要封装块的完整性
    /// 3. ZKP证明的有效性（如果存在）
    /// 4. cap0_id的有效性（格式检查）
    pub fn verify_integrity(&self) -> crate::Result<bool> {
        // TODO: 实现完整性验证逻辑
        // 1. 验证元数据块的签名和完整性
        // 2. 验证摘要块的签名和完整性
        // 3. 如果有ZKP证明，验证证明的有效性
        // 4. 检查cap0_id的格式和有效性
        // 5. 验证元数据和摘要的一致性（作者、时间戳等）

        Ok(true) // 临时返回，待实现具体验证逻辑
    }

    /// 验证与0阶胶囊的关联性
    ///
    /// 这个方法需要访问对应的0阶胶囊来验证：
    /// 1. cap0_id确实存在且有效
    /// 2. 摘要数据与0阶胶囊的内容一致
    /// 3. 元数据中的信息与0阶胶囊匹配
    pub fn verify_cap0_association(&self, _cap0: &crate::capsule::Cap0) -> crate::Result<bool> {
        // TODO: 实现与0阶胶囊的关联验证
        // 1. 验证cap0_id匹配
        // 2. 检查时间戳的一致性
        // 3. 验证作者信息的一致性
        // 4. 可选：验证摘要确实来源于0阶胶囊的内容

        Ok(true) // 临时返回，待实现具体验证逻辑
    }

    /// 获取1阶胶囊的摘要信息
    ///
    /// 返回用于索引和检索的基本信息，不包含敏感数据
    pub fn get_summary_info(&self) -> Cap1Summary {
        Cap1Summary {
            cap0_id: self.cap0_id.clone(),
            meta_content_type: self.meta.content_type.clone(),
            meta_size: self.meta.ciphertext.len,
            bnf_extract_content_type: self.bnf_extract.content_type.clone(),
            bnf_extract_size: self.bnf_extract.ciphertext.len,
            has_zkp_proof: self.has_zkp_proof(),
            zkp_claim: self.zkp.as_ref().map(|z| z.claim.clone()),
            created_at: self.meta.proof.issued_at.clone(),
        }
    }

    /// 封装创建1阶数据胶囊
    ///
    /// 将元数据和BNF提取数据加密封装成1阶数据胶囊
    /// 由于数据量相对较小，使用内联存储模式
    ///
    /// # 参数
    /// - `cap0_id`: 关联的0阶数据胶囊ID
    /// - `meta_data`: 元数据明文字节
    /// - `bnf_extract_data`: BNF解析提取的数据明文字节
    /// - `content_types`: 内容类型元组 (meta_type, bnf_extract_type)
    /// - `aad`: 额外认证数据（外层上下文）
    /// - `keyring`: 密钥环用于存储加密的DEK
    /// - `spki_der`: 所有者公钥（SPKI DER格式）
    /// - `signing_key`: 作者签名密钥
    /// - `zkp`: 可选的零知识证明
    ///
    /// # 返回
    /// 新的Cap1实例，所有数据都已加密并签名
    pub fn seal<S>(
        cap0_id: String,
        meta_data: &[u8],
        bnf_extract_data: &[u8],
        content_types: (ContentType, ContentType),
        aad: &[u8],
        keyring: &mut Keyring,
        spki_der: &[u8],
        signing_key: &S,
        zkp: Option<ZkpProof>,
    ) -> crate::Result<Self>
    where
        S: Key + KeySign,
    {
        // 1. 封装元数据
        let meta = SealedBlock::seal_inline(
            meta_data,
            content_types.0,
            aad,
            keyring,
            spki_der,
            signing_key,
        )?;

        // 2. 封装BNF提取数据
        let bnf_extract = SealedBlock::seal_inline(
            bnf_extract_data,
            content_types.1,
            aad,
            keyring,
            spki_der,
            signing_key,
        )?;

        Ok(Self {
            cap0_id,
            meta,
            bnf_extract,
            zkp,
        })
    }

    /// 解封1阶数据胶囊
    ///
    /// 解密1阶胶囊中的元数据和BNF提取数据
    /// 由于1阶胶囊使用内联存储，解封过程相对简单
    ///
    /// # 参数
    /// - `keyring`: 密钥环
    /// - `decryption_key`: 解密密钥
    ///
    /// # 返回
    /// 解密后的数据元组 (元数据, BNF提取数据)
    pub fn unseal<T>(
        &self,
        keyring: &Keyring,
        decryption_key: &T,
    ) -> crate::Result<(Vec<u8>, Vec<u8>)>
    where
        T: Key + KeyEncDec,
    {
        // 1. 解封元数据
        let meta_data = self.meta.unseal_inline(keyring, decryption_key)?;

        // 2. 解封BNF提取数据
        let bnf_extract_data = self.bnf_extract.unseal_inline(keyring, decryption_key)?;

        Ok((meta_data, bnf_extract_data))
    }
}

/// 1阶数据胶囊的摘要信息
///
/// 用于索引和检索，不包含敏感的密文数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap1Summary {
    /// 关联的0阶数据胶囊ID
    pub cap0_id: String,

    /// 元数据的内容类型
    pub meta_content_type: crate::ContentType,

    /// 元数据的大小（字节）
    pub meta_size: u64,

    /// BNF提取数据的内容类型
    pub bnf_extract_content_type: crate::ContentType,

    /// BNF提取数据的大小（字节）
    pub bnf_extract_size: u64,

    /// 是否包含ZKP证明
    pub has_zkp_proof: bool,

    /// ZKP证明的声明（如果存在）
    pub zkp_claim: Option<String>,

    /// 创建时间
    pub created_at: Option<String>,
}

impl ZkpProof {
    /// 创建新的ZKP证明
    pub fn new(
        proof_type: String,
        claim: String,
        proof_data: String,
        verification_key: Option<String>,
    ) -> Self {
        Self {
            proof_type,
            claim,
            proof_data,
            verification_key,
            generated_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        }
    }

    /// 验证ZKP证明的有效性
    pub fn verify(&self) -> crate::Result<bool> {
        // TODO: 实现ZKP验证逻辑
        // 这里需要根据具体的ZKP系统实现验证
        // 1. 解析proof_data
        // 2. 使用verification_key验证证明
        // 3. 检查claim的格式和有效性
        // 4. 验证时间戳

        Ok(true) // 临时返回，待实现具体验证逻辑
    }
}
