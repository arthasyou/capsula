use std::path::Path;

use capsula_key::key::{Key, KeyEncDec, KeySign};
use serde::{Deserialize, Serialize};

use crate::{block::SealedBlock, keyring::Keyring, ContentType};

/// 0阶数据胶囊：原始数据层
///
/// 0阶数据胶囊是数据胶囊体系的基础层，负责封装原始数据。
/// 它包含两个主要部分：
/// 1. origin: 原始数据的加密密文（图片、视频、音频、文档等）
/// 2. origin_text: 文字注释版本的加密密文（OCR提取、描述、摘要等）
///
/// 设计原则：
/// - 每个SealedBlock都是独立可验证的加密单元
/// - 原始数据和文字注释各自有独立的作者证明
/// - 支持ZKP证明的基础：文字注释提供结构化数据用于证明生成
/// - 明文永不直接暴露，只能通过密钥持有者解封
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap0 {
    /// 原始数据的加密密文
    /// 包含原始文件（如CT影像、血检报告PDF、病历记录等）的AEAD加密密文
    /// 以及对应的作者证明，确保数据来源可信且不可篡改
    pub origin: SealedBlock,

    /// 文字注释版本的加密密文
    /// 包含从原始数据中提取的结构化文字信息：
    /// - 图片：OCR提取的文字、医学影像的诊断描述
    /// - 文档：关键信息提取、标准化字段
    /// - 音频：语音识别转写文本
    /// - 视频：关键帧描述、操作记录
    ///
    /// 这部分数据为后续ZKP证明提供基础，允许在不暴露原始数据的情况下
    /// 对特定片段或结论生成可验证证明
    pub origin_text: SealedBlock,
}

/// 0阶数据胶囊外部封装状态
///
/// 用于外部存储模式下的中间状态管理
/// 包含两个SealedBlock（URI都待设置）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap0ExternalSeal {
    /// 原始文件的SealedBlock（URI为占位符）
    /// 等待用户上传加密文件并设置存储URI
    pub origin_block: SealedBlock,

    /// 文字注释的SealedBlock（URI为占位符）
    /// 等待用户上传加密文件并设置存储URI
    pub origin_text_block: SealedBlock,
}

impl Cap0 {
    /// 验证0阶胶囊的完整性
    ///
    /// 检查：
    /// 1. 原始数据封装块的完整性
    /// 2. 文字注释封装块的完整性
    /// 3. 两个封装块的一致性（例如时间戳、作者等）
    pub fn verify_integrity(&self) -> crate::Result<bool> {
        // TODO: 实现完整性验证逻辑
        // 1. 验证原始数据块的签名和完整性
        // 2. 如果有文字注释，验证其签名和完整性
        // 3. 检查两个块之间的一致性（作者、时间戳等）
        // 4. 验证文字注释确实对应原始数据（通过某种绑定机制）

        Ok(true) // 临时返回，待实现具体验证逻辑
    }

    /// 封装0阶数据胶囊（外部存储模式）
    ///
    /// 将原始文件和文字注释文件都加密到外部存储
    /// 返回预封装状态，用户需要上传两个加密文件后设置URI
    ///
    /// # 参数
    /// - `origin_file_path`: 原始文件路径
    /// - `origin_encrypted_output_path`: 原始文件加密输出路径
    /// - `origin_text_file_path`: 文字注释文件路径
    /// - `origin_text_encrypted_output_path`: 文字注释文件加密输出路径
    /// - `content_types`: 内容类型元组 (origin_type, origin_text_type)
    /// - `aad`: 额外认证数据（外层上下文）
    /// - `keyring`: 密钥环用于存储加密的DEK
    /// - `spki_der`: 所有者公钥（SPKI DER格式）
    /// - `signing_key`: 作者签名密钥
    ///
    /// # 返回
    /// 预封装状态，用户需要上传两个加密文件后设置URI
    pub fn seal<S>(
        origin_file_path: &Path,
        origin_encrypted_output_path: &Path,
        origin_text_file_path: &Path,
        origin_text_encrypted_output_path: &Path,
        content_types: (ContentType, ContentType),
        aad: &[u8],
        keyring: &mut Keyring,
        spki_der: &[u8],
        signing_key: &S,
    ) -> crate::Result<Cap0ExternalSeal>
    where
        S: Key + KeySign,
    {
        // 1. 预封装原始文件
        let origin_block = SealedBlock::pre_seal(
            origin_file_path,
            origin_encrypted_output_path,
            content_types.0,
            aad,
            keyring,
            spki_der,
            signing_key,
        )?;

        // 2. 预封装文字注释文件
        let origin_text_block = SealedBlock::pre_seal(
            origin_text_file_path,
            origin_text_encrypted_output_path,
            content_types.1,
            aad,
            keyring,
            spki_der,
            signing_key,
        )?;

        Ok(Cap0ExternalSeal {
            origin_block,
            origin_text_block,
        })
    }

    /// 完成封装
    ///
    /// 用户上传两个加密文件后，同时设置两个存储URI完成0阶胶囊的封装
    ///
    /// # 参数
    /// - `external_seal`: 外部封装状态
    /// - `origin_uri`: 原始数据的存储URI
    /// - `origin_text_uri`: 文字注释的存储URI
    ///
    /// # 返回
    /// 完整的Cap0实例
    pub fn complete_seal(
        mut external_seal: Cap0ExternalSeal,
        origin_uri: String,
        origin_text_uri: String,
    ) -> crate::Result<Self> {
        // 设置两个文件的存储URI
        external_seal.origin_block.set_uri(origin_uri)?;
        external_seal.origin_text_block.set_uri(origin_text_uri)?;

        Ok(Self {
            origin: external_seal.origin_block,
            origin_text: external_seal.origin_text_block,
        })
    }

    /// 解封0阶数据胶囊
    ///
    /// 解密0阶胶囊中的数据，两个数据都使用外部存储
    /// 用户需要提供下载的两个加密文件路径
    ///
    /// # 参数
    /// - `encrypted_origin_file`: 下载的原始数据加密文件路径
    /// - `output_origin_file`: 原始数据解密输出文件路径
    /// - `encrypted_origin_text_file`: 下载的文字注释加密文件路径
    /// - `output_origin_text_file`: 文字注释解密输出文件路径
    /// - `keyring`: 密钥环
    /// - `decryption_key`: 解密密钥
    ///
    /// # 返回
    /// 无返回值，两个文件都解密到指定的输出文件
    pub fn unseal<T>(
        &self,
        encrypted_origin_file: &Path,
        output_origin_file: &Path,
        encrypted_origin_text_file: &Path,
        output_origin_text_file: &Path,
        keyring: &Keyring,
        decryption_key: &T,
    ) -> crate::Result<()>
    where
        T: Key + KeyEncDec,
    {
        // 1. 解封原始数据到文件
        self.origin.unseal_external(
            encrypted_origin_file,
            output_origin_file,
            keyring,
            decryption_key,
        )?;

        // 2. 解封文字注释数据到文件
        self.origin_text.unseal_external(
            encrypted_origin_text_file,
            output_origin_text_file,
            keyring,
            decryption_key,
        )?;

        Ok(())
    }

    /// 获取原始数据的存储类型
    ///
    /// 检查原始数据使用的是内联存储还是外部存储
    pub fn origin_storage_type(&self) -> crate::block::StorageType {
        self.origin.storage_type()
    }

    /// 获取原始数据外部存储的URI
    pub fn get_origin_external_uri(&self) -> crate::Result<&str> {
        self.origin.get_external_uri()
    }

    /// 获取文字注释外部存储的URI
    pub fn get_origin_text_external_uri(&self) -> crate::Result<&str> {
        self.origin_text.get_external_uri()
    }
}

impl Cap0ExternalSeal {
    /// 设置原始数据的存储URI
    ///
    /// 用户上传原始数据加密文件后调用此方法设置存储URI
    ///
    /// # 参数
    /// - `uri`: 原始数据的存储URI
    pub fn set_origin_uri(&mut self, uri: String) -> crate::Result<()> {
        self.origin_block.set_uri(uri)
    }

    /// 设置文字注释的存储URI
    ///
    /// 用户上传文字注释加密文件后调用此方法设置存储URI
    ///
    /// # 参数
    /// - `uri`: 文字注释的存储URI
    pub fn set_origin_text_uri(&mut self, uri: String) -> crate::Result<()> {
        self.origin_text_block.set_uri(uri)
    }

    /// 检查是否已设置所有URI
    ///
    /// 返回true表示两个URI都已设置，可以调用complete_seal
    pub fn is_ready_for_completion(&self) -> bool {
        // 检查两个block的URI是否都已设置（不为空字符串）
        if let (Ok(origin_uri), Ok(text_uri)) = (
            self.origin_block.get_external_uri(),
            self.origin_text_block.get_external_uri(),
        ) {
            !origin_uri.is_empty() && !text_uri.is_empty()
        } else {
            false
        }
    }

    /// 完成封装（从状态创建Cap0）
    ///
    /// 两个URI都设置后，调用此方法创建最终的Cap0实例
    pub fn into_cap0(self) -> crate::Result<Cap0> {
        // 检查是否准备好
        if !self.is_ready_for_completion() {
            return Err(crate::error::CoreError::DataError(
                "Both origin and origin_text URIs must be set before completion".to_string(),
            ));
        }

        Ok(Cap0 {
            origin: self.origin_block,
            origin_text: self.origin_text_block,
        })
    }
}
