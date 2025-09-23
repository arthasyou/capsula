use serde::{Deserialize, Serialize};

use crate::block::SealedBlock;

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

    /// 文字注释版本的加密密文（可选）
    /// 包含从原始数据中提取的结构化文字信息：
    /// - 图片：OCR提取的文字、医学影像的诊断描述
    /// - 文档：关键信息提取、标准化字段
    /// - 音频：语音识别转写文本
    /// - 视频：关键帧描述、操作记录
    ///
    /// 这部分数据为后续ZKP证明提供基础，允许在不暴露原始数据的情况下
    /// 对特定片段或结论生成可验证证明
    pub origin_text: Option<SealedBlock>,
}

impl Cap0 {
    /// 创建新的0阶数据胶囊
    ///
    /// # 参数
    /// - `origin`: 原始数据的封装块
    /// - `origin_text`: 可选的文字注释版本封装块
    ///
    /// # 返回
    /// 新的Cap0实例
    pub fn new(origin: SealedBlock, origin_text: Option<SealedBlock>) -> Self {
        Self {
            origin,
            origin_text,
        }
    }

    /// 获取原始数据封装块的引用
    pub fn get_origin(&self) -> &SealedBlock {
        &self.origin
    }

    /// 获取文字注释封装块的引用（如果存在）
    pub fn get_origin_text(&self) -> Option<&SealedBlock> {
        self.origin_text.as_ref()
    }

    /// 检查是否包含文字注释版本
    pub fn has_text_version(&self) -> bool {
        self.origin_text.is_some()
    }

    /// 验证0阶胶囊的完整性
    ///
    /// 检查：
    /// 1. 原始数据封装块的完整性
    /// 2. 文字注释封装块的完整性（如果存在）
    /// 3. 两个封装块的一致性（例如时间戳、作者等）
    pub fn verify_integrity(&self) -> crate::Result<bool> {
        // TODO: 实现完整性验证逻辑
        // 1. 验证原始数据块的签名和完整性
        // 2. 如果有文字注释，验证其签名和完整性
        // 3. 检查两个块之间的一致性（作者、时间戳等）
        // 4. 验证文字注释确实对应原始数据（通过某种绑定机制）

        Ok(true) // 临时返回，待实现具体验证逻辑
    }
}
