use capsula_key::key::{Key, KeySign};
use serde::{Deserialize, Serialize};

use crate::integrity::{digest::Digest, signature::Signature};

/// 2阶数据胶囊：聚合层
///
/// 2阶数据胶囊是按所有者聚合的胶囊容器，提供：
/// 1. owner_id: 所有者唯一标识
/// 2. refs: 按类型分组的1阶胶囊ID引用列表
/// 3. bundle_hash: 引用集合的完整性哈希
/// 4. bundle_signature: 对bundle_hash的签名
///
/// 设计原则：
/// - 按所有者聚合，便于权限管理和检索
/// - 只存储引用，不存储实际数据，保持轻量级
/// - 支持类型化检索：按报告类型快速定位相关胶囊
/// - 明文存储引用信息，便于快速索引和搜索
/// - 通过签名保证引用集合的完整性和不可篡改性
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap2 {
    /// 所有者唯一标识
    /// 通常是用户ID、患者ID或机构ID
    pub owner_id: String,

    /// 按类型分组的胶囊引用列表
    /// 每个RefEntry包含一种类型的所有相关1阶胶囊ID
    pub refs: Vec<RefEntry>,

    /// 引用集合的哈希值
    /// 对所有refs进行规范化排序后计算的哈希值
    /// 用于检测引用集合是否被篡改
    pub bundle_hash: Digest,

    /// 对bundle_hash的签名
    /// 提供引用集合的不可抵赖性和完整性保证
    pub bundle_signature: Signature,
}

/// 引用条目：特定类型的胶囊ID集合
///
/// 按报告类型或数据类型对1阶胶囊进行分组
/// 便于类型化检索和管理
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefEntry {
    /// 报告类型或数据类型标识
    /// 例如："血常规报告"、"胸部CT"、"心电图"、"病理报告"等
    pub report_type: String,

    /// 该类型下的1阶胶囊ID列表
    /// 按时间顺序或其他逻辑顺序排列
    pub ids: Vec<String>,

    /// 可选的元数据
    /// 存储该类型胶囊的额外信息，如数量统计、时间范围等
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RefMetadata>,
}

/// 引用条目的元数据
///
/// 提供关于特定类型胶囊集合的统计和描述信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefMetadata {
    /// 胶囊数量
    pub count: u32,

    /// 最早的胶囊创建时间
    pub earliest_date: Option<String>,

    /// 最新的胶囊创建时间
    pub latest_date: Option<String>,

    /// 该类型的描述信息
    pub description: Option<String>,

    /// 标签或分类信息
    pub tags: Vec<String>,
}

impl Cap2 {
    /// 计算引用集合的哈希值
    ///
    /// 对refs进行规范化序列化后计算SHA-256哈希
    /// 确保相同的引用集合产生相同的哈希值
    pub fn compute_bundle_hash(&self) -> crate::Result<Digest> {
        use sha2::{Digest as Sha2Digest, Sha256};

        // 规范化序列化：按report_type排序，ids内部也排序
        let mut normalized_refs = self.refs.clone();
        normalized_refs.sort_by(|a, b| a.report_type.cmp(&b.report_type));

        for ref_entry in &mut normalized_refs {
            ref_entry.ids.sort();
        }

        // 序列化并计算哈希
        let serialized = serde_json::to_string(&normalized_refs)
            .map_err(|e| crate::error::CoreError::JsonError(e))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash_bytes = hasher.finalize();
        let hash = capsula_crypto::base64::encode(hash_bytes);

        Ok(Digest {
            alg: "SHA-256".to_string(),
            hash,
        })
    }

    /// 验证bundle_hash的正确性
    ///
    /// 重新计算引用集合的哈希值并与存储的hash比较
    pub fn verify_bundle_hash(&self) -> crate::Result<bool> {
        let computed_hash = self.compute_bundle_hash()?;
        Ok(computed_hash.hash == self.bundle_hash.hash)
    }

    /// 根据报告类型查找引用条目
    pub fn find_refs_by_type(&self, report_type: &str) -> Option<&RefEntry> {
        self.refs
            .iter()
            .find(|ref_entry| ref_entry.report_type == report_type)
    }

    /// 获取所有1阶胶囊ID的扁平化列表
    pub fn get_all_cap1_ids(&self) -> Vec<String> {
        self.refs
            .iter()
            .flat_map(|ref_entry| ref_entry.ids.iter())
            .cloned()
            .collect()
    }

    /// 获取报告类型列表
    pub fn get_report_types(&self) -> Vec<String> {
        self.refs
            .iter()
            .map(|ref_entry| ref_entry.report_type.clone())
            .collect()
    }

    /// 统计总的胶囊数量
    pub fn count_total_capsules(&self) -> usize {
        self.refs.iter().map(|ref_entry| ref_entry.ids.len()).sum()
    }

    /// 添加新的引用条目
    ///
    /// 如果该类型已存在，则合并ID列表；否则创建新条目
    pub fn add_ref_entry(&mut self, mut new_entry: RefEntry) -> crate::Result<()> {
        if let Some(existing) = self
            .refs
            .iter_mut()
            .find(|ref_entry| ref_entry.report_type == new_entry.report_type)
        {
            // 合并ID列表，去重
            existing.ids.append(&mut new_entry.ids);
            existing.ids.sort();
            existing.ids.dedup();

            // 更新元数据
            if let Some(new_meta) = new_entry.metadata {
                if let Some(existing_meta) = &mut existing.metadata {
                    existing_meta.count = existing.ids.len() as u32;
                    // 更新时间范围
                    if let (Some(new_earliest), Some(existing_earliest)) =
                        (&new_meta.earliest_date, &existing_meta.earliest_date)
                    {
                        if new_earliest < existing_earliest {
                            existing_meta.earliest_date = new_meta.earliest_date;
                        }
                    }
                    if let (Some(new_latest), Some(existing_latest)) =
                        (&new_meta.latest_date, &existing_meta.latest_date)
                    {
                        if new_latest > existing_latest {
                            existing_meta.latest_date = new_meta.latest_date;
                        }
                    }
                } else {
                    existing.metadata = Some(new_meta);
                }
            }
        } else {
            // 创建新条目
            self.refs.push(new_entry);
            self.refs.sort_by(|a, b| a.report_type.cmp(&b.report_type));
        }

        // 重新计算hash（需要重新签名）
        self.bundle_hash = self.compute_bundle_hash()?;

        Ok(())
    }

    /// 移除指定类型的引用条目
    pub fn remove_ref_entry(&mut self, report_type: &str) -> crate::Result<bool> {
        let original_len = self.refs.len();
        self.refs
            .retain(|ref_entry| ref_entry.report_type != report_type);

        if self.refs.len() < original_len {
            // 重新计算hash（需要重新签名）
            self.bundle_hash = self.compute_bundle_hash()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 封装创建2阶数据胶囊
    ///
    /// 将引用条目列表封装成2阶数据胶囊，自动计算hash和签名
    /// 2阶胶囊使用明文存储引用信息，只对引用集合进行签名保护
    ///
    /// # 参数
    /// - `owner_id`: 所有者唯一标识
    /// - `refs`: 引用条目列表
    /// - `signing_key`: 签名密钥（用于对引用集合hash签名）
    ///
    /// # 返回
    /// 新的Cap2实例，包含计算好的hash和签名
    pub fn seal<S>(owner_id: String, refs: Vec<RefEntry>, signing_key: &S) -> crate::Result<Self>
    where
        S: Key + KeySign,
    {
        // 创建临时实例来计算hash
        let temp_cap2 = Self {
            owner_id,
            refs,
            bundle_hash: Digest {
                alg: "SHA-256".to_string(),
                hash: "temp".to_string(),
            },
            bundle_signature: Signature {
                alg: "Ed25519".to_string(),
                sig: "temp".to_string(),
                author_hint: "temp".to_string(),
                cert_hint: None,
            },
        };

        // 1. 计算引用集合的hash
        let bundle_hash = temp_cap2.compute_bundle_hash()?;

        // 2. 对hash进行签名
        let hash_bytes = bundle_hash.hash.as_bytes();
        let signature_bytes = signing_key
            .sign(hash_bytes)
            .map_err(|e| crate::error::CoreError::DataError(format!("Signing failed: {}", e)))?;

        let bundle_signature = Signature {
            alg: "Ed25519".to_string(),
            sig: capsula_crypto::base64::encode(&signature_bytes),
            author_hint: format!("cap2_signer_{}", temp_cap2.owner_id),
            cert_hint: None,
        };

        // 3. 创建最终的Cap2实例
        Ok(Self {
            owner_id: temp_cap2.owner_id,
            refs: temp_cap2.refs,
            bundle_hash,
            bundle_signature,
        })
    }
}

impl RefEntry {
    /// 创建新的引用条目
    pub fn new(report_type: String, ids: Vec<String>, metadata: Option<RefMetadata>) -> Self {
        Self {
            report_type,
            ids,
            metadata,
        }
    }

    /// 添加胶囊ID
    pub fn add_id(&mut self, id: String) {
        if !self.ids.contains(&id) {
            self.ids.push(id);
            self.ids.sort();

            // 更新元数据计数
            if let Some(meta) = &mut self.metadata {
                meta.count = self.ids.len() as u32;
            }
        }
    }

    /// 移除胶囊ID
    pub fn remove_id(&mut self, id: &str) -> bool {
        let original_len = self.ids.len();
        self.ids.retain(|existing_id| existing_id != id);

        if self.ids.len() < original_len {
            // 更新元数据计数
            if let Some(meta) = &mut self.metadata {
                meta.count = self.ids.len() as u32;
            }
            true
        } else {
            false
        }
    }

    /// 检查是否包含指定ID
    pub fn contains_id(&self, id: &str) -> bool {
        self.ids.contains(&id.to_string())
    }

    /// 获取ID数量
    pub fn count(&self) -> usize {
        self.ids.len()
    }
}

impl RefMetadata {
    /// 创建新的引用元数据
    pub fn new(
        count: u32,
        earliest_date: Option<String>,
        latest_date: Option<String>,
        description: Option<String>,
    ) -> Self {
        Self {
            count,
            earliest_date,
            latest_date,
            description,
            tags: Vec::new(),
        }
    }

    /// 添加标签
    pub fn add_tag(&mut self, tag: String) {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.tags.sort();
        }
    }

    /// 移除标签
    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试专用构造函数
    impl Cap2 {
        fn new_for_test(
            owner_id: String,
            refs: Vec<RefEntry>,
            bundle_hash: Digest,
            bundle_signature: Signature,
        ) -> Self {
            Self {
                owner_id,
                refs,
                bundle_hash,
                bundle_signature,
            }
        }
    }

    fn create_test_digest() -> Digest {
        Digest {
            alg: "SHA-256".to_string(),
            hash: "test_hash_value".to_string(),
        }
    }

    fn create_test_signature() -> Signature {
        Signature {
            alg: "Ed25519".to_string(),
            sig: "test_signature_value".to_string(),
            author_hint: "test_author".to_string(),
            cert_hint: None,
        }
    }

    #[test]
    fn test_cap2_creation() {
        let metadata1 = RefMetadata::new(
            2,
            Some("2025-09-01T00:00:00Z".to_string()),
            Some("2025-09-15T00:00:00Z".to_string()),
            Some("血常规检查报告".to_string()),
        );

        let metadata2 = RefMetadata::new(
            1,
            Some("2025-09-10T00:00:00Z".to_string()),
            Some("2025-09-10T00:00:00Z".to_string()),
            Some("胸部CT检查报告".to_string()),
        );

        let refs = vec![
            RefEntry::new(
                "血常规报告".to_string(),
                vec!["cap1_blood_001".to_string(), "cap1_blood_002".to_string()],
                Some(metadata1),
            ),
            RefEntry::new(
                "胸部CT".to_string(),
                vec!["cap1_ct_001".to_string()],
                Some(metadata2),
            ),
        ];

        let cap2 = Cap2::new_for_test(
            "patient_001".to_string(),
            refs,
            create_test_digest(),
            create_test_signature(),
        );

        // 验证基本属性
        assert_eq!(cap2.owner_id, "patient_001");
        assert_eq!(cap2.refs.len(), 2);
        assert_eq!(cap2.count_total_capsules(), 3);

        // 验证类型查找
        let blood_refs = cap2.find_refs_by_type("血常规报告");
        assert!(blood_refs.is_some());
        assert_eq!(blood_refs.unwrap().ids.len(), 2);

        // 验证所有ID获取
        let all_ids = cap2.get_all_cap1_ids();
        assert_eq!(all_ids.len(), 3);
        assert!(all_ids.contains(&"cap1_blood_001".to_string()));
        assert!(all_ids.contains(&"cap1_ct_001".to_string()));
    }

    #[test]
    fn test_ref_entry_operations() {
        let mut ref_entry = RefEntry::new(
            "测试报告".to_string(),
            vec!["id1".to_string(), "id2".to_string()],
            None,
        );

        // 测试添加ID
        ref_entry.add_id("id3".to_string());
        assert_eq!(ref_entry.count(), 3);
        assert!(ref_entry.contains_id("id3"));

        // 测试重复添加
        ref_entry.add_id("id1".to_string());
        assert_eq!(ref_entry.count(), 3); // 不应该增加

        // 测试移除ID
        assert!(ref_entry.remove_id("id2"));
        assert_eq!(ref_entry.count(), 2);
        assert!(!ref_entry.contains_id("id2"));

        // 测试移除不存在的ID
        assert!(!ref_entry.remove_id("id999"));
        assert_eq!(ref_entry.count(), 2);
    }

    #[test]
    fn test_bundle_hash_computation() -> crate::Result<()> {
        let refs = vec![
            RefEntry::new(
                "B类型".to_string(),
                vec!["id2".to_string(), "id1".to_string()], // 无序
                None,
            ),
            RefEntry::new("A类型".to_string(), vec!["id3".to_string()], None),
        ];

        let cap2 = Cap2::new_for_test(
            "owner1".to_string(),
            refs,
            create_test_digest(),
            create_test_signature(),
        );

        // 计算哈希
        let computed_hash = cap2.compute_bundle_hash()?;
        assert_eq!(computed_hash.alg, "SHA-256");
        assert!(!computed_hash.hash.is_empty());

        // 验证相同数据产生相同哈希
        let refs2 = vec![
            RefEntry::new("A类型".to_string(), vec!["id3".to_string()], None),
            RefEntry::new(
                "B类型".to_string(),
                vec!["id1".to_string(), "id2".to_string()], // 不同顺序
                None,
            ),
        ];

        let cap2_2 = Cap2::new_for_test(
            "owner1".to_string(),
            refs2,
            create_test_digest(),
            create_test_signature(),
        );

        let computed_hash2 = cap2_2.compute_bundle_hash()?;
        assert_eq!(computed_hash.hash, computed_hash2.hash);

        Ok(())
    }

    #[test]
    fn test_add_ref_entry() -> crate::Result<()> {
        let mut cap2 = Cap2::new_for_test(
            "owner1".to_string(),
            vec![RefEntry::new(
                "类型A".to_string(),
                vec!["id1".to_string()],
                None,
            )],
            create_test_digest(),
            create_test_signature(),
        );

        // 添加新类型
        cap2.add_ref_entry(RefEntry::new(
            "类型B".to_string(),
            vec!["id2".to_string(), "id3".to_string()],
            None,
        ))?;

        assert_eq!(cap2.refs.len(), 2);
        assert_eq!(cap2.count_total_capsules(), 3);

        // 添加到已有类型
        cap2.add_ref_entry(RefEntry::new(
            "类型A".to_string(),
            vec!["id4".to_string(), "id1".to_string()], // id1重复
            None,
        ))?;

        assert_eq!(cap2.refs.len(), 2);
        assert_eq!(cap2.count_total_capsules(), 4); // id1不重复计算

        let type_a_refs = cap2.find_refs_by_type("类型A").unwrap();
        assert_eq!(type_a_refs.ids.len(), 2);
        assert!(type_a_refs.contains_id("id1"));
        assert!(type_a_refs.contains_id("id4"));

        Ok(())
    }

    #[test]
    fn test_cap2_summary() {
        let metadata = RefMetadata::new(
            2,
            Some("2025-09-01T00:00:00Z".to_string()),
            Some("2025-09-15T00:00:00Z".to_string()),
            Some("测试报告".to_string()),
        );

        let refs = vec![RefEntry::new(
            "类型A".to_string(),
            vec!["id1".to_string(), "id2".to_string()],
            Some(metadata),
        )];

        let cap2 = Cap2::new_for_test(
            "owner1".to_string(),
            refs,
            create_test_digest(),
            create_test_signature(),
        );

        // 验证基本属性
        assert_eq!(cap2.owner_id, "owner1");
        assert_eq!(cap2.get_report_types(), vec!["类型A".to_string()]);
        assert_eq!(cap2.refs.len(), 1);
        assert_eq!(cap2.count_total_capsules(), 2);
    }

    #[test]
    fn test_cap2_serialization() {
        let refs = vec![RefEntry::new(
            "测试类型".to_string(),
            vec!["id1".to_string()],
            None,
        )];

        let cap2 = Cap2::new_for_test(
            "owner1".to_string(),
            refs,
            create_test_digest(),
            create_test_signature(),
        );

        // 测试序列化和反序列化
        let json = serde_json::to_string(&cap2).unwrap();
        let deserialized: Cap2 = serde_json::from_str(&json).unwrap();

        assert_eq!(cap2.owner_id, deserialized.owner_id);
        assert_eq!(cap2.refs.len(), deserialized.refs.len());
        assert_eq!(cap2.bundle_hash.hash, deserialized.bundle_hash.hash);
    }
}
