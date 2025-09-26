use serde::{Deserialize, Serialize};

/// 权限分类
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCategory {
    ReadEdit,
    Usage,
    Transfer,
    Supervision,
}

/// 原子权限定义
/// position 字段表示该原子权限在分子权限布尔向量中的位置（0-13）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicPermission {
    pub atom_id: String,
    pub name: String,
    pub position: u8, // 在权限向量中的位置（0-13）
    pub category: PermissionCategory,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>, // Unix timestamp, 由数据库自动生成
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>, // Unix timestamp, 由数据库自动生成
}

impl AtomicPermission {
    /// 创建一个新的原子权限
    pub fn new(
        atom_id: impl Into<String>,
        name: impl Into<String>,
        position: u8,
        category: PermissionCategory,
        description: impl Into<String>,
    ) -> Self {
        Self {
            atom_id: atom_id.into(),
            name: name.into(),
            position,
            category,
            description: description.into(),
            created_at: None, // 由数据库自动生成
            updated_at: None, // 由数据库自动生成
        }
    }
}

/// 获取默认的原子权限列表
/// 权限向量顺序：[阅读, 注释, 编辑胶囊, 修改原始数据, 明文用, 黑盒用, 统计用, 导出, 授权, 转授, 撤销, 拥有, 转让, 追溯]
pub fn get_default_atomic_permissions() -> Vec<AtomicPermission> {
    vec![
        // 1. 阅读编辑类
        AtomicPermission::new(
            "read",
            "阅读",
            0,  // 位置0
            PermissionCategory::ReadEdit,
            "查看数据胶囊内容，包括元数据和浓缩概览的查看，原始数据的查看不属于数据胶囊范畴",
        ),
        AtomicPermission::new(
            "annotate",
            "注释",
            1,  // 位置1
            PermissionCategory::ReadEdit,
            "添加注释说明，但不修改元数据",
        ),
        AtomicPermission::new(
            "edit_capsule",
            "编辑胶囊",
            2,  // 位置2
            PermissionCategory::ReadEdit,
            "数据银行的权利，用于封装数据胶囊时，生成和编辑其元数据和浓缩概览",
        ),
        AtomicPermission::new(
            "modify_raw",
            "修改原始数据",
            3,  // 位置3
            PermissionCategory::ReadEdit,
            "采集者创建原始数据，和发送给数据银行前的修改，其他实体无此权利",
        ),
        // 2. 使用类
        AtomicPermission::new(
            "plaintext_use",
            "明文用",
            4,  // 位置4
            PermissionCategory::Usage,
            "明文直接使用",
        ),
        AtomicPermission::new(
            "blackbox_use",
            "黑盒用",
            5,  // 位置5
            PermissionCategory::Usage,
            "可用不可见，可将数据、数据回答直接传输到APP",
        ),
        AtomicPermission::new(
            "statistical_use",
            "统计用",
            6,  // 位置6
            PermissionCategory::Usage,
            "用于统计处理，只传输和展现统计结果",
        ),
        // 3. 流转类
        AtomicPermission::new(
            "export",
            "导出",
            7,  // 位置7
            PermissionCategory::Transfer,
            "数据下载导出",
        ),
        AtomicPermission::new(
            "authorize",
            "授权",
            8,  // 位置8
            PermissionCategory::Transfer,
            "拥有将该数据胶囊进行授权的能力",
        ),
        AtomicPermission::new(
            "delegate",
            "转授",
            9,  // 位置9
            PermissionCategory::Transfer,
            "数据拥有者将授权能力，委托给数据银行，进行转授权",
        ),
        AtomicPermission::new(
            "revoke",
            "撤销",
            10, // 位置10
            PermissionCategory::Transfer,
            "撤销已授予权限",
        ),
        AtomicPermission::new(
            "own",
            "拥有",
            11, // 位置11
            PermissionCategory::Transfer,
            "表达拥有该数据胶囊，数据拥有者的所有权的核心",
        ),
        AtomicPermission::new(
            "transfer",
            "转让",
            12, // 位置12
            PermissionCategory::Transfer,
            "转让所有权，仅1次",
        ),
        // 4. 监督类
        AtomicPermission::new(
            "trace",
            "追溯",
            13, // 位置13
            PermissionCategory::Supervision,
            "拥有对日志的追溯权利",
        ),
    ]
}