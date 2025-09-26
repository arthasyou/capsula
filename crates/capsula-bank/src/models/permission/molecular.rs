use serde::{Deserialize, Serialize};

/// 权限级别
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    Owner,
    Admin,
    Editor,
    User,
    Viewer,
    Auditor,
}

/// 分子权限定义
/// atomic_permissions 是一个长度为14的布尔数组，对应14个原子权限：
/// [阅读, 注释, 编辑胶囊, 修改原始数据, 明文用, 黑盒用, 统计用, 导出, 授权, 转授, 撤销, 拥有, 转让,
/// 追溯]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MolecularPermission {
    pub molecule_id: String,
    pub name: String,
    pub description: String,
    pub atomic_permissions: Vec<bool>, // 14个布尔值的权限向量
    pub permission_level: PermissionLevel,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>, // Unix timestamp, 由数据库自动生成
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>, // Unix timestamp, 由数据库自动生成
}

fn default_true() -> bool {
    true
}

impl MolecularPermission {
    /// 创建一个新的分子权限，初始化为全false的14位权限向量
    pub fn new(
        molecule_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        permission_level: PermissionLevel,
    ) -> Self {
        Self {
            molecule_id: molecule_id.into(),
            name: name.into(),
            description: description.into(),
            atomic_permissions: vec![false; 14], // 初始化14个false
            permission_level,
            is_active: true,
            created_at: None, // 由数据库自动生成
            updated_at: None, // 由数据库自动生成
        }
    }

    /// 使用布尔向量设置原子权限
    /// 向量顺序：[阅读, 注释, 编辑胶囊, 修改原始数据, 明文用, 黑盒用, 统计用, 导出, 授权, 转授,
    /// 撤销, 拥有, 转让, 追溯]
    pub fn with_atomic_permissions(mut self, permissions: Vec<bool>) -> Self {
        if permissions.len() == 14 {
            self.atomic_permissions = permissions;
        }
        self
    }
}

/// 获取默认的分子权限列表
/// 基于《数据胶囊权属向量码》文档中的权限矩阵表
pub fn get_default_molecular_permissions() -> Vec<MolecularPermission> {
    // 权限向量顺序：[阅读, 注释, 编辑胶囊, 修改原始数据, 明文用, 黑盒用, 统计用, 导出, 授权, 转授,
    // 撤销, 拥有, 转让, 追溯]
    vec![
        // 1. 修改权
        MolecularPermission::new(
            "modify_right",
            "修改权",
            "采集者修改原始数据的权限",
            PermissionLevel::Editor,
        )
        .with_atomic_permissions(vec![
            false, false, false, true, false, false, false, false, false, false, false, false,
            false, false,
        ]),
        // 2. 解释权
        MolecularPermission::new(
            "interpret_right",
            "解释权",
            "阅读并添加注释的权限",
            PermissionLevel::Editor,
        )
        .with_atomic_permissions(vec![
            true, true, false, false, false, false, false, false, false, false, false, false,
            false, false,
        ]),
        // 3. 所有权
        MolecularPermission::new(
            "ownership",
            "所有权",
            "数据拥有者的完整权限集，注意数据所有者无法编辑修改数据胶囊",
            PermissionLevel::Owner,
        )
        .with_atomic_permissions(vec![
            true, false, false, false, true, false, true, true, true, true, true, true, true, false,
        ]),
        // 4. 编辑权
        MolecularPermission::new(
            "edit_right",
            "编辑权",
            "数据银行编辑数据胶囊的权限",
            PermissionLevel::Admin,
        )
        .with_atomic_permissions(vec![
            true, false, true, false, false, false, false, false, false, false, false, false,
            false, false,
        ]),
        // 5. 使用权-无限制
        MolecularPermission::new(
            "unlimited_use",
            "使用权-无限制",
            "完整的数据使用权限",
            PermissionLevel::User,
        )
        .with_atomic_permissions(vec![
            true, false, false, false, true, false, true, true, false, false, false, false, false,
            false,
        ]),
        // 6. 使用权-不可多条统计
        MolecularPermission::new(
            "limited_statistical_use",
            "使用权-不可多条统计",
            "限制统计功能的使用权限",
            PermissionLevel::User,
        )
        .with_atomic_permissions(vec![
            true, false, false, false, true, false, false, true, false, false, false, false, false,
            false,
        ]),
        // 7. 使用权-可用不可看
        MolecularPermission::new(
            "blackbox_only",
            "使用权-可用不可看",
            "仅黑盒使用，不可查看原始数据",
            PermissionLevel::User,
        )
        .with_atomic_permissions(vec![
            false, false, false, false, false, true, false, false, false, false, false, false,
            false, false,
        ]),
        // 8. 仅阅读权
        MolecularPermission::new(
            "read_only",
            "仅阅读权",
            "只能查看，不能进行任何操作",
            PermissionLevel::Viewer,
        )
        .with_atomic_permissions(vec![
            true, false, false, false, false, false, false, false, false, false, false, false,
            false, false,
        ]),
        // 9. 转让权
        MolecularPermission::new(
            "transfer_right",
            "转让权",
            "转让所有权的权限",
            PermissionLevel::Owner,
        )
        .with_atomic_permissions(vec![
            false, false, false, false, false, false, false, false, false, false, false, false,
            true, false,
        ]),
        // 10. 追溯权
        MolecularPermission::new(
            "audit_right",
            "追溯权",
            "查看和追溯操作日志的权限",
            PermissionLevel::Auditor,
        )
        .with_atomic_permissions(vec![
            true, false, false, false, false, false, false, false, false, false, false, false,
            false, true,
        ]),
    ]
}
