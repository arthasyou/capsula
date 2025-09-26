// 权限相关模型
// 未来可以在这里添加更多权限相关的表模型
// 例如：user_permission (用户权限关联), permission_audit (权限审计日志) 等

pub mod atomic;
pub mod molecular;

// 重新导出常用的结构体，方便外部使用
pub use atomic::{get_default_atomic_permissions, AtomicPermission, PermissionCategory};
pub use molecular::{get_default_molecular_permissions, MolecularPermission, PermissionLevel};
