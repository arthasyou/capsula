//! 临时文件管理模块
//!
//! 提供 RAII 模式的临时文件管理，确保文件在使用后自动清理

use std::path::{Path, PathBuf};
use std::fs;
use std::io;

/// 临时文件守卫，使用 RAII 模式自动清理文件
///
/// # 特性
/// - 自动清理：离开作用域时自动删除文件
/// - 路径访问：提供文件路径的只读访问
/// - 手动清理：可以提前手动删除文件
///
/// # 示例
/// ```rust
/// use capsula_bank::services::temp_file::TempFileGuard;
///
/// {
///     let temp = TempFileGuard::new("/tmp/myfile.txt");
///     // 使用文件...
///     std::fs::write(temp.path(), b"data").unwrap();
/// } // 文件在这里自动删除
/// ```
pub struct TempFileGuard {
    path: PathBuf,
    should_delete: bool,
}

impl TempFileGuard {
    /// 创建新的临时文件守卫
    ///
    /// # 参数
    /// - `path`: 临时文件路径
    ///
    /// # 注意
    /// 这个函数不会创建文件，只是注册路径用于后续清理
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            should_delete: true,
        }
    }

    /// 获取文件路径
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 手动删除文件
    ///
    /// # 返回
    /// - `Ok(true)`: 文件成功删除
    /// - `Ok(false)`: 文件不存在
    /// - `Err(e)`: 删除失败
    pub fn delete(&mut self) -> io::Result<bool> {
        if !self.should_delete {
            return Ok(false);
        }

        match fs::remove_file(&self.path) {
            Ok(_) => {
                self.should_delete = false;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.should_delete = false;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// 取消自动删除
    ///
    /// 调用此方法后，文件不会在 Drop 时自动删除
    pub fn keep(mut self) -> PathBuf {
        self.should_delete = false;
        self.path.clone()
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.should_delete {
            // 忽略删除错误，因为在 Drop 中我们无法处理错误
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl AsRef<Path> for TempFileGuard {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_temp_file_auto_cleanup() {
        let temp_path = "/tmp/test_temp_file_auto_cleanup.txt";

        {
            let temp = TempFileGuard::new(temp_path);
            let mut file = File::create(temp.path()).unwrap();
            file.write_all(b"test data").unwrap();
            assert!(temp.path().exists());
        }

        // 文件应该被自动删除
        assert!(!Path::new(temp_path).exists());
    }

    #[test]
    fn test_temp_file_manual_delete() {
        let temp_path = "/tmp/test_temp_file_manual_delete.txt";

        let mut temp = TempFileGuard::new(temp_path);
        let mut file = File::create(temp.path()).unwrap();
        file.write_all(b"test data").unwrap();

        // 手动删除
        let result = temp.delete();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
        assert!(!temp.path().exists());

        // 再次删除应该返回 false
        let result = temp.delete();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_temp_file_keep() {
        let temp_path = "/tmp/test_temp_file_keep.txt";

        {
            let temp = TempFileGuard::new(temp_path);
            let mut file = File::create(temp.path()).unwrap();
            file.write_all(b"test data").unwrap();

            // 调用 keep() 保留文件
            let _kept_path = temp.keep();
        }

        // 文件应该被保留
        assert!(Path::new(temp_path).exists());

        // 清理测试文件
        fs::remove_file(temp_path).unwrap();
    }
}
