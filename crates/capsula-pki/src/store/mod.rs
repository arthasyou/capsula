use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use capsula_crypto::{export_certificate, import_certificate, X509Certificate};
use time::OffsetDateTime;

use crate::{
    error::{PkiError, Result as PkiResult},
    types::{CertificateMetadata, CertificateStatus},
};

/// 存储后端接口
pub trait StorageBackend: Send + Sync {
    /// 保存证书
    fn save_certificate(&mut self, serial_number: &str, cert: &X509Certificate) -> PkiResult<()>;

    /// 加载证书
    fn load_certificate(&self, serial_number: &str) -> PkiResult<X509Certificate>;

    /// 删除证书
    fn delete_certificate(&mut self, serial_number: &str) -> PkiResult<()>;

    /// 列出所有证书序列号
    fn list_certificates(&self) -> PkiResult<Vec<String>>;

    /// 保存元数据
    fn save_metadata(
        &mut self,
        serial_number: &str,
        metadata: &CertificateMetadata,
    ) -> PkiResult<()>;

    /// 加载元数据
    fn load_metadata(&self, serial_number: &str) -> PkiResult<CertificateMetadata>;
}

/// 文件系统存储后端
pub struct FileSystemBackend {
    #[allow(dead_code)]
    root_path: PathBuf,
    certs_dir: PathBuf,
    metadata_dir: PathBuf,
}

impl FileSystemBackend {
    /// 创建新的文件系统存储后端
    pub fn new<P: AsRef<Path>>(root_path: P) -> PkiResult<Self> {
        let root_path = root_path.as_ref().to_path_buf();
        let certs_dir = root_path.join("certificates");
        let metadata_dir = root_path.join("metadata");

        // 创建目录
        fs::create_dir_all(&certs_dir)?;
        fs::create_dir_all(&metadata_dir)?;

        Ok(Self {
            root_path,
            certs_dir,
            metadata_dir,
        })
    }

    fn cert_path(&self, serial_number: &str) -> PathBuf {
        self.certs_dir.join(format!("{serial_number}.pem"))
    }

    fn metadata_path(&self, serial_number: &str) -> PathBuf {
        self.metadata_dir.join(format!("{serial_number}.json"))
    }
}

impl StorageBackend for FileSystemBackend {
    fn save_certificate(&mut self, serial_number: &str, cert: &X509Certificate) -> PkiResult<()> {
        let cert_pem = export_certificate(cert, "PEM")
            .map_err(|e| PkiError::StoreError(format!("Failed to export certificate: {e}")))?;

        let path = self.cert_path(serial_number);
        fs::write(path, cert_pem)?;

        Ok(())
    }

    fn load_certificate(&self, serial_number: &str) -> PkiResult<X509Certificate> {
        let path = self.cert_path(serial_number);
        if !path.exists() {
            return Err(PkiError::CertificateNotFound(serial_number.to_string()));
        }

        let cert_pem = fs::read(path)?;
        import_certificate(&cert_pem)
            .map_err(|e| PkiError::StoreError(format!("Failed to import certificate: {e}")))
    }

    fn delete_certificate(&mut self, serial_number: &str) -> PkiResult<()> {
        let cert_path = self.cert_path(serial_number);
        let metadata_path = self.metadata_path(serial_number);

        if cert_path.exists() {
            fs::remove_file(cert_path)?;
        }

        if metadata_path.exists() {
            fs::remove_file(metadata_path)?;
        }

        Ok(())
    }

    fn list_certificates(&self) -> PkiResult<Vec<String>> {
        let mut serials = Vec::new();

        for entry in fs::read_dir(&self.certs_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("pem") {
                if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                    serials.push(filename.to_string());
                }
            }
        }

        Ok(serials)
    }

    fn save_metadata(
        &mut self,
        serial_number: &str,
        metadata: &CertificateMetadata,
    ) -> PkiResult<()> {
        let path = self.metadata_path(serial_number);
        let json = serde_json::to_string_pretty(metadata)?;
        fs::write(path, json)?;
        Ok(())
    }

    fn load_metadata(&self, serial_number: &str) -> PkiResult<CertificateMetadata> {
        let path = self.metadata_path(serial_number);
        if !path.exists() {
            return Err(PkiError::CertificateNotFound(serial_number.to_string()));
        }

        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

/// 证书存储仓库
pub struct CertificateStore {
    backend: Box<dyn StorageBackend>,
    cache: HashMap<String, (X509Certificate, CertificateMetadata)>,
}

impl CertificateStore {
    /// 创建新的证书存储仓库
    pub fn new(backend: Box<dyn StorageBackend>) -> Self {
        Self {
            backend,
            cache: HashMap::new(),
        }
    }

    /// 创建文件系统存储仓库
    pub fn file_system<P: AsRef<Path>>(path: P) -> PkiResult<Self> {
        let backend = FileSystemBackend::new(path)?;
        Ok(Self::new(Box::new(backend)))
    }

    /// 存储证书
    pub fn store_certificate(&mut self, cert: &X509Certificate) -> PkiResult<()> {
        let serial_number = &cert.info.serial_number;

        // 检查证书是否已存在
        if self.cache.contains_key(serial_number)
            || self.backend.list_certificates()?.contains(serial_number)
        {
            return Err(PkiError::CertificateExists(serial_number.clone()));
        }

        // 创建元数据
        let metadata = CertificateMetadata {
            serial_number: serial_number.clone(),
            subject: cert.info.subject.common_name.clone(),
            issuer: cert.info.issuer.common_name.clone(),
            not_before: cert.info.not_before,
            not_after: cert.info.not_after,
            status: if cert.info.is_currently_valid() {
                CertificateStatus::Valid
            } else if cert.info.not_after < OffsetDateTime::now_utc() {
                CertificateStatus::Expired
            } else {
                CertificateStatus::NotYetValid
            },
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        // 保存到后端
        self.backend.save_certificate(serial_number, cert)?;
        self.backend.save_metadata(serial_number, &metadata)?;

        // 更新缓存
        self.cache
            .insert(serial_number.clone(), (cert.clone(), metadata));

        Ok(())
    }

    /// 获取证书
    pub fn get_certificate(&mut self, serial_number: &str) -> PkiResult<&X509Certificate> {
        // 检查缓存
        if !self.cache.contains_key(serial_number) {
            // 从后端加载
            let cert = self.backend.load_certificate(serial_number)?;
            let metadata = self.backend.load_metadata(serial_number)?;
            self.cache
                .insert(serial_number.to_string(), (cert, metadata));
        }

        Ok(&self.cache.get(serial_number).unwrap().0)
    }

    /// 获取证书元数据
    pub fn get_metadata(&mut self, serial_number: &str) -> PkiResult<&CertificateMetadata> {
        // 确保证书在缓存中
        self.get_certificate(serial_number)?;
        Ok(&self.cache.get(serial_number).unwrap().1)
    }

    /// 更新证书状态
    pub fn update_status(
        &mut self,
        serial_number: &str,
        status: CertificateStatus,
    ) -> PkiResult<()> {
        // 确保证书在缓存中
        self.get_certificate(serial_number)?;

        // 更新元数据
        let (_cert, metadata) = self.cache.get_mut(serial_number).unwrap();
        metadata.status = status;
        metadata.updated_at = OffsetDateTime::now_utc();

        // 保存到后端
        self.backend.save_metadata(serial_number, metadata)?;

        Ok(())
    }

    /// 删除证书
    pub fn delete_certificate(&mut self, serial_number: &str) -> PkiResult<()> {
        // 从缓存中删除
        self.cache.remove(serial_number);

        // 从后端删除
        self.backend.delete_certificate(serial_number)?;

        Ok(())
    }

    /// 列出所有证书
    pub fn list_certificates(&self) -> PkiResult<Vec<String>> {
        self.backend.list_certificates()
    }

    /// 搜索证书
    pub fn search_certificates<F>(&mut self, predicate: F) -> PkiResult<Vec<String>>
    where
        F: Fn(&CertificateMetadata) -> bool,
    {
        let serials = self.list_certificates()?;
        let mut results = Vec::new();

        for serial in serials {
            let metadata = self.get_metadata(&serial)?;
            if predicate(metadata) {
                results.push(serial);
            }
        }

        Ok(results)
    }

    /// 获取即将过期的证书（指定天数内）
    pub fn get_expiring_certificates(&mut self, days: i64) -> PkiResult<Vec<String>> {
        let threshold = OffsetDateTime::now_utc() + time::Duration::days(days);

        self.search_certificates(|metadata| {
            matches!(metadata.status, CertificateStatus::Valid) && metadata.not_after <= threshold
        })
    }

    /// 获取已过期的证书
    pub fn get_expired_certificates(&mut self) -> PkiResult<Vec<String>> {
        self.search_certificates(|metadata| matches!(metadata.status, CertificateStatus::Expired))
    }

    /// 清除缓存
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use capsula_crypto::EccKeyPair;
    use tempfile::TempDir;

    use super::*;
    use capsula_crypto::{create_certificate, CertificateSubject};

    #[test]
    #[ignore = "Certificate parsing is not fully implemented yet"]
    fn test_file_system_backend() {
        let temp_dir = TempDir::new().unwrap();
        let mut backend = FileSystemBackend::new(temp_dir.path()).unwrap();

        // 创建测试证书
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let subject = CertificateSubject::new("Test Certificate".to_string());
        let cert = create_certificate(&keypair, subject, None, 365, false).unwrap();
        let serial = &cert.info.serial_number;

        // 保存证书
        backend.save_certificate(serial, &cert).unwrap();

        // 加载证书
        let loaded_cert = backend.load_certificate(serial).unwrap();
        assert_eq!(cert.info.serial_number, loaded_cert.info.serial_number);

        // 列出证书
        let certs = backend.list_certificates().unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], *serial);

        // 删除证书
        backend.delete_certificate(serial).unwrap();
        assert!(backend.load_certificate(serial).is_err());
    }

    #[test]
    fn test_certificate_store() {
        let temp_dir = TempDir::new().unwrap();
        let mut store = CertificateStore::file_system(temp_dir.path()).unwrap();

        // 创建测试证书
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let subject = CertificateSubject::new("Test Certificate".to_string());
        let cert = create_certificate(&keypair, subject, None, 365, false).unwrap();
        let serial = cert.info.serial_number.clone();

        // 存储证书
        store.store_certificate(&cert).unwrap();

        // 获取证书
        let retrieved_cert = store.get_certificate(&serial).unwrap();
        assert_eq!(cert.info.serial_number, retrieved_cert.info.serial_number);

        // 获取元数据
        let metadata = store.get_metadata(&serial).unwrap();
        assert_eq!(metadata.serial_number, serial);
        assert!(matches!(metadata.status, CertificateStatus::Valid));

        // 尝试存储相同的证书应该失败
        assert!(store.store_certificate(&cert).is_err());

        // 删除证书
        store.delete_certificate(&serial).unwrap();
        assert!(store.get_certificate(&serial).is_err());
    }
}
