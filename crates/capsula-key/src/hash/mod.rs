use sha2::{Digest, Sha256, Sha512};

/// 支持的哈希算法
#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

/// 计算数据哈希值
///
/// # Arguments
/// * `data` - 要计算哈希的数据
/// * `algorithm` - 哈希算法
///
/// # Returns
/// * `Vec<u8>` - 哈希值字节数组
///
/// # Example
/// ```rust
/// use capsula_key::hash::{hash_data, HashAlgorithm};
///
/// let data = b"Hello, World!";
/// let hash = hash_data(data, HashAlgorithm::Sha256);
/// println!("SHA256: {}", hex::encode(&hash));
/// ```
pub fn hash_data(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
    }
}

/// 计算数据的SHA256哈希值（便捷函数）
///
/// # Arguments
/// * `data` - 要计算哈希的数据
///
/// # Returns
/// * `Vec<u8>` - SHA256哈希值
pub fn sha256(data: &[u8]) -> Vec<u8> {
    hash_data(data, HashAlgorithm::Sha256)
}

/// 计算数据的SHA512哈希值（便捷函数）
///
/// # Arguments
/// * `data` - 要计算哈希的数据
///
/// # Returns
/// * `Vec<u8>` - SHA512哈希值
pub fn sha512(data: &[u8]) -> Vec<u8> {
    hash_data(data, HashAlgorithm::Sha512)
}

/// 计算数据哈希值并返回十六进制字符串
///
/// # Arguments
/// * `data` - 要计算哈希的数据
/// * `algorithm` - 哈希算法
///
/// # Returns
/// * `String` - 哈希值的十六进制表示
pub fn hash_data_hex(data: &[u8], algorithm: HashAlgorithm) -> String {
    hex::encode(hash_data(data, algorithm))
}

/// 验证数据的哈希值
///
/// # Arguments
/// * `data` - 原始数据
/// * `expected_hash` - 期望的哈希值
/// * `algorithm` - 哈希算法
///
/// # Returns
/// * `bool` - 哈希值是否匹配
pub fn verify_hash(data: &[u8], expected_hash: &[u8], algorithm: HashAlgorithm) -> bool {
    let computed_hash = hash_data(data, algorithm);
    computed_hash == expected_hash
}

/// 计算多个数据块的组合哈希
///
/// # Arguments
/// * `data_blocks` - 数据块数组
/// * `algorithm` - 哈希算法
///
/// # Returns
/// * `Vec<u8>` - 组合哈希值
pub fn hash_multiple(data_blocks: &[&[u8]], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for data in data_blocks {
                hasher.update(data);
            }
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            for data in data_blocks {
                hasher.update(data);
            }
            hasher.finalize().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_data() {
        let data = b"Hello, World!";

        // 测试SHA256
        let hash256 = hash_data(data, HashAlgorithm::Sha256);
        assert_eq!(hash256.len(), 32);

        // 测试SHA512
        let hash512 = hash_data(data, HashAlgorithm::Sha512);
        assert_eq!(hash512.len(), 64);

        // 确保相同数据产生相同哈希
        let hash256_2 = hash_data(data, HashAlgorithm::Sha256);
        assert_eq!(hash256, hash256_2);
    }

    #[test]
    fn test_hash_data_hex() {
        let data = b"Test data";

        let hex256 = hash_data_hex(data, HashAlgorithm::Sha256);
        assert_eq!(hex256.len(), 64); // 32 bytes * 2

        let hex512 = hash_data_hex(data, HashAlgorithm::Sha512);
        assert_eq!(hex512.len(), 128); // 64 bytes * 2
    }

    #[test]
    fn test_verify_hash() {
        let data = b"Secret message";
        let hash = hash_data(data, HashAlgorithm::Sha256);

        assert!(verify_hash(data, &hash, HashAlgorithm::Sha256));
        assert!(!verify_hash(
            b"Different message",
            &hash,
            HashAlgorithm::Sha256
        ));
    }

    #[test]
    fn test_hash_multiple() {
        let data1 = b"Part 1";
        let data2 = b"Part 2";
        let data3 = b"Part 3";

        let combined_hash = hash_multiple(&[data1, data2, data3], HashAlgorithm::Sha256);

        // 验证结果与直接连接数据的哈希相同
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(data1);
        combined_data.extend_from_slice(data2);
        combined_data.extend_from_slice(data3);
        let direct_hash = hash_data(&combined_data, HashAlgorithm::Sha256);

        assert_eq!(combined_hash, direct_hash);
    }
}