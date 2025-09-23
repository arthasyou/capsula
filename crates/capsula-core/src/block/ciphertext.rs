use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use capsula_crypto::{
    base64, encrypt_dek_with_algorithm, generate_id, generate_key,
    hash::sha256_hex,
    parse_algorithm_from_spki,
    symmetric::aead::{decrypt_aead, encrypt_aead, generate_nonce},
};
use capsula_key::key::{Key, KeyEncDec};
use pkcs8::{der::Decode, spki::SubjectPublicKeyInfoRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    error::{CoreError as Error, Result},
    integrity::digest::Digest,
    keyring::KeyWrap,
    EncAlg,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub aad: String,    // base64(aad) —— 由外层计算并传入（绑定上下文）
    pub enc: EncAlg,    // AES-256-GCM / ChaCha20-Poly1305
    pub nonce: String,  // base64(12 bytes)
    pub len: u64,       // 明文长度（字节）
    pub dek_id: String, // 对应的 DEK ID（外层用 KeyWrap 关联）
    pub storage: CipherStorage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CipherStorage {
    Inline {
        ct_b64: String, // base64(ciphertext||tag)
        ciphertext_len: Option<u64>,
        ciphertext_digest: Option<Digest>, // 传输校验可选
    },
    External {
        uri: String, // s3://... 或 https://...
        ciphertext_len: Option<u64>,
        ciphertext_digest: Option<Digest>,
    },
}

impl Ciphertext {
    /// Create a new Ciphertext with Inline storage by encrypting plaintext
    ///
    /// This function:
    /// 1. Generates a new Data Encryption Key (DEK)
    /// 2. Encrypts the DEK for the recipient and stores it in the keyring
    /// 3. Uses the DEK to encrypt the plaintext with AEAD
    /// 4. Creates a complete Ciphertext structure with Inline storage
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data
    /// * `enc_alg` - Encryption algorithm to use
    /// * `keyring` - Mutable keyring to store the encrypted DEK
    /// * `spki_der` - Recipient's public key in SPKI DER format
    ///
    /// # Returns
    /// A Ciphertext with Inline storage containing the encrypted data
    pub fn new_inline(
        plaintext: &[u8],
        aad: &[u8],
        enc_alg: EncAlg,
        keyring: &mut crate::keyring::Keyring,
        spki_der: &[u8],
    ) -> Result<Self> {
        // 1. Prepare encryption materials (DEK, keyring, nonce)
        let (dek, dek_id, nonce_bytes, nonce_b64) =
            prepare_encryption_materials(keyring, spki_der)?;

        // 2. Perform AEAD encryption and calculate metadata
        let (ciphertext_b64, _ciphertext_bytes, ciphertext_len, ciphertext_digest) =
            perform_encryption(plaintext, aad, &dek, &nonce_bytes)?;

        let ciphertext = Ciphertext {
            aad: base64::encode(aad),
            enc: enc_alg,
            nonce: nonce_b64,
            len: plaintext.len() as u64,
            dek_id: dek_id.clone(),
            storage: CipherStorage::Inline {
                ct_b64: ciphertext_b64,
                ciphertext_len: Some(ciphertext_len),
                ciphertext_digest,
            },
        };

        Ok(ciphertext)
    }

    /// Create a new Ciphertext with Inline storage using AES-256-GCM (default algorithm)
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data
    /// * `keyring` - Mutable keyring to store the encrypted DEK
    /// * `spki_der` - Recipient's public key in SPKI DER format
    ///
    /// # Returns
    /// A Ciphertext using AES-256-GCM encryption
    pub fn new_inline_aes(
        plaintext: &[u8],
        aad: &[u8],
        keyring: &mut crate::keyring::Keyring,
        spki_der: &[u8],
    ) -> Result<Self> {
        Self::new_inline(plaintext, aad, EncAlg::Aes256Gcm, keyring, spki_der)
    }

    /// Create a new Ciphertext with Inline storage using ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data
    /// * `keyring` - Mutable keyring to store the encrypted DEK
    /// * `spki_der` - Recipient's public key in SPKI DER format
    ///
    /// # Returns
    /// A Ciphertext using ChaCha20-Poly1305 encryption
    pub fn new_inline_chacha(
        plaintext: &[u8],
        aad: &[u8],
        keyring: &mut crate::keyring::Keyring,
        spki_der: &[u8],
    ) -> Result<Self> {
        Self::new_inline(plaintext, aad, EncAlg::ChaCha20Poly1305, keyring, spki_der)
    }

    /// Get the ciphertext as base64 string for decryption
    pub fn get_ciphertext_b64(&self) -> Result<&str> {
        match &self.storage {
            CipherStorage::Inline { ct_b64, .. } => Ok(ct_b64),
            CipherStorage::External { .. } => Err(Error::DataError(
                "External storage not yet supported for direct access".to_string(),
            )),
        }
    }

    /// Get the ciphertext bytes for decryption (decodes base64)
    pub fn get_ciphertext_bytes(&self) -> Result<Vec<u8>> {
        match &self.storage {
            CipherStorage::Inline { ct_b64, .. } => capsula_crypto::base64::decode(ct_b64)
                .map_err(|e| Error::DataError(format!("Failed to decode ciphertext: {}", e))),
            CipherStorage::External { .. } => Err(Error::DataError(
                "External storage not yet supported for direct access".to_string(),
            )),
        }
    }

    /// Create a new Ciphertext with External storage by encrypting a large file
    ///
    /// This function:
    /// 1. Generates a new Data Encryption Key (DEK)
    /// 2. Encrypts the DEK for the recipient and stores it in the keyring
    /// 3. Encrypts the file content using the DEK with AEAD
    /// 4. Saves the encrypted file to the specified output path
    /// 5. Creates a Ciphertext structure with External storage (uri will be empty initially)
    ///
    /// # Arguments
    /// * `input_file_path` - Path to the file to encrypt
    /// * `output_file_path` - Path where encrypted file will be saved
    /// * `aad` - Additional authenticated data
    /// * `enc_alg` - Encryption algorithm to use
    /// * `keyring` - Mutable keyring to store the encrypted DEK
    /// * `spki_der` - Recipient's public key in SPKI DER format
    ///
    /// # Returns
    /// A Ciphertext with External storage containing the encrypted file path
    pub fn new_external(
        input_file_path: &std::path::Path,
        output_file_path: &std::path::Path,
        aad: &[u8],
        enc_alg: EncAlg,
        keyring: &mut crate::keyring::Keyring,
        spki_der: &[u8],
    ) -> Result<Self> {
        // 1. Prepare encryption materials (DEK, keyring, nonce)
        let (dek, dek_id, nonce_bytes, nonce_b64) =
            prepare_encryption_materials(keyring, spki_der)?;

        // 2. Read input file
        let mut input_file = File::open(input_file_path)
            .map_err(|e| Error::DataError(format!("Failed to open input file: {}", e)))?;

        let mut plaintext = Vec::new();
        input_file
            .read_to_end(&mut plaintext)
            .map_err(|e| Error::DataError(format!("Failed to read input file: {}", e)))?;

        let plaintext_len = plaintext.len() as u64;

        // 3. Perform AEAD encryption and calculate metadata
        let (_ciphertext_b64, ciphertext_bytes, ciphertext_len, ciphertext_digest) =
            perform_encryption(&plaintext, aad, &dek, &nonce_bytes)?;

        // 4. Write encrypted content to output file
        let mut output_file = File::create(output_file_path)
            .map_err(|e| Error::DataError(format!("Failed to create output file: {}", e)))?;

        output_file
            .write_all(&ciphertext_bytes)
            .map_err(|e| Error::DataError(format!("Failed to write encrypted file: {}", e)))?;

        let ciphertext = Ciphertext {
            aad: base64::encode(aad),
            enc: enc_alg,
            nonce: nonce_b64,
            len: plaintext_len,
            dek_id: dek_id.clone(),
            storage: CipherStorage::External {
                uri: String::new(), // Empty initially, to be set by external upload process
                ciphertext_len: Some(ciphertext_len),
                ciphertext_digest,
            },
        };

        Ok(ciphertext)
    }

    /// Create a new Ciphertext with External storage using AES-256-GCM (default algorithm)
    ///
    /// # Arguments
    /// * `input_file_path` - Path to the file to encrypt
    /// * `output_file_path` - Path where encrypted file will be saved
    /// * `aad` - Additional authenticated data
    /// * `keyring` - Mutable keyring to store the encrypted DEK
    /// * `spki_der` - Recipient's public key in SPKI DER format
    ///
    /// # Returns
    /// A Ciphertext using AES-256-GCM encryption with External storage
    pub fn new_external_aes(
        input_file_path: &std::path::Path,
        output_file_path: &std::path::Path,
        aad: &[u8],
        keyring: &mut crate::keyring::Keyring,
        spki_der: &[u8],
    ) -> Result<Self> {
        Self::new_external(
            input_file_path,
            output_file_path,
            aad,
            EncAlg::Aes256Gcm,
            keyring,
            spki_der,
        )
    }

    /// Create a new Ciphertext with External storage using ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `input_file_path` - Path to the file to encrypt
    /// * `output_file_path` - Path where encrypted file will be saved
    /// * `aad` - Additional authenticated data
    /// * `keyring` - Mutable keyring to store the encrypted DEK
    /// * `spki_der` - Recipient's public key in SPKI DER format
    ///
    /// # Returns
    /// A Ciphertext using ChaCha20-Poly1305 encryption with External storage
    pub fn new_external_chacha(
        input_file_path: &std::path::Path,
        output_file_path: &std::path::Path,
        aad: &[u8],
        keyring: &mut crate::keyring::Keyring,
        spki_der: &[u8],
    ) -> Result<Self> {
        Self::new_external(
            input_file_path,
            output_file_path,
            aad,
            EncAlg::ChaCha20Poly1305,
            keyring,
            spki_der,
        )
    }

    /// Set the URI for External storage after the file has been uploaded
    ///
    /// This method should be called after the encrypted file has been uploaded to external storage
    /// to update the Ciphertext with the actual URI where the file can be accessed.
    ///
    /// # Arguments
    /// * `uri` - The URI where the encrypted file is stored (e.g., "s3://bucket/file" or "https://...")
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn set_external_uri(&mut self, uri: String) -> Result<()> {
        match &mut self.storage {
            CipherStorage::External {
                uri: storage_uri, ..
            } => {
                *storage_uri = uri;
                Ok(())
            }
            CipherStorage::Inline { .. } => Err(Error::DataError(
                "Cannot set URI on Inline storage type".to_string(),
            )),
        }
    }

    /// Get the URI for External storage
    ///
    /// # Returns
    /// The URI where the encrypted file is stored, or an error if storage is Inline
    pub fn get_external_uri(&self) -> Result<&str> {
        match &self.storage {
            CipherStorage::External { uri, .. } => Ok(uri),
            CipherStorage::Inline { .. } => Err(Error::DataError(
                "Cannot get URI from Inline storage type".to_string(),
            )),
        }
    }

    /// Decrypt inline stored ciphertext and return plaintext
    ///
    /// This method:
    /// 1. Retrieves and decrypts the DEK from the keyring
    /// 2. Decrypts the inline ciphertext using AEAD
    /// 3. Returns the decrypted plaintext
    ///
    /// # Arguments
    /// * `keyring` - Keyring containing the encrypted DEK
    /// * `key` - Key with decryption capability for DEK decryption
    ///
    /// # Returns
    /// The decrypted plaintext as bytes
    pub fn decrypt_inline<K>(&self, keyring: &crate::keyring::Keyring, key: &K) -> Result<Vec<u8>>
    where
        K: Key + KeyEncDec,
    {
        // 1. Verify this is inline storage
        let ct_b64 = match &self.storage {
            CipherStorage::Inline { ct_b64, .. } => ct_b64,
            CipherStorage::External { .. } => {
                return Err(Error::DataError(
                    "Cannot decrypt inline: ciphertext uses External storage".to_string(),
                ));
            }
        };

        // 2. Decrypt the DEK from keyring
        let dek = decrypt_dek_from_keyring(&self.dek_id, keyring, key)?;

        // 3. Decode AAD and nonce
        let aad = base64::decode(&self.aad)
            .map_err(|e| Error::DataError(format!("Failed to decode AAD: {}", e)))?;

        let nonce_bytes = base64::decode(&self.nonce)
            .map_err(|e| Error::DataError(format!("Failed to decode nonce: {}", e)))?;

        if nonce_bytes.len() != 12 {
            return Err(Error::DataError(format!(
                "Invalid nonce length: expected 12 bytes, got {}",
                nonce_bytes.len()
            )));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        // 4. Decrypt using AEAD
        let plaintext = decrypt_aead(ct_b64, &dek, &nonce, &aad)
            .map_err(|e| Error::DecapsulationError(format!("AEAD decryption failed: {}", e)))?;

        // 5. Verify plaintext length matches expected
        if plaintext.len() != self.len as usize {
            return Err(Error::IntegrityError(format!(
                "Decrypted plaintext length mismatch: expected {}, got {}",
                self.len,
                plaintext.len()
            )));
        }

        Ok(plaintext)
    }

    /// Decrypt external stored ciphertext from file and save to output file
    ///
    /// This method:
    /// 1. Retrieves and decrypts the DEK from the keyring
    /// 2. Reads the encrypted file (assuming it was already downloaded)
    /// 3. Decrypts the file content using AEAD
    /// 4. Writes the decrypted content to the output file
    ///
    /// # Arguments
    /// * `encrypted_file_path` - Path to the encrypted file (already downloaded)
    /// * `output_file_path` - Path where decrypted content will be saved
    /// * `keyring` - Keyring containing the encrypted DEK
    /// * `key` - Key with decryption capability for DEK decryption
    ///
    /// # Returns
    /// Success or error result
    pub fn decrypt_external<K>(
        &self,
        encrypted_file_path: &Path,
        output_file_path: &Path,
        keyring: &crate::keyring::Keyring,
        key: &K,
    ) -> Result<()>
    where
        K: Key + KeyEncDec,
    {
        // 1. Verify this is external storage
        match &self.storage {
            CipherStorage::External { .. } => {}
            CipherStorage::Inline { .. } => {
                return Err(Error::DataError(
                    "Cannot decrypt external: ciphertext uses Inline storage".to_string(),
                ));
            }
        }

        // 2. Decrypt the DEK from keyring
        let dek = decrypt_dek_from_keyring(&self.dek_id, keyring, key)?;

        // 3. Read encrypted file
        let mut encrypted_file = File::open(encrypted_file_path)
            .map_err(|e| Error::DataError(format!("Failed to open encrypted file: {}", e)))?;

        let mut encrypted_data = Vec::new();
        encrypted_file
            .read_to_end(&mut encrypted_data)
            .map_err(|e| Error::DataError(format!("Failed to read encrypted file: {}", e)))?;

        // 4. Decode AAD and nonce
        let aad = base64::decode(&self.aad)
            .map_err(|e| Error::DataError(format!("Failed to decode AAD: {}", e)))?;

        let nonce_bytes = base64::decode(&self.nonce)
            .map_err(|e| Error::DataError(format!("Failed to decode nonce: {}", e)))?;

        if nonce_bytes.len() != 12 {
            return Err(Error::DataError(format!(
                "Invalid nonce length: expected 12 bytes, got {}",
                nonce_bytes.len()
            )));
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        // 5. Convert encrypted data to base64 for AEAD decryption
        let encrypted_b64 = base64::encode(&encrypted_data);

        // 6. Decrypt using AEAD
        let plaintext = decrypt_aead(&encrypted_b64, &dek, &nonce, &aad)
            .map_err(|e| Error::DecapsulationError(format!("AEAD decryption failed: {}", e)))?;

        // 7. Verify plaintext length matches expected
        if plaintext.len() != self.len as usize {
            return Err(Error::IntegrityError(format!(
                "Decrypted plaintext length mismatch: expected {}, got {}",
                self.len,
                plaintext.len()
            )));
        }

        // 8. Write decrypted content to output file
        let mut output_file = File::create(output_file_path)
            .map_err(|e| Error::DataError(format!("Failed to create output file: {}", e)))?;

        output_file
            .write_all(&plaintext)
            .map_err(|e| Error::DataError(format!("Failed to write decrypted file: {}", e)))?;

        Ok(())
    }

    /// Decrypt inline stored ciphertext using AES-256-GCM
    ///
    /// Convenience wrapper for decrypt_inline with AES verification
    ///
    /// # Arguments
    /// * `keyring` - Keyring containing the encrypted DEK
    /// * `key` - Key with decryption capability for DEK decryption
    ///
    /// # Returns
    /// The decrypted plaintext as bytes
    pub fn decrypt_inline_aes<K>(
        &self,
        keyring: &crate::keyring::Keyring,
        key: &K,
    ) -> Result<Vec<u8>>
    where
        K: Key + KeyEncDec,
    {
        // Verify algorithm is AES-256-GCM
        if self.enc != EncAlg::Aes256Gcm {
            return Err(Error::DataError(format!(
                "Expected AES-256-GCM, found {:?}",
                self.enc
            )));
        }
        self.decrypt_inline(keyring, key)
    }

    /// Decrypt inline stored ciphertext using ChaCha20-Poly1305
    ///
    /// Convenience wrapper for decrypt_inline with ChaCha verification
    ///
    /// # Arguments
    /// * `keyring` - Keyring containing the encrypted DEK
    /// * `key` - Key with decryption capability for DEK decryption
    ///
    /// # Returns
    /// The decrypted plaintext as bytes
    pub fn decrypt_inline_chacha<K>(
        &self,
        keyring: &crate::keyring::Keyring,
        key: &K,
    ) -> Result<Vec<u8>>
    where
        K: Key + KeyEncDec,
    {
        // Verify algorithm is ChaCha20-Poly1305
        if self.enc != EncAlg::ChaCha20Poly1305 {
            return Err(Error::DataError(format!(
                "Expected ChaCha20-Poly1305, found {:?}",
                self.enc
            )));
        }
        self.decrypt_inline(keyring, key)
    }

    /// Decrypt external stored ciphertext using AES-256-GCM
    ///
    /// Convenience wrapper for decrypt_external with AES verification
    ///
    /// # Arguments
    /// * `encrypted_file_path` - Path to the encrypted file (already downloaded)
    /// * `output_file_path` - Path where decrypted content will be saved
    /// * `keyring` - Keyring containing the encrypted DEK
    /// * `key` - Key with decryption capability for DEK decryption
    ///
    /// # Returns
    /// Success or error result
    pub fn decrypt_external_aes<K>(
        &self,
        encrypted_file_path: &Path,
        output_file_path: &Path,
        keyring: &crate::keyring::Keyring,
        key: &K,
    ) -> Result<()>
    where
        K: Key + KeyEncDec,
    {
        // Verify algorithm is AES-256-GCM
        if self.enc != EncAlg::Aes256Gcm {
            return Err(Error::DataError(format!(
                "Expected AES-256-GCM, found {:?}",
                self.enc
            )));
        }
        self.decrypt_external(encrypted_file_path, output_file_path, keyring, key)
    }

    /// Decrypt external stored ciphertext using ChaCha20-Poly1305
    ///
    /// Convenience wrapper for decrypt_external with ChaCha verification
    ///
    /// # Arguments
    /// * `encrypted_file_path` - Path to the encrypted file (already downloaded)
    /// * `output_file_path` - Path where decrypted content will be saved
    /// * `keyring` - Keyring containing the encrypted DEK
    /// * `key` - Key with decryption capability for DEK decryption
    ///
    /// # Returns
    /// Success or error result
    pub fn decrypt_external_chacha<K>(
        &self,
        encrypted_file_path: &Path,
        output_file_path: &Path,
        keyring: &crate::keyring::Keyring,
        key: &K,
    ) -> Result<()>
    where
        K: Key + KeyEncDec,
    {
        // Verify algorithm is ChaCha20-Poly1305
        if self.enc != EncAlg::ChaCha20Poly1305 {
            return Err(Error::DataError(format!(
                "Expected ChaCha20-Poly1305, found {:?}",
                self.enc
            )));
        }
        self.decrypt_external(encrypted_file_path, output_file_path, keyring, key)
    }
}

/// Common DEK generation and keyring management for both Inline and External storage
///
/// This helper function:
/// 1. Generates a new Data Encryption Key (DEK) and DEK ID
/// 2. Parses the recipient's public key to determine the algorithm
/// 3. Encrypts the DEK using the recipient's public key
/// 4. Creates and stores the KeyWrap in the keyring
/// 5. Generates a random nonce for encryption
///
/// # Arguments
/// * `keyring` - Mutable keyring to store the encrypted DEK
/// * `spki_der` - Recipient's public key in SPKI DER format
///
/// # Returns
/// A tuple of (dek, dek_id, nonce_bytes, nonce_b64) for use in encryption
fn prepare_encryption_materials(
    keyring: &mut crate::keyring::Keyring,
    spki_der: &[u8],
) -> Result<([u8; 32], String, [u8; 12], String)> {
    // 1. Generate DEK and DEK ID
    let dek = generate_key();
    let dek_id = generate_id("dek");

    // 2. Parse SPKI DER to get algorithm and public key
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| Error::DataError(format!("Invalid SPKI DER: {}", e)))?;

    let algorithm = parse_algorithm_from_spki(&spki.algorithm)
        .map_err(|e| Error::DataError(format!("Algorithm parsing failed: {}", e)))?;

    // 3. Encrypt DEK based on algorithm
    let (encrypted_dek, algorithm_name) = encrypt_dek_with_algorithm(&dek, algorithm, spki_der)
        .map_err(|e| Error::DataError(format!("DEK encryption failed: {}", e)))?;

    let cek_wrapped = base64::encode(encrypted_dek);

    // 4. Compute recipient key ID (using SHA-256 hash of public key)
    let recipient_key_id = {
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        hex::encode(hasher.finalize())[.. 16].to_string()
    };

    // 5. Create KeyWrap and add to keyring
    let key_wrap = KeyWrap::new(recipient_key_id, algorithm_name, cek_wrapped);
    keyring.insert(dek_id.clone(), key_wrap);

    // 6. Generate random nonce
    let nonce_bytes = generate_nonce();
    let nonce_b64 = base64::encode(&nonce_bytes);

    Ok((dek, dek_id, nonce_bytes, nonce_b64))
}

/// Common encryption helper that handles AEAD encryption and metadata calculation
///
/// This helper function:
/// 1. Encrypts plaintext using AEAD with provided DEK and nonce
/// 2. Calculates ciphertext metadata (length and SHA-256 digest)
/// 3. Returns encrypted data and metadata for use in storage
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data
/// * `dek` - Data Encryption Key
/// * `nonce_bytes` - Nonce for encryption
///
/// # Returns
/// A tuple of (ciphertext_b64, ciphertext_bytes, ciphertext_len, ciphertext_digest)
fn perform_encryption(
    plaintext: &[u8],
    aad: &[u8],
    dek: &[u8; 32],
    nonce_bytes: &[u8; 12],
) -> Result<(
    String,
    Vec<u8>,
    u64,
    Option<crate::integrity::digest::Digest>,
)> {
    // 1. Encrypt the plaintext using AEAD
    let ciphertext_b64 = encrypt_aead(plaintext, dek, nonce_bytes, aad)
        .map_err(|e| Error::EncapsulationError(format!("Encryption failed: {}", e)))?;

    // 2. Decode ciphertext to get raw bytes for metadata calculation
    let ciphertext_bytes = base64::decode(&ciphertext_b64)
        .map_err(|e| Error::DataError(format!("Failed to decode ciphertext: {}", e)))?;

    // 3. Calculate ciphertext metadata
    let ciphertext_len = ciphertext_bytes.len() as u64;
    let ciphertext_digest = Some(crate::integrity::digest::Digest {
        alg: "SHA-256".to_string(),
        hash: sha256_hex(&ciphertext_bytes),
    });

    Ok((
        ciphertext_b64,
        ciphertext_bytes,
        ciphertext_len,
        ciphertext_digest,
    ))
}

/// Common DEK decryption helper for both Inline and External storage
///
/// This helper function:
/// 1. Retrieves the encrypted DEK from the keyring using dek_id
/// 2. Decrypts the DEK using the provided key
/// 3. Returns the decrypted DEK for use in AEAD decryption
///
/// # Arguments
/// * `dek_id` - ID of the DEK to retrieve from keyring
/// * `keyring` - Keyring containing the encrypted DEK
/// * `key` - Key with decryption capability for DEK decryption
///
/// # Returns
/// The decrypted 32-byte DEK
fn decrypt_dek_from_keyring<K>(
    dek_id: &str,
    keyring: &crate::keyring::Keyring,
    key: &K,
) -> Result<[u8; 32]>
where
    K: Key + KeyEncDec,
{
    // 1. Get the KeyWrap from keyring
    let key_wrap = keyring.get(dek_id).ok_or_else(|| {
        Error::DecapsulationError(format!("DEK with ID '{}' not found in keyring", dek_id))
    })?;

    // 2. Decode the wrapped DEK from base64
    let encrypted_dek = base64::decode(&key_wrap.cek_wrapped)
        .map_err(|e| Error::DataError(format!("Failed to decode wrapped DEK: {}", e)))?;

    // 3. Decrypt the DEK using the key
    let dek_bytes = key
        .decrypt(&encrypted_dek)
        .map_err(|e| Error::DecapsulationError(format!("Failed to decrypt DEK: {}", e)))?;

    // 4. Convert to fixed-size array
    if dek_bytes.len() != 32 {
        return Err(Error::DataError(format!(
            "Invalid DEK length: expected 32 bytes, got {}",
            dek_bytes.len()
        )));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);
    Ok(dek)
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use capsula_key::{Key, RsaKey};

    use super::*;

    // Simple helper for creating test keys - this focuses on testing ciphertext logic, not key generation
    fn create_test_key() -> Result<(RsaKey, Vec<u8>)> {
        let key_pair = RsaKey::generate_2048()?;
        let public_keys = key_pair.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| Error::DataError("No signing key found".to_string()))?;
        Ok((key_pair, signing_key_entry.spki_der.clone()))
    }

    #[test]
    fn test_ciphertext_inline_storage_structure() -> Result<()> {
        let plaintext = b"Test inline storage";
        let aad = b"test_aad";
        let mut keyring = HashMap::new();
        let (_, public_key_spki) = create_test_key()?;

        let ciphertext =
            Ciphertext::new_inline_aes(plaintext, aad, &mut keyring, &public_key_spki)?;

        // Verify core structure
        assert_eq!(ciphertext.enc, EncAlg::Aes256Gcm);
        assert_eq!(ciphertext.len, plaintext.len() as u64);
        assert!(!ciphertext.dek_id.is_empty());
        assert!(!ciphertext.aad.is_empty());
        assert!(!ciphertext.nonce.is_empty());

        // Verify inline storage
        match &ciphertext.storage {
            CipherStorage::Inline { ct_b64, ciphertext_len, ciphertext_digest } => {
                assert!(!ct_b64.is_empty());
                assert!(ciphertext_len.is_some());
                assert!(ciphertext_digest.is_some());
            }
            _ => panic!("Expected Inline storage"),
        }

        // Verify keyring integration
        assert!(keyring.contains_key(&ciphertext.dek_id));
        assert_eq!(keyring.len(), 1);

        Ok(())
    }

    #[test]
    fn test_ciphertext_external_storage_and_uri_management() -> Result<()> {
        let test_data = b"Test external storage";
        let aad = b"external_aad";
        let mut keyring = HashMap::new();
        let (_, public_key_spki) = create_test_key()?;

        // Create temporary files for testing
        let input_path = std::path::Path::new("/tmp/test_external_input.txt");
        let output_path = std::path::Path::new("/tmp/test_external_output.enc");
        let _ = std::fs::remove_file(input_path);
        let _ = std::fs::remove_file(output_path);

        std::fs::write(input_path, test_data)
            .map_err(|e| Error::DataError(format!("Failed to write test file: {}", e)))?;

        let mut ciphertext = Ciphertext::new_external_aes(
            input_path,
            output_path,
            aad,
            &mut keyring,
            &public_key_spki,
        )?;

        // Verify external storage structure
        match &ciphertext.storage {
            CipherStorage::External { uri, ciphertext_len, ciphertext_digest } => {
                assert!(uri.is_empty()); // Initially empty
                assert!(ciphertext_len.is_some());
                assert!(ciphertext_digest.is_some());
            }
            _ => panic!("Expected External storage"),
        }

        // Test URI management
        assert_eq!(ciphertext.get_external_uri()?, "");
        
        let test_uri = "s3://bucket/file.enc";
        ciphertext.set_external_uri(test_uri.to_string())?;
        assert_eq!(ciphertext.get_external_uri()?, test_uri);

        // Test that inline storage rejects URI operations
        let mut inline_ciphertext = Ciphertext::new_inline_aes(
            b"inline", aad, &mut HashMap::new(), &public_key_spki
        )?;
        assert!(inline_ciphertext.set_external_uri("fail".to_string()).is_err());
        assert!(inline_ciphertext.get_external_uri().is_err());

        // Clean up
        let _ = std::fs::remove_file(input_path);
        let _ = std::fs::remove_file(output_path);

        Ok(())
    }

    #[test]
    fn test_ciphertext_algorithm_support() -> Result<()> {
        let plaintext = b"Test algorithm support";
        let aad = b"test_aad";
        let mut aes_keyring = HashMap::new();
        let mut chacha_keyring = HashMap::new();
        let (_, public_key_spki) = create_test_key()?;

        // Test both algorithms
        let aes_ciphertext = Ciphertext::new_inline_aes(
            plaintext, aad, &mut aes_keyring, &public_key_spki
        )?;
        let chacha_ciphertext = Ciphertext::new_inline_chacha(
            plaintext, aad, &mut chacha_keyring, &public_key_spki
        )?;

        // Verify algorithm types
        assert_eq!(aes_ciphertext.enc, EncAlg::Aes256Gcm);
        assert_eq!(chacha_ciphertext.enc, EncAlg::ChaCha20Poly1305);

        // Verify different outputs
        assert_ne!(aes_ciphertext.get_ciphertext_b64()?, chacha_ciphertext.get_ciphertext_b64()?);
        assert_ne!(aes_ciphertext.dek_id, chacha_ciphertext.dek_id);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() -> Result<()> {
        let original_data = b"Round trip test data";
        let aad = b"round_trip_aad";
        let mut keyring = HashMap::new();
        let (key_pair, public_key_spki) = create_test_key()?;

        // Test inline round trip
        let ciphertext = Ciphertext::new_inline_aes(
            original_data, aad, &mut keyring, &public_key_spki
        )?;
        let decrypted = ciphertext.decrypt_inline_aes(&keyring, &key_pair)?;
        assert_eq!(decrypted, original_data);

        Ok(())
    }

    #[test]
    fn test_algorithm_mismatch_error() -> Result<()> {
        let plaintext = b"Test error handling";
        let aad = b"test_aad";
        let mut keyring = HashMap::new();
        let (key_pair, public_key_spki) = create_test_key()?;

        // Create AES ciphertext but try to decrypt with ChaCha method
        let aes_ciphertext = Ciphertext::new_inline_aes(
            plaintext, aad, &mut keyring, &public_key_spki
        )?;
        let result = aes_ciphertext.decrypt_inline_chacha(&keyring, &key_pair);
        assert!(result.is_err()); // Should fail due to algorithm mismatch

        Ok(())
    }
}
