use capsula_crypto::base64;
use capsula_key::key::{Key, KeySign};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    error::{CoreError as Error, Result},
    integrity::{digest::Digest, signature::Signature},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorProof {
    pub subject: Digest,             // 明文指纹（或 Merkle 根）
    #[serde(default)]
    pub schema_hash: Option<String>, // 可选：明文结构/规范哈希
    #[serde(default)]
    pub issued_at: Option<String>, // 可选：RFC3339 出具时间
    pub signature: Signature, // 作者对 {subject, schema_hash?, issued_at?} 的脱离式签名
}

impl AuthorProof {
    /// Create a new AuthorProof by signing the plaintext with the provided signing key
    ///
    /// This method:
    /// 1. Computes SHA-256 digest of the plaintext
    /// 2. Prepares signing data structure
    /// 3. Signs the data using the provided key
    /// 4. Creates AuthorProof with signature and metadata
    ///
    /// # Arguments
    /// * `plaintext` - Data to create proof for
    /// * `signing_key` - Key with signing capability
    /// * `schema_hash` - Optional schema hash for structured data
    ///
    /// # Returns
    /// A new AuthorProof with signature
    pub fn create<K>(
        plaintext: &[u8],
        signing_key: &K,
        schema_hash: Option<String>,
    ) -> Result<Self>
    where
        K: Key + KeySign,
    {
        // 1. Compute plaintext digest
        let subject = Self::compute_digest(plaintext)?;

        // 2. Create issued_at timestamp
        let issued_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| Error::DataError(format!("Failed to format timestamp: {}", e)))?,
        );

        // 3. Prepare signing data
        let signing_data = Self::prepare_signing_data(&subject, &schema_hash, &issued_at)?;

        // 4. Sign the data
        let signature_bytes = signing_key
            .sign(&signing_data)
            .map_err(|e| Error::SignatureError(format!("Signing failed: {}", e)))?;

        // 5. Get algorithm from signing key
        let signature_alg = Self::get_signature_algorithm_name(signing_key);

        // 6. Create signature structure
        let signature = Signature {
            alg: signature_alg,
            sig: base64::encode(signature_bytes),
            author_hint: signing_key.key_id_hex(),
            cert_hint: None,
        };

        Ok(Self {
            subject,
            schema_hash,
            issued_at,
            signature,
        })
    }

    /// Verify the proof against the expected plaintext using the provided verification key
    ///
    /// This method:
    /// 1. Computes digest of the expected plaintext
    /// 2. Compares with the digest in the proof
    /// 3. Reconstructs signing data
    /// 4. Verifies signature using the provided key
    ///
    /// # Arguments
    /// * `expected_plaintext` - Expected plaintext to verify against
    /// * `verification_key_spki` - Public key in SPKI DER format for signature verification
    ///
    /// # Returns
    /// True if proof is valid, false otherwise
    pub fn verify(&self, expected_plaintext: &[u8], verification_key_spki: &[u8]) -> Result<bool> {
        // 1. Compute expected digest
        let expected_digest = Self::compute_digest(expected_plaintext)?;

        // 2. Verify digest matches
        if expected_digest.hash != self.subject.hash {
            return Ok(false);
        }

        // 3. Prepare signing data
        let signing_data = Self::prepare_signing_data(
            &self.subject,
            &self.schema_hash,
            &self.issued_at,
        )?;

        // 4. Decode signature
        let signature_bytes = base64::decode(&self.signature.sig)
            .map_err(|e| Error::DataError(format!("Failed to decode signature: {}", e)))?;

        // 5. Verify signature using crypto module
        let is_valid = capsula_crypto::verify_signature(
            verification_key_spki,
            &signing_data,
            &signature_bytes,
        )
        .map_err(|e| Error::SignatureError(format!("Signature verification failed: {}", e)))?;

        Ok(is_valid)
    }

    /// Compute SHA-256 digest of plaintext
    fn compute_digest(plaintext: &[u8]) -> Result<Digest> {
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let hash_bytes = hasher.finalize();
        let hash = base64::encode(hash_bytes);

        Ok(Digest {
            alg: "SHA-256".to_string(),
            hash,
        })
    }

    /// Prepare data for signing by creating a canonical representation
    fn prepare_signing_data(
        subject: &Digest,
        schema_hash: &Option<String>,
        issued_at: &Option<String>,
    ) -> Result<Vec<u8>> {
        // Create a canonical representation of the signing data
        let signing_obj = serde_json::json!({
            "subject": subject,
            "schema_hash": schema_hash,
            "issued_at": issued_at
        });

        let json = serde_json::to_string(&signing_obj)
            .map_err(|e| Error::JsonError(e))?;
        Ok(json.into_bytes())
    }

    /// Get signature algorithm name from signing key
    fn get_signature_algorithm_name<K: Key>(signing_key: &K) -> String {
        match signing_key.algorithm() {
            capsula_key::key::Algorithm::Ed25519 => "Ed25519".to_string(),
            capsula_key::key::Algorithm::P256 => "ES256".to_string(),
            capsula_key::key::Algorithm::Rsa => "RS256".to_string(),
            capsula_key::key::Algorithm::X25519 => {
                // X25519 is for key agreement, not signing
                "UNKNOWN".to_string()
            }
        }
    }

    /// Get the digest hash for comparison
    pub fn get_digest_hash(&self) -> &str {
        &self.subject.hash
    }

    /// Get the signature algorithm
    pub fn get_signature_algorithm(&self) -> &str {
        &self.signature.alg
    }

    /// Get the author hint (key ID)
    pub fn get_author_hint(&self) -> &str {
        &self.signature.author_hint
    }

    /// Get the issued timestamp
    pub fn get_issued_at(&self) -> Option<&str> {
        self.issued_at.as_deref()
    }
}
