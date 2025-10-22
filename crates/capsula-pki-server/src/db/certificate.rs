use chrono::Utc;
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::{
    error::{AppError, Result},
    models::certificate::{CertificateRecord, CertificateStatus, UserCertificateQuery},
};

/// Certificate database operations
pub struct CertificateService {
    db: Surreal<Client>,
}

impl CertificateService {
    pub fn new(db: Surreal<Client>) -> Self {
        Self { db }
    }

    /// Create certificate table
    pub async fn create_table(&self) -> Result<()> {
        // Drop existing table first to ensure clean schema
        let _drop_result = self
            .db
            .query("REMOVE TABLE IF EXISTS certificates;")
            .await
            .map_err(|e| AppError::DbError(e))?;

        let _result = self
            .db
            .query(
                "
                DEFINE TABLE certificates SCHEMAFULL;
                DEFINE FIELD certificate_id ON TABLE certificates TYPE string;
                DEFINE FIELD user_id ON TABLE certificates TYPE string;
                DEFINE FIELD serial_number ON TABLE certificates TYPE string;
                DEFINE FIELD common_name ON TABLE certificates TYPE string;
                DEFINE FIELD organization ON TABLE certificates TYPE option<string>;
                DEFINE FIELD organizational_unit ON TABLE certificates TYPE option<string>;
                DEFINE FIELD country ON TABLE certificates TYPE option<string>;
                DEFINE FIELD state ON TABLE certificates TYPE option<string>;
                DEFINE FIELD locality ON TABLE certificates TYPE option<string>;
                DEFINE FIELD email ON TABLE certificates TYPE option<string>;
                DEFINE FIELD certificate_pem ON TABLE certificates TYPE string;
                DEFINE FIELD private_key_pem ON TABLE certificates TYPE option<string>;
                DEFINE FIELD key_algorithm ON TABLE certificates TYPE string;
                DEFINE FIELD key_size ON TABLE certificates TYPE option<number>;
                DEFINE FIELD subject_dn ON TABLE certificates TYPE string;
                DEFINE FIELD issuer_dn ON TABLE certificates TYPE string;
                DEFINE FIELD not_before ON TABLE certificates TYPE number;
                DEFINE FIELD not_after ON TABLE certificates TYPE number;
                DEFINE FIELD status ON TABLE certificates TYPE string;
                DEFINE FIELD created_at ON TABLE certificates TYPE number;
                DEFINE FIELD revoked_at ON TABLE certificates TYPE option<number>;
                DEFINE FIELD revocation_reason ON TABLE certificates TYPE option<string>;
                DEFINE FIELD revocation_comment ON TABLE certificates TYPE option<string>;
                
                DEFINE INDEX idx_certificate_id ON TABLE certificates COLUMNS certificate_id \
                 UNIQUE;
                DEFINE INDEX idx_user_id ON TABLE certificates COLUMNS user_id;
                DEFINE INDEX idx_serial_number ON TABLE certificates COLUMNS serial_number UNIQUE;
                DEFINE INDEX idx_status ON TABLE certificates COLUMNS status;
                DEFINE INDEX idx_user_status ON TABLE certificates COLUMNS user_id, status;
                ",
            )
            .await
            .map_err(|e| AppError::DbError(e))?;

        Ok(())
    }

    /// Store a new certificate in the database
    pub async fn store_certificate(&self, cert: CertificateRecord) -> Result<CertificateRecord> {
        let created: Option<CertificateRecord> = self
            .db
            .create("certificates")
            .content(cert)
            .await
            .map_err(|e| AppError::DbError(e))?;

        created.ok_or_else(|| AppError::Internal("Failed to create certificate record".to_string()))
    }

    /// Get certificate by ID
    pub async fn get_certificate(&self, cert_id: &str) -> Result<Option<CertificateRecord>> {
        let cert: Option<CertificateRecord> = self
            .db
            .query("SELECT * FROM certificates WHERE certificate_id = $cert_id")
            .bind(("cert_id", cert_id.to_string()))
            .await
            .map_err(|e| AppError::DbError(e))?
            .take(0)
            .map_err(|e| AppError::DbError(e))?;

        Ok(cert)
    }

    /// Get certificate by serial number
    pub async fn get_certificate_by_serial(
        &self,
        serial: &str,
    ) -> Result<Option<CertificateRecord>> {
        let cert: Option<CertificateRecord> = self
            .db
            .query("SELECT * FROM certificates WHERE serial_number = $serial")
            .bind(("serial", serial.to_string()))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to query certificate: {}", e)))?
            .take(0)
            .map_err(|e| AppError::Internal(format!("Failed to parse certificate: {}", e)))?;

        Ok(cert)
    }

    /// Get certificates for a specific user
    pub async fn get_user_certificates(
        &self,
        query: &UserCertificateQuery,
    ) -> Result<(Vec<CertificateRecord>, u32)> {
        let page = query.page.unwrap_or(1);
        let limit = query.limit.unwrap_or(10);
        let offset = (page - 1) * limit;

        let user_id = query
            .user_id
            .as_ref()
            .ok_or_else(|| AppError::BadRequest("user_id is required".to_string()))?;
        let mut where_clause = format!("user_id = '{}'", user_id);
        if let Some(status) = &query.status {
            let status_str = match status {
                crate::models::certificate::CertificateStatus::Active => "active",
                crate::models::certificate::CertificateStatus::Revoked => "revoked",
                crate::models::certificate::CertificateStatus::Expired => "expired",
            };
            where_clause.push_str(&format!(" AND status = '{}'", status_str));
        }

        // Get total count using different approach
        let cert_query = format!("SELECT * FROM certificates WHERE {}", where_clause);
        let all_certificates: Vec<CertificateRecord> = self
            .db
            .query(&cert_query)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to query certificates for count: {}", e))
            })?
            .take(0)
            .map_err(|e| {
                AppError::Internal(format!("Failed to parse certificates for count: {}", e))
            })?;

        let total_count = all_certificates.len() as u32;

        // Use already queried certificates and apply pagination
        let mut sorted_certs = all_certificates;
        // Sort by created_at DESC (timestamp order)
        sorted_certs.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply pagination
        let start_idx = offset as usize;
        let end_idx = std::cmp::min(start_idx + limit as usize, sorted_certs.len());
        let certificates = if start_idx < sorted_certs.len() {
            sorted_certs[start_idx .. end_idx].to_vec()
        } else {
            vec![]
        };

        Ok((certificates, total_count))
    }

    /// Update certificate status
    pub async fn update_certificate_status(
        &self,
        cert_id: &str,
        status: CertificateStatus,
    ) -> Result<()> {
        let _result: Option<CertificateRecord> = self
            .db
            .query("UPDATE certificates SET status = $status WHERE certificate_id = $cert_id")
            .bind(("status", format!("{:?}", status)))
            .bind(("cert_id", cert_id.to_string()))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to update certificate status: {}", e)))?
            .take(0)
            .map_err(|e| AppError::Internal(format!("Failed to parse update result: {}", e)))?;

        Ok(())
    }

    /// Revoke a certificate
    pub async fn revoke_certificate(
        &self,
        cert_id: &str,
        reason: Option<String>,
        comment: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();

        let _result: Option<CertificateRecord> = self
            .db
            .query(
                "UPDATE certificates SET 
                 status = 'revoked', 
                 revoked_at = $revoked_at,
                 revocation_reason = $reason,
                 revocation_comment = $comment
                 WHERE certificate_id = $cert_id",
            )
            .bind(("revoked_at", now))
            .bind(("reason", reason))
            .bind(("comment", comment))
            .bind(("cert_id", cert_id.to_string()))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to revoke certificate: {}", e)))?
            .take(0)
            .map_err(|e| AppError::Internal(format!("Failed to parse revoke result: {}", e)))?;

        Ok(())
    }

    /// Get all certificates (for admin)
    pub async fn list_certificates(
        &self,
        status: Option<CertificateStatus>,
        page: Option<u32>,
        limit: Option<u32>,
    ) -> Result<(Vec<CertificateRecord>, u32)> {
        let page = page.unwrap_or(1);
        let limit = limit.unwrap_or(10);
        let offset = (page - 1) * limit;

        let where_clause = if let Some(status) = status {
            let status_str = match status {
                CertificateStatus::Active => "active",
                CertificateStatus::Revoked => "revoked",
                CertificateStatus::Expired => "expired",
            };
            format!("WHERE status = '{}'", status_str)
        } else {
            String::new()
        };

        // Query all certificates
        let cert_query = format!("SELECT * FROM certificates {}", where_clause);
        let all_certificates: Vec<CertificateRecord> = self
            .db
            .query(&cert_query)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to query certificates: {}", e)))?
            .take(0)
            .map_err(|e| AppError::Internal(format!("Failed to parse certificates: {}", e)))?;

        let total_count = all_certificates.len() as u32;

        // Sort and paginate
        let mut sorted_certs = all_certificates;
        sorted_certs.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let start_idx = offset as usize;
        let end_idx = std::cmp::min(start_idx + limit as usize, sorted_certs.len());
        let certificates = if start_idx < sorted_certs.len() {
            sorted_certs[start_idx .. end_idx].to_vec()
        } else {
            vec![]
        };

        Ok((certificates, total_count))
    }

    /// Mark old certificate as superseded when renewing
    pub async fn supersede_certificate(&self, cert_id: &str) -> Result<()> {
        let now = Utc::now().timestamp();

        let query = format!(
            "UPDATE certificates SET status = 'revoked', revoked_at = {}, revocation_reason = \
             'superseded' WHERE certificate_id = '{}'",
            now, cert_id
        );

        let _result: Vec<CertificateRecord> = self
            .db
            .query(query)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to supersede certificate: {}", e)))?
            .take(0)
            .map_err(|e| AppError::Internal(format!("Failed to parse supersede result: {}", e)))?;

        Ok(())
    }

    /// Check if user already has an active certificate with the specified algorithm
    pub async fn get_active_certificate_by_user_and_algorithm(
        &self,
        user_id: &str,
        algorithm: &str,
    ) -> Result<Option<CertificateRecord>> {
        let cert: Option<CertificateRecord> = self
            .db
            .query(
                "SELECT * FROM certificates WHERE user_id = $user_id AND key_algorithm = \
                 $algorithm AND status = 'active'",
            )
            .bind(("user_id", user_id.to_string()))
            .bind(("algorithm", algorithm.to_string()))
            .await
            .map_err(|e| {
                AppError::Internal(format!(
                    "Failed to query certificate by user and algorithm: {}",
                    e
                ))
            })?
            .take(0)
            .map_err(|e| AppError::Internal(format!("Failed to parse certificate: {}", e)))?;

        Ok(cert)
    }
}
