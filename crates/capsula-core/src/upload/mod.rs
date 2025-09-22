use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    state::{CapsuleState, UploadMeta, UploadVerification},
    Result, CoreError,
};

/// Upload task management for decoupling encapsulation from S3 upload
/// 
/// This module implements the core requirement: "数据胶囊的封装要和上传解藕"
/// It manages the lifecycle of upload tasks from encapsulation through S3 storage.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadTask {
    pub task_id: String,
    pub capsule_id: String,
    pub target_uri: String,
    pub ciphertext_data: Vec<u8>,
    pub content_hash: String,
    pub content_type: String,
    pub upload_meta: UploadMeta,
    pub state: UploadTaskState,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadTaskState {
    /// Task created but upload not started
    Queued {
        priority: UploadPriority,
        retry_count: u32,
    },
    /// Upload in progress
    InProgress {
        upload_id: String,
        progress: f64,       // 0.0 to 1.0
        bytes_uploaded: u64,
        total_bytes: u64,
        started_at: String,
    },
    /// Upload completed successfully
    Completed {
        final_uri: String,
        uploaded_at: String,
        verification: UploadVerification,
    },
    /// Upload failed
    Failed {
        error: String,
        retry_count: u32,
        last_attempt: String,
        can_retry: bool,
    },
    /// Upload cancelled by user
    Cancelled {
        reason: String,
        cancelled_at: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadPriority {
    Low,
    Normal, 
    High,
    Critical,
}

impl UploadPriority {
    pub fn to_numeric(&self) -> u8 {
        match self {
            UploadPriority::Low => 1,
            UploadPriority::Normal => 2,
            UploadPriority::High => 3,
            UploadPriority::Critical => 4,
        }
    }
}

/// Upload task manager coordinates between capsule states and S3 operations
#[derive(Debug)]
pub struct UploadTaskManager {
    tasks: HashMap<String, UploadTask>,
    queue: Vec<String>, // Task IDs sorted by priority
}

impl UploadTaskManager {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            queue: Vec::new(),
        }
    }

    /// Create upload task from pending capsule state
    /// This decouples encapsulation from upload as requested
    pub fn create_task_from_capsule(&mut self, capsule_state: &CapsuleState) -> Result<String> {
        let task_id = Uuid::new_v4().to_string();
        
        let (ciphertext_data, content_hash, target_uri) = match capsule_state {
            CapsuleState::Pending { 
                placeholder_uri, 
                ciphertext_data, 
                content_hash, 
                .. 
            } => {
                (ciphertext_data.clone(), content_hash.clone(), placeholder_uri.clone())
            }
            _ => {
                return Err(CoreError::InvalidState(
                    "Can only create upload task from Pending state".to_string()
                ));
            }
        };

        // Create default upload meta from state
        let mut config = std::collections::HashMap::new();
        config.insert("content_type".to_string(), "application/octet-stream".to_string());
        config.insert("file_size".to_string(), ciphertext_data.len().to_string());
        config.insert("checksum".to_string(), content_hash.clone());
        
        let upload_meta = UploadMeta {
            backend_type: "s3".to_string(),
            bucket: Some("capsula-storage".to_string()),
            config,
        };

        let task = UploadTask {
            task_id: task_id.clone(),
            capsule_id: Uuid::new_v4().to_string(), // Will be set by caller
            target_uri,
            ciphertext_data,
            content_hash,
            content_type: upload_meta.config.get("content_type")
                .unwrap_or(&"application/octet-stream".to_string()).clone(),
            upload_meta,
            state: UploadTaskState::Queued { 
                priority: UploadPriority::Normal,
                retry_count: 0,
            },
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };

        self.add_task_to_queue(&task_id, &UploadPriority::Normal);
        self.tasks.insert(task_id.clone(), task);
        
        Ok(task_id)
    }

    /// Start upload task (transition to InProgress state)
    pub fn start_upload(&mut self, task_id: &str, upload_id: String, total_bytes: u64) -> Result<()> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        match &task.state {
            UploadTaskState::Queued { .. } => {
                task.state = UploadTaskState::InProgress {
                    upload_id,
                    progress: 0.0,
                    bytes_uploaded: 0,
                    total_bytes,
                    started_at: chrono::Utc::now().to_rfc3339(),
                };
                task.updated_at = chrono::Utc::now().to_rfc3339();
                self.remove_from_queue(task_id);
                Ok(())
            }
            _ => Err(CoreError::InvalidState(
                format!("Cannot start upload for task in state: {:?}", task.state)
            ))
        }
    }

    /// Update upload progress
    pub fn update_progress(&mut self, task_id: &str, bytes_uploaded: u64) -> Result<()> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        match &mut task.state {
            UploadTaskState::InProgress { 
                ref mut progress, 
                bytes_uploaded: ref mut current_bytes, 
                total_bytes,
                .. 
            } => {
                *current_bytes = bytes_uploaded;
                *progress = if *total_bytes > 0 {
                    bytes_uploaded as f64 / (*total_bytes) as f64
                } else {
                    0.0
                };
                task.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(())
            }
            _ => Err(CoreError::InvalidState(
                format!("Cannot update progress for task in state: {:?}", task.state)
            ))
        }
    }

    /// Complete upload task successfully
    pub fn complete_upload(&mut self, task_id: &str, final_uri: String, verification: UploadVerification) -> Result<()> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        match &task.state {
            UploadTaskState::InProgress { .. } => {
                task.state = UploadTaskState::Completed {
                    final_uri,
                    uploaded_at: chrono::Utc::now().to_rfc3339(),
                    verification,
                };
                task.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(())
            }
            _ => Err(CoreError::InvalidState(
                format!("Cannot complete upload for task in state: {:?}", task.state)
            ))
        }
    }

    /// Fail upload task
    pub fn fail_upload(&mut self, task_id: &str, error: String, can_retry: bool) -> Result<()> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        let retry_count = match &task.state {
            UploadTaskState::Queued { retry_count, .. } => *retry_count + 1,
            UploadTaskState::InProgress { .. } => 1,
            UploadTaskState::Failed { retry_count, .. } => *retry_count + 1,
            _ => return Err(CoreError::InvalidState(
                format!("Cannot fail upload for task in state: {:?}", task.state)
            ))
        };

        task.state = UploadTaskState::Failed {
            error,
            retry_count,
            last_attempt: chrono::Utc::now().to_rfc3339(),
            can_retry: can_retry && retry_count < 3, // Max 3 retries
        };
        task.updated_at = chrono::Utc::now().to_rfc3339();

        // Re-queue if can retry
        if can_retry && retry_count < 3 {
            task.state = UploadTaskState::Queued {
                priority: UploadPriority::High, // Higher priority for retries
                retry_count,
            };
            self.add_task_to_queue(task_id, &UploadPriority::High);
        }

        Ok(())
    }

    /// Get next task from queue (highest priority first)
    pub fn get_next_task(&self) -> Option<&UploadTask> {
        self.queue.first().and_then(|task_id| self.tasks.get(task_id))
    }

    /// Get task by ID
    pub fn get_task(&self, task_id: &str) -> Option<&UploadTask> {
        self.tasks.get(task_id)
    }

    /// List all tasks with optional state filter
    pub fn list_tasks(&self, state_filter: Option<UploadTaskState>) -> Vec<&UploadTask> {
        self.tasks.values()
            .filter(|task| {
                if let Some(ref filter_state) = state_filter {
                    std::mem::discriminant(&task.state) == std::mem::discriminant(filter_state)
                } else {
                    true
                }
            })
            .collect()
    }

    /// Cancel upload task
    pub fn cancel_task(&mut self, task_id: &str, reason: String) -> Result<()> {
        let task = self.tasks.get_mut(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        match &task.state {
            UploadTaskState::Queued { .. } | UploadTaskState::Failed { .. } => {
                task.state = UploadTaskState::Cancelled {
                    reason,
                    cancelled_at: chrono::Utc::now().to_rfc3339(),
                };
                task.updated_at = chrono::Utc::now().to_rfc3339();
                self.remove_from_queue(task_id);
                Ok(())
            }
            UploadTaskState::InProgress { .. } => {
                // Note: In real implementation, would need to cancel S3 upload
                task.state = UploadTaskState::Cancelled {
                    reason,
                    cancelled_at: chrono::Utc::now().to_rfc3339(),
                };
                task.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(())
            }
            _ => Err(CoreError::InvalidState(
                format!("Cannot cancel task in state: {:?}", task.state)
            ))
        }
    }

    /// Remove completed or cancelled tasks
    pub fn cleanup_finished_tasks(&mut self) -> u32 {
        let mut removed_count = 0;
        let mut to_remove = Vec::new();

        for (task_id, task) in &self.tasks {
            match &task.state {
                UploadTaskState::Completed { .. } | UploadTaskState::Cancelled { .. } => {
                    to_remove.push(task_id.clone());
                }
                UploadTaskState::Failed { can_retry: false, .. } => {
                    to_remove.push(task_id.clone());
                }
                _ => {}
            }
        }

        for task_id in to_remove {
            self.tasks.remove(&task_id);
            self.remove_from_queue(&task_id);
            removed_count += 1;
        }

        removed_count
    }

    // Private helper methods
    
    fn add_task_to_queue(&mut self, task_id: &str, priority: &UploadPriority) {
        // Insert task in priority order (highest priority first)
        let priority_num = priority.to_numeric();
        let insert_pos = self.queue.iter().position(|id| {
            if let Some(task) = self.tasks.get(id) {
                match &task.state {
                    UploadTaskState::Queued { priority: task_priority, .. } => {
                        task_priority.to_numeric() < priority_num
                    }
                    _ => false
                }
            } else {
                true // Insert before invalid entries
            }
        }).unwrap_or(self.queue.len());

        self.queue.insert(insert_pos, task_id.to_string());
    }

    fn remove_from_queue(&mut self, task_id: &str) {
        self.queue.retain(|id| id != task_id);
    }
}

/// Integration with capsule state transitions
impl UploadTaskManager {
    /// Create capsule state from completed upload task
    /// This enables the transition from upload completion back to capsule state
    pub fn create_completed_state(&self, task_id: &str) -> Result<CapsuleState> {
        let task = self.get_task(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        match &task.state {
            UploadTaskState::Completed { final_uri, uploaded_at, verification } => {
                Ok(CapsuleState::Completed {
                    final_uri: final_uri.clone(),
                    uploaded_at: uploaded_at.clone(),
                    verification: Some(verification.clone()),
                })
            }
            _ => Err(CoreError::InvalidState(
                format!("Cannot create completed state from task in state: {:?}", task.state)
            ))
        }
    }

    /// Create uploading state from in-progress upload task
    pub fn create_uploading_state(&self, task_id: &str) -> Result<CapsuleState> {
        let task = self.get_task(task_id)
            .ok_or_else(|| CoreError::InvalidState(format!("Task {} not found", task_id)))?;

        match &task.state {
            UploadTaskState::InProgress { upload_id, progress, started_at, .. } => {
                Ok(CapsuleState::Uploading {
                    upload_id: upload_id.clone(),
                    target_uri: task.target_uri.clone(),
                    progress: *progress,
                    started_at: started_at.clone(),
                    upload_meta: Some(task.upload_meta.clone()),
                })
            }
            _ => Err(CoreError::InvalidState(
                format!("Cannot create uploading state from task in state: {:?}", task.state)
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::UploadMeta;

    fn create_test_pending_state() -> CapsuleState {
        CapsuleState::Pending {
            placeholder_uri: "s3://test-bucket/placeholder".to_string(),
            ciphertext_data: vec![1, 2, 3, 4],
            content_hash: "test-hash".to_string(),
            ciphertext_len: 4,
            created_at: "2023-10-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_upload_task_creation() {
        let mut manager = UploadTaskManager::new();
        let pending_state = create_test_pending_state();

        let task_id = manager.create_task_from_capsule(&pending_state).unwrap();
        
        let task = manager.get_task(&task_id).unwrap();
        assert_eq!(task.ciphertext_data, vec![1, 2, 3, 4]);
        assert_eq!(task.content_hash, "test-hash");
        assert!(matches!(task.state, UploadTaskState::Queued { .. }));
    }

    #[test]
    fn test_upload_lifecycle() {
        let mut manager = UploadTaskManager::new();
        let pending_state = create_test_pending_state();

        // Create task
        let task_id = manager.create_task_from_capsule(&pending_state).unwrap();
        
        // Start upload
        manager.start_upload(&task_id, "upload-123".to_string(), 100).unwrap();
        let task = manager.get_task(&task_id).unwrap();
        assert!(matches!(task.state, UploadTaskState::InProgress { .. }));

        // Update progress
        manager.update_progress(&task_id, 50).unwrap();
        let task = manager.get_task(&task_id).unwrap();
        if let UploadTaskState::InProgress { progress, .. } = &task.state {
            assert_eq!(*progress, 0.5);
        }

        // Complete upload
        let verification = UploadVerification {
            uploaded_size: 100,
            etag: Some("test-etag".to_string()),
            integrity_digest: None,
        };
        manager.complete_upload(&task_id, "s3://bucket/final".to_string(), verification).unwrap();
        
        let task = manager.get_task(&task_id).unwrap();
        assert!(matches!(task.state, UploadTaskState::Completed { .. }));
    }

    #[test]
    fn test_upload_failure_and_retry() {
        let mut manager = UploadTaskManager::new();
        let pending_state = create_test_pending_state();

        let task_id = manager.create_task_from_capsule(&pending_state).unwrap();
        manager.start_upload(&task_id, "upload-123".to_string(), 100).unwrap();

        // Fail upload with retry enabled
        manager.fail_upload(&task_id, "Network error".to_string(), true).unwrap();
        
        let task = manager.get_task(&task_id).unwrap();
        assert!(matches!(task.state, UploadTaskState::Queued { .. }));
        
        // Should be back in queue with higher priority
        let next_task = manager.get_next_task().unwrap();
        assert_eq!(next_task.task_id, task_id);
    }

    #[test]
    fn test_priority_queue() {
        let mut manager = UploadTaskManager::new();
        
        // Create tasks with different priorities
        manager.add_task_to_queue("low", &UploadPriority::Low);
        manager.add_task_to_queue("high", &UploadPriority::High);
        manager.add_task_to_queue("normal", &UploadPriority::Normal);
        manager.add_task_to_queue("critical", &UploadPriority::Critical);

        // Should be ordered by priority
        assert_eq!(manager.queue, vec!["critical", "high", "normal", "low"]);
    }

    #[test]
    fn test_state_conversion() {
        let mut manager = UploadTaskManager::new();
        let pending_state = create_test_pending_state();

        let task_id = manager.create_task_from_capsule(&pending_state).unwrap();
        manager.start_upload(&task_id, "upload-123".to_string(), 100).unwrap();

        // Test conversion to uploading state
        let uploading_state = manager.create_uploading_state(&task_id).unwrap();
        assert!(matches!(uploading_state, CapsuleState::Uploading { .. }));

        // Complete and test conversion to completed state
        let verification = UploadVerification {
            uploaded_size: 100,
            etag: Some("test-etag".to_string()),
            integrity_digest: None,
        };
        manager.complete_upload(&task_id, "s3://bucket/final".to_string(), verification).unwrap();
        
        let completed_state = manager.create_completed_state(&task_id).unwrap();
        assert!(matches!(completed_state, CapsuleState::Completed { .. }));
    }

    #[test]
    fn test_cleanup_finished_tasks() {
        let mut manager = UploadTaskManager::new();
        let pending_state = create_test_pending_state();

        // Create and complete a task
        let task_id = manager.create_task_from_capsule(&pending_state).unwrap();
        manager.start_upload(&task_id, "upload-123".to_string(), 100).unwrap();
        let verification = UploadVerification {
            uploaded_size: 100,
            etag: Some("test-etag".to_string()),
            integrity_digest: None,
        };
        manager.complete_upload(&task_id, "s3://bucket/final".to_string(), verification).unwrap();

        // Should have one completed task
        assert_eq!(manager.tasks.len(), 1);
        
        // Cleanup should remove completed task
        let removed = manager.cleanup_finished_tasks();
        assert_eq!(removed, 1);
        assert_eq!(manager.tasks.len(), 0);
    }
}