//! Framework middleware for Tork governance
//!
//! Provides middleware implementations for popular Rust web frameworks:
//! - Actix Web
//! - Axum
//! - Rocket

pub mod actix;
pub mod axum;
pub mod rocket;

use crate::{GovernanceResult, Tork};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Configuration for middleware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareConfig {
    /// Paths that should be protected (default: ["/api/"])
    pub protected_paths: Vec<String>,
    /// Paths to skip (default: [])
    pub skip_paths: Vec<String>,
    /// Content field names to look for in JSON body
    pub content_fields: Vec<String>,
}

impl Default for MiddlewareConfig {
    fn default() -> Self {
        Self {
            protected_paths: vec!["/api/".to_string()],
            skip_paths: vec![],
            content_fields: vec![
                "content".to_string(),
                "message".to_string(),
                "text".to_string(),
                "prompt".to_string(),
                "query".to_string(),
                "input".to_string(),
            ],
        }
    }
}

/// Shared Tork instance for middleware
pub type SharedTork = Arc<Mutex<Tork>>;

/// Create a new shared Tork instance
pub fn create_shared_tork() -> SharedTork {
    Arc::new(Mutex::new(Tork::new()))
}

/// Extract content from JSON body
pub fn extract_content(body: &str, config: &MiddlewareConfig) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;

    if let serde_json::Value::Object(map) = json {
        for field in &config.content_fields {
            if let Some(serde_json::Value::String(s)) = map.get(field) {
                if !s.is_empty() {
                    return Some(s.clone());
                }
            }
        }
    }
    None
}

/// Check if a path should be skipped
pub fn should_skip_path(path: &str, config: &MiddlewareConfig) -> bool {
    for skip in &config.skip_paths {
        if path.starts_with(skip) {
            return true;
        }
    }
    false
}

/// Check if a path should be protected
pub fn should_protect_path(path: &str, config: &MiddlewareConfig) -> bool {
    for protected in &config.protected_paths {
        if path.starts_with(protected) {
            return true;
        }
    }
    false
}

/// Error response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub receipt_id: String,
    pub pii_types: Vec<String>,
}

impl ErrorResponse {
    pub fn from_result(result: &GovernanceResult) -> Self {
        Self {
            error: "Request blocked by governance policy".to_string(),
            receipt_id: result.receipt.receipt_id.clone(),
            pii_types: result.pii.types.iter().map(|t| format!("{:?}", t).to_lowercase()).collect(),
        }
    }
}
