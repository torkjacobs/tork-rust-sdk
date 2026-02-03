//! Rocket middleware (fairing) for Tork governance
//!
//! # Example
//!
//! ```rust,ignore
//! #[macro_use] extern crate rocket;
//! use rocket::serde::json::Json;
//! use tork_governance::middleware::rocket::{TorkFairing, TorkGuard};
//! use serde_json::json;
//!
//! #[post("/api/chat", data = "<_body>")]
//! fn chat(guard: TorkGuard, _body: &str) -> Json<serde_json::Value> {
//!     if let Some(result) = guard.result() {
//!         Json(json!({
//!             "output": result.output,
//!             "receipt_id": result.receipt.receipt_id
//!         }))
//!     } else {
//!         Json(json!({"message": "ok"}))
//!     }
//! }
//!
//! #[launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(TorkFairing::default())
//!         .mount("/", routes![chat])
//! }
//! ```

use super::{extract_content, should_protect_path, should_skip_path, ErrorResponse, MiddlewareConfig, SharedTork};
use crate::{GovernanceAction, GovernanceResult, Tork};
use std::sync::{Arc, Mutex};

/// Tork governance result for Rocket
pub type TorkRocketResult = GovernanceResult;

/// Rocket fairing for Tork governance
pub struct TorkFairing {
    tork: SharedTork,
    config: MiddlewareConfig,
}

impl TorkFairing {
    /// Create new fairing with default configuration
    pub fn new() -> Self {
        Self {
            tork: Arc::new(Mutex::new(Tork::new())),
            config: MiddlewareConfig::default(),
        }
    }

    /// Create new fairing with custom configuration
    pub fn with_config(config: MiddlewareConfig) -> Self {
        Self {
            tork: Arc::new(Mutex::new(Tork::new())),
            config,
        }
    }

    /// Create new fairing with existing Tork instance
    pub fn with_tork(tork: SharedTork) -> Self {
        Self {
            tork,
            config: MiddlewareConfig::default(),
        }
    }

    /// Create new fairing with custom Tork and config
    pub fn with_tork_and_config(tork: SharedTork, config: MiddlewareConfig) -> Self {
        Self { tork, config }
    }

    /// Get reference to config
    pub fn config(&self) -> &MiddlewareConfig {
        &self.config
    }

    /// Get reference to shared Tork
    pub fn tork(&self) -> &SharedTork {
        &self.tork
    }

    /// Process request body and return governance result
    pub fn process(&self, method: &str, path: &str, body: &str) -> Option<GovernanceResult> {
        // Only process POST, PUT, PATCH
        if !["POST", "PUT", "PATCH"].contains(&method) {
            return None;
        }

        // Check paths
        if should_skip_path(path, &self.config) {
            return None;
        }

        if !should_protect_path(path, &self.config) {
            return None;
        }

        // Extract content
        let content = extract_content(body, &self.config)?;

        // Govern content
        let mut tork = self.tork.lock().unwrap();
        Some(tork.govern(&content))
    }

    /// Check if result should block the request
    pub fn should_block(result: &GovernanceResult) -> bool {
        result.action == GovernanceAction::Deny
    }

    /// Create error response for blocked request
    pub fn create_error_response(result: &GovernanceResult) -> ErrorResponse {
        ErrorResponse::from_result(result)
    }
}

impl Default for TorkFairing {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TorkFairing {
    fn clone(&self) -> Self {
        Self {
            tork: Arc::clone(&self.tork),
            config: self.config.clone(),
        }
    }
}

/// Request guard for accessing Tork result in handlers
///
/// # Example
///
/// ```rust,ignore
/// #[post("/chat")]
/// fn chat(guard: TorkGuard) -> Json<Value> {
///     match guard.result() {
///         Some(result) => Json(json!({"output": result.output})),
///         None => Json(json!({"message": "no governance applied"})),
///     }
/// }
/// ```
pub struct TorkGuard {
    result: Option<GovernanceResult>,
}

impl TorkGuard {
    /// Create a new guard with a governance result
    pub fn new(result: Option<GovernanceResult>) -> Self {
        Self { result }
    }

    /// Get the governance result if available
    pub fn result(&self) -> Option<&GovernanceResult> {
        self.result.as_ref()
    }

    /// Take ownership of the governance result
    pub fn into_result(self) -> Option<GovernanceResult> {
        self.result
    }

    /// Check if governance was applied
    pub fn has_result(&self) -> bool {
        self.result.is_some()
    }

    /// Check if the request was allowed
    pub fn is_allowed(&self) -> bool {
        self.result
            .as_ref()
            .map(|r| r.action == GovernanceAction::Allow)
            .unwrap_or(true)
    }

    /// Check if the request was denied
    pub fn is_denied(&self) -> bool {
        self.result
            .as_ref()
            .map(|r| r.action == GovernanceAction::Deny)
            .unwrap_or(false)
    }

    /// Check if content was redacted
    pub fn is_redacted(&self) -> bool {
        self.result
            .as_ref()
            .map(|r| r.action == GovernanceAction::Redact)
            .unwrap_or(false)
    }

    /// Get the redacted output if available
    pub fn output(&self) -> Option<&str> {
        self.result.as_ref().map(|r| r.output.as_str())
    }

    /// Get the receipt ID if available
    pub fn receipt_id(&self) -> Option<&str> {
        self.result.as_ref().map(|r| r.receipt.receipt_id.as_str())
    }
}

/// Rocket fairing implementation details
///
/// This module provides the implementation for Rocket's Fairing trait
/// when rocket is available as a dependency.
///
/// # Example Implementation
///
/// ```rust,ignore
/// use rocket::{
///     fairing::{Fairing, Info, Kind},
///     Data, Request, Response,
/// };
///
/// #[rocket::async_trait]
/// impl Fairing for TorkFairing {
///     fn info(&self) -> Info {
///         Info {
///             name: "Tork Governance",
///             kind: Kind::Request | Kind::Response,
///         }
///     }
///
///     async fn on_request(&self, request: &mut Request<'_>, data: &mut Data<'_>) {
///         // Read body, process with self.process(), store result
///     }
/// }
/// ```
pub mod fairing_impl {
    /// Info for Tork fairing
    pub const FAIRING_NAME: &str = "Tork Governance";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fairing_creation() {
        let fairing = TorkFairing::new();
        assert_eq!(fairing.config().protected_paths, vec!["/api/"]);
    }

    #[test]
    fn test_process_post_with_pii() {
        let fairing = TorkFairing::new();
        let result = fairing.process(
            "POST",
            "/api/chat",
            r#"{"content": "Card: 4111-1111-1111-1111"}"#,
        );

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.pii.has_pii);
    }

    #[test]
    fn test_guard_methods() {
        let mut tork = Tork::new();
        let result = tork.govern("SSN: 123-45-6789");
        let guard = TorkGuard::new(Some(result));

        assert!(guard.has_result());
        assert!(guard.is_redacted());
        assert!(!guard.is_denied());
        assert!(guard.output().is_some());
        assert!(guard.receipt_id().is_some());
    }

    #[test]
    fn test_guard_empty() {
        let guard = TorkGuard::new(None);

        assert!(!guard.has_result());
        assert!(guard.is_allowed()); // Default to allowed when no result
        assert!(!guard.is_denied());
    }
}
