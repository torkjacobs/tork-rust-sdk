//! Actix Web middleware for Tork governance
//!
//! # Example
//!
//! ```rust,ignore
//! use actix_web::{web, App, HttpServer, HttpResponse};
//! use tork_governance::middleware::actix::{TorkMiddleware, TorkResult};
//!
//! async fn chat(tork_result: Option<web::ReqData<TorkResult>>) -> HttpResponse {
//!     if let Some(result) = tork_result {
//!         HttpResponse::Ok().json(serde_json::json!({
//!             "output": result.output,
//!             "receipt_id": result.receipt.receipt_id
//!         }))
//!     } else {
//!         HttpResponse::Ok().json(serde_json::json!({"message": "ok"}))
//!     }
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     HttpServer::new(|| {
//!         App::new()
//!             .wrap(TorkMiddleware::default())
//!             .route("/api/chat", web::post().to(chat))
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! ```

use super::{extract_content, should_protect_path, should_skip_path, ErrorResponse, MiddlewareConfig, SharedTork};
use crate::{GovernanceAction, GovernanceResult, Tork};
use std::sync::{Arc, Mutex};

/// Tork governance result wrapper for Actix
pub type TorkResult = GovernanceResult;

/// Actix Web middleware configuration
pub struct TorkMiddleware {
    tork: SharedTork,
    config: MiddlewareConfig,
}

impl TorkMiddleware {
    /// Create new middleware with default configuration
    pub fn new() -> Self {
        Self {
            tork: Arc::new(Mutex::new(Tork::new())),
            config: MiddlewareConfig::default(),
        }
    }

    /// Create new middleware with custom configuration
    pub fn with_config(config: MiddlewareConfig) -> Self {
        Self {
            tork: Arc::new(Mutex::new(Tork::new())),
            config,
        }
    }

    /// Create new middleware with existing Tork instance
    pub fn with_tork(tork: SharedTork) -> Self {
        Self {
            tork,
            config: MiddlewareConfig::default(),
        }
    }

    /// Create new middleware with custom Tork and config
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

impl Default for TorkMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TorkMiddleware {
    fn clone(&self) -> Self {
        Self {
            tork: Arc::clone(&self.tork),
            config: self.config.clone(),
        }
    }
}

/// Actix-compatible transform wrapper
///
/// This can be used to implement actix_web::middleware::Transform
/// when actix-web is available as a dependency.
///
/// # Example Implementation
///
/// ```rust,ignore
/// use actix_web::{
///     dev::{Service, ServiceRequest, ServiceResponse, Transform},
///     Error, HttpResponse,
/// };
/// use futures::future::{ok, Ready};
/// use std::task::{Context, Poll};
///
/// impl<S, B> Transform<S, ServiceRequest> for TorkMiddleware
/// where
///     S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
///     S::Future: 'static,
///     B: 'static,
/// {
///     type Response = ServiceResponse<B>;
///     type Error = Error;
///     type Transform = TorkMiddlewareService<S>;
///     type InitError = ();
///     type Future = Ready<Result<Self::Transform, Self::InitError>>;
///
///     fn new_transform(&self, service: S) -> Self::Future {
///         ok(TorkMiddlewareService {
///             service,
///             middleware: self.clone(),
///         })
///     }
/// }
/// ```
#[derive(Clone)]
pub struct TorkActixTransform {
    inner: TorkMiddleware,
}

impl TorkActixTransform {
    pub fn new(middleware: TorkMiddleware) -> Self {
        Self { inner: middleware }
    }

    pub fn inner(&self) -> &TorkMiddleware {
        &self.inner
    }
}

impl Default for TorkActixTransform {
    fn default() -> Self {
        Self::new(TorkMiddleware::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_creation() {
        let middleware = TorkMiddleware::new();
        assert_eq!(middleware.config().protected_paths, vec!["/api/"]);
    }

    #[test]
    fn test_process_post_with_pii() {
        let middleware = TorkMiddleware::new();
        let result = middleware.process(
            "POST",
            "/api/chat",
            r#"{"content": "My SSN is 123-45-6789"}"#,
        );

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.pii.has_pii);
    }

    #[test]
    fn test_skip_get_request() {
        let middleware = TorkMiddleware::new();
        let result = middleware.process("GET", "/api/chat", r#"{"content": "test"}"#);
        assert!(result.is_none());
    }

    #[test]
    fn test_skip_unprotected_path() {
        let middleware = TorkMiddleware::new();
        let result = middleware.process("POST", "/health", r#"{"content": "test"}"#);
        assert!(result.is_none());
    }
}
