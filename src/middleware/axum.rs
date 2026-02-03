//! Axum middleware for Tork governance
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{
//!     routing::post,
//!     Router, Extension, Json,
//! };
//! use tork_governance::middleware::axum::{TorkLayer, TorkExtension};
//! use serde_json::json;
//!
//! async fn chat(
//!     Extension(tork_result): Extension<Option<TorkExtension>>,
//! ) -> Json<serde_json::Value> {
//!     if let Some(result) = tork_result {
//!         Json(json!({
//!             "output": result.output,
//!             "receipt_id": result.receipt.receipt_id
//!         }))
//!     } else {
//!         Json(json!({"message": "ok"}))
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new()
//!         .route("/api/chat", post(chat))
//!         .layer(TorkLayer::default());
//!
//!     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```

use super::{extract_content, should_protect_path, should_skip_path, ErrorResponse, MiddlewareConfig, SharedTork};
use crate::{GovernanceAction, GovernanceResult, Tork};
use std::sync::{Arc, Mutex};

/// Tork governance extension type for Axum
pub type TorkExtension = GovernanceResult;

/// Axum layer for Tork governance
#[derive(Clone)]
pub struct TorkLayer {
    tork: SharedTork,
    config: MiddlewareConfig,
}

impl TorkLayer {
    /// Create new layer with default configuration
    pub fn new() -> Self {
        Self {
            tork: Arc::new(Mutex::new(Tork::new())),
            config: MiddlewareConfig::default(),
        }
    }

    /// Create new layer with custom configuration
    pub fn with_config(config: MiddlewareConfig) -> Self {
        Self {
            tork: Arc::new(Mutex::new(Tork::new())),
            config,
        }
    }

    /// Create new layer with existing Tork instance
    pub fn with_tork(tork: SharedTork) -> Self {
        Self {
            tork,
            config: MiddlewareConfig::default(),
        }
    }

    /// Create new layer with custom Tork and config
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

impl Default for TorkLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum middleware service
///
/// This struct can be used to implement tower::Layer when tower is available.
///
/// # Example Implementation
///
/// ```rust,ignore
/// use tower::{Layer, Service};
/// use http::{Request, Response};
/// use std::task::{Context, Poll};
///
/// impl<S> Layer<S> for TorkLayer {
///     type Service = TorkMiddlewareService<S>;
///
///     fn layer(&self, service: S) -> Self::Service {
///         TorkMiddlewareService {
///             inner: service,
///             layer: self.clone(),
///         }
///     }
/// }
/// ```
pub struct TorkMiddlewareService<S> {
    pub inner: S,
    pub layer: TorkLayer,
}

impl<S: Clone> Clone for TorkMiddlewareService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

/// Extractor for Axum handlers to get Tork result
///
/// # Example
///
/// ```rust,ignore
/// use axum::extract::Extension;
/// use tork_governance::middleware::axum::TorkResultExtractor;
///
/// async fn handler(TorkResultExtractor(result): TorkResultExtractor) {
///     if let Some(r) = result {
///         println!("Receipt: {}", r.receipt.receipt_id);
///     }
/// }
/// ```
pub struct TorkResultExtractor(pub Option<GovernanceResult>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer_creation() {
        let layer = TorkLayer::new();
        assert_eq!(layer.config().protected_paths, vec!["/api/"]);
    }

    #[test]
    fn test_process_post_with_pii() {
        let layer = TorkLayer::new();
        let result = layer.process(
            "POST",
            "/api/chat",
            r#"{"content": "My email is test@example.com"}"#,
        );

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.pii.has_pii);
    }

    #[test]
    fn test_skip_get_request() {
        let layer = TorkLayer::new();
        let result = layer.process("GET", "/api/chat", r#"{"content": "test"}"#);
        assert!(result.is_none());
    }

    #[test]
    fn test_custom_config() {
        let config = MiddlewareConfig {
            protected_paths: vec!["/v1/".to_string()],
            skip_paths: vec!["/v1/health".to_string()],
            content_fields: vec!["data".to_string()],
        };
        let layer = TorkLayer::with_config(config);

        let result = layer.process(
            "POST",
            "/v1/chat",
            r#"{"data": "SSN: 123-45-6789"}"#,
        );

        assert!(result.is_some());
    }
}
