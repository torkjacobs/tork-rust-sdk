//! # Tork Governance SDK
//!
//! On-device AI governance with PII detection, redaction, and cryptographic receipts.
//!
//! ## Quick Start
//!
//! ```rust
//! use tork_governance::{Tork, GovernanceAction};
//!
//! let mut tork = Tork::new();
//! let result = tork.govern("My SSN is 123-45-6789");
//!
//! assert_eq!(result.action, GovernanceAction::Redact);
//! assert_eq!(result.output, "My SSN is [SSN_REDACTED]");
//! ```
//!
//! ## Framework Middleware
//!
//! The SDK includes middleware for popular web frameworks:
//!
//! - **Actix Web**: `tork_governance::middleware::actix::TorkMiddleware`
//! - **Axum**: `tork_governance::middleware::axum::TorkLayer`
//! - **Rocket**: `tork_governance::middleware::rocket::TorkFairing`
//!
//! See the middleware module documentation for usage examples.

pub mod middleware;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Instant;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Types of PII that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PIIType {
    Ssn,
    CreditCard,
    Email,
    Phone,
    Address,
    IpAddress,
    DateOfBirth,
    Passport,
    DriversLicense,
    BankAccount,
}

impl PIIType {
    /// Get the redaction placeholder for this PII type
    pub fn redaction(&self) -> &'static str {
        match self {
            PIIType::Ssn => "[SSN_REDACTED]",
            PIIType::CreditCard => "[CARD_REDACTED]",
            PIIType::Email => "[EMAIL_REDACTED]",
            PIIType::Phone => "[PHONE_REDACTED]",
            PIIType::Address => "[ADDRESS_REDACTED]",
            PIIType::IpAddress => "[IP_REDACTED]",
            PIIType::DateOfBirth => "[DOB_REDACTED]",
            PIIType::Passport => "[PASSPORT_REDACTED]",
            PIIType::DriversLicense => "[DL_REDACTED]",
            PIIType::BankAccount => "[ACCOUNT_REDACTED]",
        }
    }
}

/// Governance action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    Allow,
    Deny,
    Redact,
    Escalate,
}

impl Default for GovernanceAction {
    fn default() -> Self {
        GovernanceAction::Redact
    }
}

/// A single PII match found in text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIIMatch {
    pub pii_type: PIIType,
    pub value: String,
    pub start_index: usize,
    pub end_index: usize,
}

/// Result of PII detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIIDetectionResult {
    pub has_pii: bool,
    pub types: Vec<PIIType>,
    pub count: usize,
    pub matches: Vec<PIIMatch>,
    pub redacted_text: String,
}

/// Cryptographic receipt for audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    pub receipt_id: String,
    pub timestamp: DateTime<Utc>,
    pub input_hash: String,
    pub output_hash: String,
    pub action: GovernanceAction,
    pub policy_version: String,
    pub processing_time_ns: u64,
}

/// Result of governance operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceResult {
    pub action: GovernanceAction,
    pub output: String,
    pub pii: PIIDetectionResult,
    pub receipt: GovernanceReceipt,
}

/// Configuration for Tork instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorkConfig {
    pub policy_version: String,
    pub default_action: GovernanceAction,
}

impl Default for TorkConfig {
    fn default() -> Self {
        TorkConfig {
            policy_version: "1.0.0".to_string(),
            default_action: GovernanceAction::Redact,
        }
    }
}

/// Statistics for Tork instance
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TorkStats {
    pub total_calls: u64,
    pub total_pii_detected: u64,
    pub total_processing_time_ns: u64,
    pub action_counts: ActionCounts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionCounts {
    pub allow: u64,
    pub deny: u64,
    pub redact: u64,
    pub escalate: u64,
}

// ============================================================================
// PII Patterns
// ============================================================================

struct PIIPattern {
    pii_type: PIIType,
    regex: Regex,
}

fn get_pii_patterns() -> Vec<PIIPattern> {
    vec![
        PIIPattern {
            pii_type: PIIType::Ssn,
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::CreditCard,
            regex: Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::Email,
            regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::Phone,
            regex: Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::Address,
            regex: Regex::new(r"(?i)\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::IpAddress,
            regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::DateOfBirth,
            regex: Regex::new(r"\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::Passport,
            regex: Regex::new(r"\b[A-Z]{1,2}\d{6,9}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::DriversLicense,
            regex: Regex::new(r"\b[A-Z]\d{7,14}\b").unwrap(),
        },
        PIIPattern {
            pii_type: PIIType::BankAccount,
            regex: Regex::new(r"\b\d{8,17}\b").unwrap(),
        },
    ]
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Generate SHA256 hash of text with prefix
pub fn hash_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Generate a unique receipt ID
pub fn generate_receipt_id() -> String {
    format!("rcpt_{}", Uuid::new_v4().to_string().replace("-", ""))
}

// ============================================================================
// PII Detection
// ============================================================================

/// Detect PII in text and return detection results with redacted text
pub fn detect_pii(text: &str) -> PIIDetectionResult {
    let patterns = get_pii_patterns();
    let mut matches: Vec<PIIMatch> = Vec::new();
    let mut detected_types: HashSet<PIIType> = HashSet::new();
    let mut redacted_text = text.to_string();

    for pattern in &patterns {
        for mat in pattern.regex.find_iter(text) {
            detected_types.insert(pattern.pii_type);
            matches.push(PIIMatch {
                pii_type: pattern.pii_type,
                value: mat.as_str().to_string(),
                start_index: mat.start(),
                end_index: mat.end(),
            });
        }

        // Redact this pattern type
        redacted_text = pattern
            .regex
            .replace_all(&redacted_text, pattern.pii_type.redaction())
            .to_string();
    }

    PIIDetectionResult {
        has_pii: !matches.is_empty(),
        types: detected_types.into_iter().collect(),
        count: matches.len(),
        matches,
        redacted_text,
    }
}

// ============================================================================
// Tork Struct
// ============================================================================

/// Main Tork governance struct
pub struct Tork {
    config: TorkConfig,
    stats: TorkStats,
    patterns: Vec<PIIPattern>,
}

impl Tork {
    /// Create a new Tork instance with default configuration
    pub fn new() -> Self {
        Tork {
            config: TorkConfig::default(),
            stats: TorkStats::default(),
            patterns: get_pii_patterns(),
        }
    }

    /// Create a new Tork instance with custom configuration
    pub fn with_config(config: TorkConfig) -> Self {
        Tork {
            config,
            stats: TorkStats::default(),
            patterns: get_pii_patterns(),
        }
    }

    /// Apply governance to input text
    pub fn govern(&mut self, input: &str) -> GovernanceResult {
        let start_time = Instant::now();

        // Detect PII
        let pii = self.detect_pii_internal(input);

        // Determine action
        let (action, output) = if pii.has_pii {
            let action = self.config.default_action;
            let output = match action {
                GovernanceAction::Redact => pii.redacted_text.clone(),
                _ => input.to_string(),
            };
            (action, output)
        } else {
            (GovernanceAction::Allow, input.to_string())
        };

        let processing_time_ns = start_time.elapsed().as_nanos() as u64;

        // Generate receipt
        let receipt = GovernanceReceipt {
            receipt_id: generate_receipt_id(),
            timestamp: Utc::now(),
            input_hash: hash_text(input),
            output_hash: hash_text(&output),
            action,
            policy_version: self.config.policy_version.clone(),
            processing_time_ns,
        };

        // Update stats
        self.stats.total_calls += 1;
        if pii.has_pii {
            self.stats.total_pii_detected += 1;
        }
        self.stats.total_processing_time_ns += processing_time_ns;
        match action {
            GovernanceAction::Allow => self.stats.action_counts.allow += 1,
            GovernanceAction::Deny => self.stats.action_counts.deny += 1,
            GovernanceAction::Redact => self.stats.action_counts.redact += 1,
            GovernanceAction::Escalate => self.stats.action_counts.escalate += 1,
        }

        GovernanceResult {
            action,
            output,
            pii,
            receipt,
        }
    }

    /// Internal PII detection using cached patterns
    fn detect_pii_internal(&self, text: &str) -> PIIDetectionResult {
        let mut matches: Vec<PIIMatch> = Vec::new();
        let mut detected_types: HashSet<PIIType> = HashSet::new();
        let mut redacted_text = text.to_string();

        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(text) {
                detected_types.insert(pattern.pii_type);
                matches.push(PIIMatch {
                    pii_type: pattern.pii_type,
                    value: mat.as_str().to_string(),
                    start_index: mat.start(),
                    end_index: mat.end(),
                });
            }

            redacted_text = pattern
                .regex
                .replace_all(&redacted_text, pattern.pii_type.redaction())
                .to_string();
        }

        PIIDetectionResult {
            has_pii: !matches.is_empty(),
            types: detected_types.into_iter().collect(),
            count: matches.len(),
            matches,
            redacted_text,
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> &TorkStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = TorkStats::default();
    }

    /// Get current configuration
    pub fn get_config(&self) -> &TorkConfig {
        &self.config
    }

    /// Update configuration
    pub fn set_config(&mut self, config: TorkConfig) {
        self.config = config;
    }
}

impl Default for Tork {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ssn() {
        let result = detect_pii("My SSN is 123-45-6789");
        assert!(result.has_pii);
        assert!(result.types.contains(&PIIType::Ssn));
        assert_eq!(result.redacted_text, "My SSN is [SSN_REDACTED]");
    }

    #[test]
    fn test_detect_email() {
        let result = detect_pii("Contact: john@example.com");
        assert!(result.has_pii);
        assert!(result.types.contains(&PIIType::Email));
    }

    #[test]
    fn test_detect_credit_card() {
        let result = detect_pii("Card: 4111-1111-1111-1111");
        assert!(result.has_pii);
        assert!(result.types.contains(&PIIType::CreditCard));
    }

    #[test]
    fn test_detect_phone() {
        let result = detect_pii("Call 555-123-4567");
        assert!(result.has_pii);
        assert!(result.types.contains(&PIIType::Phone));
    }

    #[test]
    fn test_no_pii() {
        let result = detect_pii("Hello world, no sensitive data here.");
        assert!(!result.has_pii);
        assert_eq!(result.count, 0);
    }

    #[test]
    fn test_multiple_pii_types() {
        let result = detect_pii("SSN: 123-45-6789, Email: test@test.com");
        assert!(result.has_pii);
        assert!(result.types.contains(&PIIType::Ssn));
        assert!(result.types.contains(&PIIType::Email));
        assert_eq!(result.count, 2);
    }

    #[test]
    fn test_tork_govern_with_pii() {
        let mut tork = Tork::new();
        let result = tork.govern("My SSN is 123-45-6789");
        assert_eq!(result.action, GovernanceAction::Redact);
        assert_eq!(result.output, "My SSN is [SSN_REDACTED]");
        assert!(result.pii.has_pii);
    }

    #[test]
    fn test_tork_govern_without_pii() {
        let mut tork = Tork::new();
        let result = tork.govern("Hello world");
        assert_eq!(result.action, GovernanceAction::Allow);
        assert_eq!(result.output, "Hello world");
    }

    #[test]
    fn test_tork_receipt_generation() {
        let mut tork = Tork::new();
        let result = tork.govern("Test input");
        assert!(result.receipt.receipt_id.starts_with("rcpt_"));
        assert!(result.receipt.input_hash.starts_with("sha256:"));
        assert!(!result.receipt.timestamp.to_string().is_empty());
    }

    #[test]
    fn test_tork_statistics() {
        let mut tork = Tork::new();
        tork.govern("Text 1");
        tork.govern("SSN: 123-45-6789");
        tork.govern("Text 3");

        let stats = tork.get_stats();
        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.total_pii_detected, 1);
    }

    #[test]
    fn test_hash_text_consistency() {
        let hash1 = hash_text("test");
        let hash2 = hash_text("test");
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
        assert_eq!(hash1.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_receipt_id_uniqueness() {
        let id1 = generate_receipt_id();
        let id2 = generate_receipt_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("rcpt_"));
    }
}
