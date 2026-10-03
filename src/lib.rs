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

pub mod pii_checksums;
pub mod pii_country;
pub mod pii_registry;
pub mod tool_result_scan;

pub use pii_country::{
    apply_redactions, detect_country_pii, detect_country_pii_with, infer_regions,
    patterns_for_regions, CountryPIIMatch, RedactionSpan, KEYWORD_WINDOW_AFTER,
    KEYWORD_WINDOW_BEFORE,
};
pub use pii_registry::{Pattern as CountryPattern, PATTERNS as COUNTRY_PATTERNS_REGISTRY,
    REGISTRY_VERSION};

pub use tool_result_scan::*;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::Instant;
use uuid::Uuid;

/// This crate's version, as declared in `Cargo.toml`. Used to tag
/// `tool_result_scan.sdk_version` on the receipt so a byte-identical block
/// can be traced back to the exact SDK build that produced it.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    /// The snake_case label for this type, e.g. `"credit_card"`. Used as the
    /// `finding.type` value on `tool_result_scan` findings, matching the JS
    /// SDK's `PIIType` string union exactly.
    pub fn label(&self) -> &'static str {
        match self {
            PIIType::Ssn => "ssn",
            PIIType::CreditCard => "credit_card",
            PIIType::Email => "email",
            PIIType::Phone => "phone",
            PIIType::Address => "address",
            PIIType::IpAddress => "ip_address",
            PIIType::DateOfBirth => "date_of_birth",
            PIIType::Passport => "passport",
            PIIType::DriversLicense => "drivers_license",
            PIIType::BankAccount => "bank_account",
        }
    }

    /// Every `PIIType` this SDK declares. The single source of truth for the
    /// parity check that every declared type has a live pattern in
    /// `get_pii_patterns()` -- see `test_parity_all_declared_pii_types_have_live_patterns`.
    pub fn all() -> [PIIType; 10] {
        [
            PIIType::Ssn,
            PIIType::CreditCard,
            PIIType::Email,
            PIIType::Phone,
            PIIType::Address,
            PIIType::IpAddress,
            PIIType::DateOfBirth,
            PIIType::Passport,
            PIIType::DriversLicense,
            PIIType::BankAccount,
        ]
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
    /// Country-registry detections. Kept separate from `matches` so `PIIType`
    /// stays the closed ten-value enum it has always been.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub country_matches: Vec<CountryPIIMatchOwned>,
    /// Redaction labels of those matches, e.g. `NATIONAL_ID`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub country_labels: Vec<String>,
    /// Country profiles the text activated, in registry order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
}

/// A country match in an owned, serialisable form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CountryPIIMatchOwned {
    pub name: String,
    pub country: String,
    pub label: String,
    pub redaction: String,
    pub start_index: usize,
    pub end_index: usize,
}

impl From<&CountryPIIMatch> for CountryPIIMatchOwned {
    fn from(m: &CountryPIIMatch) -> Self {
        CountryPIIMatchOwned {
            name: m.name.to_string(),
            country: m.country.to_string(),
            label: m.label.to_string(),
            redaction: m.redaction.to_string(),
            start_index: m.start_index,
            end_index: m.end_index,
        }
    }
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
    /// Agent/session context when provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_context: Option<SessionContext>,
    /// Set only on receipts produced by `Tork::scan_tool_result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_result_scan: Option<ToolResultScanReceiptBlock>,
}

/// Agent/session context for multi-agent governance tracking.
///
/// All fields are optional. When provided, they are included in the POST body
/// to /api/v1/govern and returned in the receipt under `session_context`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionContext {
    /// Identifier for the agent making the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Role of the agent: "planner", "worker", or "judge".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    /// Groups all calls from the same agent session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Position in the conversation (1, 2, 3...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_turn: Option<u32>,
}

/// Options for regional and industry-specific PII detection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernOptions {
    pub region: Option<Vec<String>>,
    pub industry: Option<String>,
    /// Optional agent/session context for multi-agent tracking.
    pub session_context: Option<SessionContext>,
}

/// Result of governance operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceResult {
    pub action: GovernanceAction,
    pub output: String,
    pub pii: PIIDetectionResult,
    pub receipt: GovernanceReceipt,
    pub region: Option<Vec<String>>,
    pub industry: Option<String>,
    /// Agent/session context when provided. Omitted from serialised output when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<SessionContext>,
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

/// Detect PII in text and return detection results with redacted text.
///
/// Country profiles are activated from the content itself. Use
/// [`detect_pii_in_regions`] to force a set of profiles on.
pub fn detect_pii(text: &str) -> PIIDetectionResult {
    detect_pii_inner(text, None)
}

/// Detect PII with an explicit set of country profiles instead of inferring
/// them from the content. Region codes are case-insensitive.
pub fn detect_pii_in_regions(text: &str, regions: &[&str]) -> PIIDetectionResult {
    detect_pii_inner(text, Some(regions))
}

/// REDACTION IS ONE PASS. Until 0.3.0 each pattern was redacted with its own
/// `replace_all` over text a previous pattern had already rewritten, while
/// `matches` carried indices into the ORIGINAL text. Two patterns matching
/// overlapping spans could leave half an identifier standing beside a redaction
/// token -- digits exposed in output the caller had been told was redacted.
/// Every match is now collected against the original text, overlaps are
/// resolved before anything is rewritten, and the surviving spans are spliced
/// right to left in a single pass.
fn detect_pii_inner(text: &str, region_override: Option<&[&str]>) -> PIIDetectionResult {
    let patterns = get_pii_patterns();
    let mut matches: Vec<PIIMatch> = Vec::new();
    let mut detected_types: HashSet<PIIType> = HashSet::new();

    // L0: collect every match against the ORIGINAL text.
    let mut l0: Vec<(PIIMatch, &'static str)> = Vec::new();
    for pattern in &patterns {
        for mat in pattern.regex.find_iter(text) {
            if mat.start() == mat.end() {
                continue;
            }
            l0.push((
                PIIMatch {
                    pii_type: pattern.pii_type,
                    // Store placeholder, never the raw PII value.
                    value: "[REDACTED]".to_string(),
                    start_index: mat.start(),
                    end_index: mat.end(),
                },
                pattern.pii_type.redaction(),
            ));
        }
    }

    // Country layer.
    let regions: Vec<String> = match region_override {
        Some(r) if !r.is_empty() => r.iter().map(|c| c.to_uppercase()).collect(),
        _ => pii_country::infer_regions(text)
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
    };
    let region_refs: Vec<&str> = regions.iter().map(|s| s.as_str()).collect();
    let active = pii_country::patterns_for_regions(&region_refs);
    let country_matches = pii_country::detect_country_pii_with(text, &active);

    // Resolve overlaps before anything is rewritten. A country identifier
    // supersedes any L0 span it fully contains -- the cloud does the same,
    // which is how a Saudi national ID stops coming back as [PHONE_REDACTED].
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    let mut spans: Vec<pii_country::RedactionSpan> = Vec::new();
    for c in &country_matches {
        claimed.push((c.start_index, c.end_index));
        spans.push(pii_country::RedactionSpan {
            start_index: c.start_index,
            end_index: c.end_index,
            redaction: c.redaction.to_string(),
        });
    }

    for (m, redaction) in l0 {
        let (s, e) = (m.start_index, m.end_index);
        let overlapping: Vec<(usize, usize)> = claimed
            .iter()
            .copied()
            .filter(|&(rs, re)| s < re && e > rs)
            .collect();
        if !overlapping.is_empty() {
            let swallows_all = overlapping.iter().all(|&(rs, re)| {
                let (cs, ce) = pii_country_trimmed_core(text, rs, re);
                s <= cs && e >= ce
            });
            if !swallows_all {
                continue;
            }
            // An L0 span that fully contains a country span still loses: the
            // country label is the more specific claim.
            let hits_country = overlapping.iter().any(|&(rs, re)| {
                country_matches
                    .iter()
                    .any(|c| c.start_index == rs && c.end_index == re)
            });
            if hits_country {
                continue;
            }
            for o in &overlapping {
                claimed.retain(|c| c != o);
                spans.retain(|sp| (sp.start_index, sp.end_index) != *o);
            }
        }
        claimed.push((s, e));
        spans.push(pii_country::RedactionSpan {
            start_index: s,
            end_index: e,
            redaction: redaction.to_string(),
        });
        detected_types.insert(m.pii_type);
        matches.push(m);
    }

    let redacted_text = pii_country::apply_redactions(text, &spans);

    let mut country_labels: Vec<String> = Vec::new();
    for c in &country_matches {
        if !country_labels.iter().any(|l| l == &c.label) {
            country_labels.push(c.label.to_string());
        }
    }

    matches.sort_by_key(|m| m.start_index);

    PIIDetectionResult {
        has_pii: !matches.is_empty() || !country_matches.is_empty(),
        types: detected_types.into_iter().collect(),
        count: matches.len() + country_matches.len(),
        matches,
        redacted_text,
        country_matches: country_matches.iter().map(Into::into).collect(),
        country_labels,
        regions,
    }
}

/// The span with leading and trailing non-alphanumeric bytes removed.
fn pii_country_trimmed_core(content: &str, start: usize, end: usize) -> (usize, usize) {
    let b = content.as_bytes();
    let mut s = start;
    let mut e = end;
    while s < e && !b[s].is_ascii_alphanumeric() {
        s += 1;
    }
    while e > s && !b[e - 1].is_ascii_alphanumeric() {
        e -= 1;
    }
    if s == e {
        (start, end)
    } else {
        (s, e)
    }
}

// ============================================================================
// Tork Struct
// ============================================================================

/// Main Tork governance struct
pub struct Tork {
    config: TorkConfig,
    stats: TorkStats,
}

impl Tork {
    /// Create a new Tork instance with default configuration
    pub fn new() -> Self {
        Tork {
            config: TorkConfig::default(),
            stats: TorkStats::default(),
        }
    }

    /// Create a new Tork instance with custom configuration
    pub fn with_config(config: TorkConfig) -> Self {
        Tork {
            config,
            stats: TorkStats::default(),
        }
    }

    /// Apply governance with regional and industry-specific detection
    pub fn govern_with_options(&mut self, input: &str, options: GovernOptions) -> GovernanceResult {
        // `options.region` now drives detection. Until 0.4.0 this called
        // govern(input) and then copied region and industry onto the result, so
        // the option was echoed back without ever selecting a pattern.
        let mut result = match options.region.as_ref() {
            Some(regions) if !regions.is_empty() => self.govern_in_regions(input, regions),
            _ => self.govern(input),
        };
        result.region = options.region;
        result.industry = options.industry;
        if options.session_context.is_some() {
            result.receipt.session_context = options.session_context.clone();
            result.session_context = options.session_context;
        }
        result
    }

    /// Apply governance to input text with an explicit set of country profiles.
    pub fn govern_in_regions(&mut self, input: &str, regions: &[String]) -> GovernanceResult {
        self.govern_inner(input, Some(regions))
    }

    /// Apply governance to input text.
    ///
    /// Country profiles are activated from the content itself. To force a set
    /// of profiles on, use [`Tork::govern_with_options`] with
    /// `GovernOptions::region`.
    pub fn govern(&mut self, input: &str) -> GovernanceResult {
        self.govern_inner(input, None)
    }

    fn govern_inner(&mut self, input: &str, regions: Option<&[String]>) -> GovernanceResult {
        let start_time = Instant::now();

        // Detect PII
        let pii = match regions {
            Some(r) if !r.is_empty() => self.detect_pii_internal_in_regions(input, r),
            _ => self.detect_pii_internal(input),
        };

        // Determine action
        let (action, output) = if pii.has_pii {
            let action = self.config.default_action;
            // Always use redacted text when PII is detected — never expose raw input.
            let output = pii.redacted_text.clone();
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
            session_context: None,
            tool_result_scan: None,
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
            region: None,
            industry: None,
            session_context: None,
        }
    }

    /// Internal PII detection.
    ///
    /// Until 0.4.0 this was a second copy of `detect_pii`, carrying the same
    /// sequential-replace bug. It now delegates, so there is one implementation
    /// of the redaction rules and one place to fix them.
    fn detect_pii_internal(&self, text: &str) -> PIIDetectionResult {
        detect_pii(text)
    }

    /// Internal PII detection with an explicit set of country profiles.
    fn detect_pii_internal_in_regions(&self, text: &str, regions: &[String]) -> PIIDetectionResult {
        let refs: Vec<&str> = regions.iter().map(|s| s.as_str()).collect();
        detect_pii_in_regions(text, &refs)
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

    // ========================================================================
    // Parity: SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS (P1)
    // ========================================================================
    //
    // Every SDK checked so far (4/4) had at least one PII type declared in
    // its public type/vocabulary without a live pattern backing it -- a
    // silent detection gap: callers see the type and assume it is scanned
    // for. This test is the standing guard against that gap in this SDK: it
    // fails if `PIIType::all()` (the declared vocabulary) and
    // `get_pii_patterns()` (the live patterns) ever diverge in either
    // direction -- a declared type with no pattern, or a pattern for an
    // undeclared type.
    #[test]
    fn test_parity_all_declared_pii_types_have_live_patterns() {
        let patterns = get_pii_patterns();
        let declared = PIIType::all();

        for pii_type in declared.iter() {
            let pattern = patterns.iter().find(|p| p.pii_type == *pii_type);
            assert!(
                pattern.is_some(),
                "PIIType::{pii_type:?} is declared (in PIIType::all()) but has no pattern in get_pii_patterns() -- \
                 this is exactly the SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS gap"
            );
            // "Live" pattern, not merely present: it must actually compile
            // and match something plausible for its type, and it must
            // redact to the label's own placeholder.
            let pattern = pattern.unwrap();
            assert!(
                !pattern.regex.as_str().is_empty(),
                "PIIType::{pii_type:?}'s pattern is an empty regex"
            );
        }

        assert_eq!(
            patterns.len(),
            declared.len(),
            "pattern count ({}) does not match declared PIIType count ({}) -- a type was added to the enum \
             without a pattern, or a pattern was added for an undeclared type",
            patterns.len(),
            declared.len(),
        );
    }
}
