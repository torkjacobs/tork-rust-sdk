//! Comprehensive tests for Tork Governance Rust SDK
//! Matches Python SDK test coverage

use tork_governance::{
    detect_pii, generate_receipt_id, hash_text, GovernanceAction, PIIDetectionResult, PIIMatch,
    PIIType, Tork, TorkConfig,
};

// ============================================================================
// PIIType Tests
// ============================================================================

#[test]
fn test_pii_type_ssn() {
    assert_eq!(PIIType::Ssn.redaction(), "[SSN_REDACTED]");
}

#[test]
fn test_pii_type_credit_card() {
    assert_eq!(PIIType::CreditCard.redaction(), "[CARD_REDACTED]");
}

#[test]
fn test_pii_type_email() {
    assert_eq!(PIIType::Email.redaction(), "[EMAIL_REDACTED]");
}

#[test]
fn test_pii_type_phone() {
    assert_eq!(PIIType::Phone.redaction(), "[PHONE_REDACTED]");
}

#[test]
fn test_pii_type_address() {
    assert_eq!(PIIType::Address.redaction(), "[ADDRESS_REDACTED]");
}

#[test]
fn test_pii_type_ip_address() {
    assert_eq!(PIIType::IpAddress.redaction(), "[IP_REDACTED]");
}

#[test]
fn test_pii_type_dob() {
    assert_eq!(PIIType::DateOfBirth.redaction(), "[DOB_REDACTED]");
}

#[test]
fn test_pii_type_passport() {
    assert_eq!(PIIType::Passport.redaction(), "[PASSPORT_REDACTED]");
}

#[test]
fn test_pii_type_drivers_license() {
    assert_eq!(PIIType::DriversLicense.redaction(), "[DL_REDACTED]");
}

#[test]
fn test_pii_type_bank_account() {
    assert_eq!(PIIType::BankAccount.redaction(), "[ACCOUNT_REDACTED]");
}

// ============================================================================
// GovernanceAction Tests
// ============================================================================

#[test]
fn test_governance_action_default() {
    let action = GovernanceAction::default();
    assert_eq!(action, GovernanceAction::Redact);
}

#[test]
fn test_governance_action_allow() {
    let action = GovernanceAction::Allow;
    assert_eq!(action, GovernanceAction::Allow);
}

#[test]
fn test_governance_action_deny() {
    let action = GovernanceAction::Deny;
    assert_eq!(action, GovernanceAction::Deny);
}

#[test]
fn test_governance_action_redact() {
    let action = GovernanceAction::Redact;
    assert_eq!(action, GovernanceAction::Redact);
}

#[test]
fn test_governance_action_escalate() {
    let action = GovernanceAction::Escalate;
    assert_eq!(action, GovernanceAction::Escalate);
}

// ============================================================================
// Utility Functions Tests
// ============================================================================

#[test]
fn test_hash_text_prefix() {
    let hash = hash_text("test");
    assert!(hash.starts_with("sha256:"));
}

#[test]
fn test_hash_text_consistent() {
    let hash1 = hash_text("test");
    let hash2 = hash_text("test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_hash_text_different_inputs() {
    let hash1 = hash_text("test1");
    let hash2 = hash_text("test2");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_hash_text_length() {
    let hash = hash_text("test");
    let hex_part = hash.replace("sha256:", "");
    assert_eq!(hex_part.len(), 64);
}

#[test]
fn test_hash_text_empty() {
    let hash = hash_text("");
    assert!(hash.starts_with("sha256:"));
}

#[test]
fn test_hash_text_unicode() {
    let hash = hash_text("Hello \u{4e16}\u{754c}");
    assert!(hash.starts_with("sha256:"));
}

#[test]
fn test_generate_receipt_id_prefix() {
    let id = generate_receipt_id();
    assert!(id.starts_with("rcpt_"));
}

#[test]
fn test_generate_receipt_id_unique() {
    let id1 = generate_receipt_id();
    let id2 = generate_receipt_id();
    assert_ne!(id1, id2);
}

#[test]
fn test_generate_receipt_id_multiple_unique() {
    let mut ids = std::collections::HashSet::new();
    for _ in 0..100 {
        ids.insert(generate_receipt_id());
    }
    assert_eq!(ids.len(), 100);
}

// ============================================================================
// detect_pii Tests
// ============================================================================

#[test]
fn test_detect_pii_ssn() {
    let result = detect_pii("My SSN is 123-45-6789");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::Ssn));
}

#[test]
fn test_detect_pii_email() {
    let result = detect_pii("Contact me at john@example.com");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::Email));
}

#[test]
fn test_detect_pii_credit_card() {
    let result = detect_pii("Card: 4111-1111-1111-1111");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::CreditCard));
}

#[test]
fn test_detect_pii_phone() {
    let result = detect_pii("Call me at 555-123-4567");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::Phone));
}

#[test]
fn test_detect_pii_ip_address() {
    let result = detect_pii("Server IP: 192.168.1.1");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::IpAddress));
}

#[test]
fn test_detect_pii_dob() {
    let result = detect_pii("DOB: 01/15/1990");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::DateOfBirth));
}

#[test]
fn test_detect_pii_no_pii() {
    let result = detect_pii("Hello world, no sensitive data here");
    assert!(!result.has_pii);
    assert_eq!(result.count, 0);
}

#[test]
fn test_detect_pii_multiple_types() {
    let result = detect_pii("SSN: 123-45-6789, Email: test@test.com");
    assert!(result.has_pii);
    assert!(result.types.contains(&PIIType::Ssn));
    assert!(result.types.contains(&PIIType::Email));
    assert_eq!(result.count, 2);
}

#[test]
fn test_detect_pii_redacts_ssn() {
    let result = detect_pii("My SSN is 123-45-6789");
    assert_eq!(result.redacted_text, "My SSN is [SSN_REDACTED]");
}

#[test]
fn test_detect_pii_redacts_email() {
    let result = detect_pii("Contact: john@example.com");
    assert_eq!(result.redacted_text, "Contact: [EMAIL_REDACTED]");
}

#[test]
fn test_detect_pii_redacts_credit_card() {
    let result = detect_pii("Card: 4111-1111-1111-1111");
    assert_eq!(result.redacted_text, "Card: [CARD_REDACTED]");
}

#[test]
fn test_detect_pii_redacts_multiple() {
    let result = detect_pii("SSN: 123-45-6789, Another: 987-65-4321");
    assert_eq!(result.count, 2);
    assert!(result.redacted_text.contains("[SSN_REDACTED]"));
}

#[test]
fn test_detect_pii_empty_string() {
    let result = detect_pii("");
    assert!(!result.has_pii);
    assert_eq!(result.count, 0);
    assert_eq!(result.redacted_text, "");
}

#[test]
fn test_detect_pii_match_indices() {
    let result = detect_pii("SSN: 123-45-6789");
    assert!(!result.matches.is_empty());
    assert!(result.matches[0].start_index < result.matches[0].end_index);
}

// ============================================================================
// Tork Struct Tests
// ============================================================================

#[test]
fn test_tork_new() {
    let tork = Tork::new();
    let config = tork.get_config();
    assert_eq!(config.policy_version, "1.0.0");
    assert_eq!(config.default_action, GovernanceAction::Redact);
}

#[test]
fn test_tork_with_config() {
    let config = TorkConfig {
        policy_version: "2.0.0".to_string(),
        default_action: GovernanceAction::Deny,
    };
    let tork = Tork::with_config(config);
    assert_eq!(tork.get_config().policy_version, "2.0.0");
    assert_eq!(tork.get_config().default_action, GovernanceAction::Deny);
}

#[test]
fn test_tork_default() {
    let tork = Tork::default();
    assert_eq!(tork.get_config().policy_version, "1.0.0");
}

#[test]
fn test_tork_govern_no_pii() {
    let mut tork = Tork::new();
    let result = tork.govern("Hello world");
    assert_eq!(result.action, GovernanceAction::Allow);
    assert_eq!(result.output, "Hello world");
}

#[test]
fn test_tork_govern_with_pii() {
    let mut tork = Tork::new();
    let result = tork.govern("My SSN is 123-45-6789");
    assert_eq!(result.action, GovernanceAction::Redact);
    assert_eq!(result.output, "My SSN is [SSN_REDACTED]");
}

#[test]
fn test_tork_govern_has_receipt() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    assert!(result.receipt.receipt_id.starts_with("rcpt_"));
}

#[test]
fn test_tork_govern_has_pii_result() {
    let mut tork = Tork::new();
    let result = tork.govern("SSN: 123-45-6789");
    assert!(result.pii.has_pii);
}

#[test]
fn test_tork_govern_receipt_hashes() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    assert!(result.receipt.input_hash.starts_with("sha256:"));
    assert!(result.receipt.output_hash.starts_with("sha256:"));
}

#[test]
fn test_tork_govern_deny_action() {
    let config = TorkConfig {
        policy_version: "1.0.0".to_string(),
        default_action: GovernanceAction::Deny,
    };
    let mut tork = Tork::with_config(config);
    let result = tork.govern("SSN: 123-45-6789");
    assert_eq!(result.action, GovernanceAction::Deny);
    assert_eq!(result.output, "SSN: 123-45-6789");
}

#[test]
fn test_tork_govern_multiple() {
    let mut tork = Tork::new();
    tork.govern("test1");
    tork.govern("test2");
    assert_eq!(tork.get_stats().total_calls, 2);
}

// ============================================================================
// Stats Tests
// ============================================================================

#[test]
fn test_tork_stats_initial() {
    let tork = Tork::new();
    let stats = tork.get_stats();
    assert_eq!(stats.total_calls, 0);
    assert_eq!(stats.total_pii_detected, 0);
}

#[test]
fn test_tork_stats_tracks_calls() {
    let mut tork = Tork::new();
    tork.govern("test");
    tork.govern("test2");
    assert_eq!(tork.get_stats().total_calls, 2);
}

#[test]
fn test_tork_stats_tracks_pii_detected() {
    let mut tork = Tork::new();
    tork.govern("SSN: 123-45-6789");
    tork.govern("clean text");
    assert_eq!(tork.get_stats().total_pii_detected, 1);
}

#[test]
fn test_tork_stats_tracks_action_counts() {
    let mut tork = Tork::new();
    tork.govern("SSN: 123-45-6789");
    tork.govern("clean text");
    let stats = tork.get_stats();
    assert_eq!(stats.action_counts.redact, 1);
    assert_eq!(stats.action_counts.allow, 1);
}

#[test]
fn test_tork_reset_stats() {
    let mut tork = Tork::new();
    tork.govern("SSN: 123-45-6789");
    tork.govern("test");
    tork.reset_stats();
    let stats = tork.get_stats();
    assert_eq!(stats.total_calls, 0);
    assert_eq!(stats.total_pii_detected, 0);
}

#[test]
fn test_tork_reset_stats_action_counts() {
    let mut tork = Tork::new();
    tork.govern("SSN: 123-45-6789");
    tork.reset_stats();
    assert_eq!(tork.get_stats().action_counts.redact, 0);
}

// ============================================================================
// Config Tests
// ============================================================================

#[test]
fn test_tork_get_config() {
    let tork = Tork::new();
    let config = tork.get_config();
    assert!(!config.policy_version.is_empty());
}

#[test]
fn test_tork_set_config() {
    let mut tork = Tork::new();
    let new_config = TorkConfig {
        policy_version: "3.0.0".to_string(),
        default_action: GovernanceAction::Escalate,
    };
    tork.set_config(new_config);
    assert_eq!(tork.get_config().policy_version, "3.0.0");
    assert_eq!(tork.get_config().default_action, GovernanceAction::Escalate);
}

#[test]
fn test_tork_config_default() {
    let config = TorkConfig::default();
    assert_eq!(config.policy_version, "1.0.0");
    assert_eq!(config.default_action, GovernanceAction::Redact);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_tork_govern_long_text() {
    let mut tork = Tork::new();
    let long_text = "A".repeat(100000);
    let result = tork.govern(&long_text);
    assert_eq!(result.action, GovernanceAction::Allow);
}

#[test]
fn test_tork_govern_unicode() {
    let mut tork = Tork::new();
    let result = tork.govern("Hello \u{4e16}\u{754c}, SSN: 123-45-6789");
    assert!(result.pii.has_pii);
}

#[test]
fn test_tork_govern_special_chars() {
    let mut tork = Tork::new();
    let result = tork.govern("Special chars: !@#$%^&*()");
    assert_eq!(result.action, GovernanceAction::Allow);
}

#[test]
fn test_tork_govern_newlines() {
    let mut tork = Tork::new();
    let result = tork.govern("Line1\nLine2\nSSN: 123-45-6789");
    assert!(result.pii.has_pii);
}

#[test]
fn test_tork_govern_tabs() {
    let mut tork = Tork::new();
    let result = tork.govern("Tab\there\tSSN: 123-45-6789");
    assert!(result.pii.has_pii);
}

#[test]
fn test_tork_govern_repeated() {
    let mut tork = Tork::new();
    for _ in 0..100 {
        let result = tork.govern("Test");
        assert!(result.receipt.receipt_id.starts_with("rcpt_"));
    }
    assert_eq!(tork.get_stats().total_calls, 100);
}

#[test]
fn test_tork_govern_empty() {
    let mut tork = Tork::new();
    let result = tork.govern("");
    assert_eq!(result.action, GovernanceAction::Allow);
}

// ============================================================================
// Receipt Tests
// ============================================================================

#[test]
fn test_receipt_unique_ids() {
    let mut tork = Tork::new();
    let result1 = tork.govern("test1");
    let result2 = tork.govern("test2");
    assert_ne!(result1.receipt.receipt_id, result2.receipt.receipt_id);
}

#[test]
fn test_receipt_has_timestamp() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    assert!(!result.receipt.timestamp.to_string().is_empty());
}

#[test]
fn test_receipt_has_policy_version() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    assert_eq!(result.receipt.policy_version, "1.0.0");
}

#[test]
fn test_receipt_has_processing_time() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    // Processing time should be non-negative
    assert!(result.receipt.processing_time_ns >= 0);
}

#[test]
fn test_receipt_has_action() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    let valid_actions = [
        GovernanceAction::Allow,
        GovernanceAction::Deny,
        GovernanceAction::Redact,
        GovernanceAction::Escalate,
    ];
    assert!(valid_actions.contains(&result.receipt.action));
}

// ============================================================================
// Serialization Tests
// ============================================================================

#[test]
fn test_pii_type_serialize() {
    let serialized = serde_json::to_string(&PIIType::Ssn).unwrap();
    assert!(serialized.contains("ssn"));
}

#[test]
fn test_governance_action_serialize() {
    let serialized = serde_json::to_string(&GovernanceAction::Redact).unwrap();
    assert!(serialized.contains("redact"));
}

#[test]
fn test_tork_config_serialize() {
    let config = TorkConfig::default();
    let serialized = serde_json::to_string(&config).unwrap();
    assert!(serialized.contains("policy_version"));
}

#[test]
fn test_governance_result_serialize() {
    let mut tork = Tork::new();
    let result = tork.govern("test");
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(serialized.contains("action"));
    assert!(serialized.contains("output"));
}
