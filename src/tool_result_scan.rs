//! Tool-result scanning (DECIDED-TACT2-V2-C), ported from
//! `tork-js-sdk/src/tool-result-scan.ts` (via the same RE2-class rewrite
//! already applied by `tork-go-sdk/toolresultscan.go`, since Rust's `regex`
//! crate is RE2-based like Go's `regexp` — no lookaround, no backreferences).
//!
//! A tool result returned by an MCP server -- or by any external system the
//! caller does not control -- is untrusted input that is about to be
//! appended to a model's context. [`scan_tool_result`] scans it BEFORE that
//! happens, on-device, for two things:
//!
//!  1. PII, using the SAME on-device detector as [`crate::Tork::govern`]
//!     ([`crate::detect_pii`]). Nothing new was written for this: same
//!     patterns, same redaction labels, same zero-network guarantee.
//!  2. Prompt injection, using the conservative heuristic pattern set below.
//!     Every injection finding is labelled `heuristic:<type>` so no caller
//!     can mistake a regex hit for a verified determination.
//!
//! ZERO NETWORK. This crate has no HTTP client dependency at all, so nothing
//! in this module -- or anywhere else in the crate -- can make a network
//! call. The payload never leaves the machine.
//!
//! WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
//! the caller attests to. It is not gateway-side enforcement -- a
//! compromised or simply careless caller can skip it entirely, and Tork
//! cannot tell. Enforcement at the gateway, where skipping is not an
//! option, is a separate and later control.
//!
//! PARITY TIER: this port matches **Tier 1** of the JS SDK -- the 10-type
//! basic PII vocabulary (`ssn`, `credit_card`, `email`, `phone`, `address`,
//! `ip_address`, `date_of_birth`, `passport`, `drivers_license`,
//! `bank_account`) with JS-identical labels and redaction markers. It does
//! NOT carry the Python SDK's regional/industry pattern tier (AU/US/GB/EU/
//! AE/... profiles). This crate's `GovernOptions::region` /
//! `GovernOptions::industry` are a separate, older mechanism (see the
//! crate-level README note on their current implementation status) and are
//! not wired into `scan_tool_result`.
//!
//! ## Rust-specific traversal notes
//!
//! `serde_json::Value` owns its data -- unlike JS objects (which can hold
//! circular references) or Go maps/slices (reference types with pointer
//! identity), a `serde_json::Value` tree is a plain owned tree and cannot
//! contain a cycle by construction. So there is no `seen`/`WeakSet`-style
//! cycle guard here: it would have nothing to guard against. `max_depth`
//! still bounds recursion, exactly as it does in the JS/Go ports.
//!
//! Likewise, the JS port returns the exact same object/array reference for
//! a subtree that contains no matches (a property of JS's and Go's
//! reference-semantic collections), so a clean payload comes back `===`
//! its input. `serde_json::Value` has no such reference identity to
//! preserve: every leaf must be visited regardless (to run the scan), and
//! handing the result back to an independent, owned [`ToolResultScanResult`]
//! requires an owned tree either way. This port therefore always builds a
//! fresh `serde_json::Value` tree bottom-up. The observable contract is
//! identical (`sanitized` is content-equal to `payload` when nothing
//! matched, and `payload` itself is never mutated -- `scan_tool_result`
//! only ever borrows it); only the never-observable allocation-identity
//! behavior differs, and that difference is deliberate rather than an
//! oversight.

use crate::{detect_pii, generate_receipt_id, hash_text, GovernanceAction, GovernanceReceipt, PIIType, Tork};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

// ============================================================================
// Types
// ============================================================================

/// 'pii' -- a detector match. 'injection' -- a heuristic pattern match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultFindingKind {
    Pii,
    Injection,
}

/// One (kind, type, location) match tally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResultFinding {
    /// 'pii' for a detector match, 'injection' for a heuristic pattern match.
    pub kind: ToolResultFindingKind,
    /// For `kind: Pii`, a [`PIIType`] label (`"ssn"`, `"email"`, ...). For
    /// `kind: Injection`, always `heuristic:<name>` -- the prefix is part of
    /// the value, not decoration, so a downstream reader of a receipt cannot
    /// mistake a pattern hit for a verified determination.
    pub r#type: String,
    /// Number of matches of this (kind, type) at this location.
    pub count: usize,
    /// JSON path of the string the matches were found in, e.g. `$.content[0].text`.
    pub location: String,
}

/// Input to [`scan_tool_result`].
#[derive(Debug, Clone)]
pub struct ToolResultScanInput {
    /// Name of the tool that produced this result. Recorded on the receipt.
    pub tool_name: String,
    /// URI of the MCP server (or other origin). Recorded on the receipt when present.
    pub server_uri: Option<String>,
    /// The tool result itself. Any JSON-shaped value; never leaves the machine.
    pub payload: serde_json::Value,
}

/// Optional parameters to [`scan_tool_result`].
#[derive(Debug, Clone, Default)]
pub struct ToolResultScanOptions {
    /// Block the result when the injection heuristics fire. Default false:
    /// detect and report, let the caller decide. When true and an injection
    /// pattern matches, `blocked` is true, `reason` is set, and `sanitized`
    /// is `Value::Null` -- there is deliberately no masked payload to
    /// accidentally append.
    pub block_on_injection: bool,
    /// Extra redaction patterns, same shape and semantics as the JS SDK's
    /// `TorkConfig.customPatterns`. NOTE (inherited from `detect_pii`):
    /// custom patterns redact but are not counted, so they can change
    /// `sanitized` without producing a finding.
    pub custom_patterns: Option<HashMap<String, Regex>>,
    /// Maximum nesting depth to walk. Deeper values are passed through
    /// unscanned and unmodified. `None` means the default (32).
    pub max_depth: Option<usize>,
}

/// Result of [`scan_tool_result`].
#[derive(Debug, Clone)]
pub struct ToolResultScanResult {
    /// The payload with PII masked in place, structurally identical
    /// otherwise. `Value::Null` when `blocked` is true.
    pub sanitized: serde_json::Value,
    pub findings: Vec<ToolResultFinding>,
    pub blocked: bool,
    /// Present only when blocked.
    pub reason: Option<String>,
}

// ============================================================================
// Injection heuristics
// ============================================================================

/// Prefix on every injection finding's `type`. Not cosmetic: these patterns
/// are regexes over untrusted text, they carry false positives and false
/// negatives, and the label travels with the finding into the receipt.
pub const INJECTION_HEURISTIC_PREFIX: &str = "heuristic:";

/// Identifies this exact pattern set in receipts. Bump when the patterns
/// change, so a receipt says which ruleset produced its counts. Every SDK
/// mirroring this implementation must emit the SAME value for the same
/// ruleset -- it is a shared identifier, not a per-language one.
pub const INJECTION_RULESET: &str = "tork-injection-heuristics-v1";

/// Distinct injection types the ruleset can emit, for documentation/tests.
pub const INJECTION_TYPES: [&str; 3] = ["exfiltration_url", "instruction_override", "role_reassignment"];

const DEFAULT_MAX_DEPTH: usize = 32;

struct InjectionPattern {
    type_name: &'static str,
    regex: Regex,
}

/// Conservative on purpose. Each pattern targets a phrase that has no
/// plausible reason to appear in a legitimate tool result -- a database row,
/// a search hit, a file listing. Broader "suspicious language" matching
/// would fire on ordinary documentation and support tickets, and an alert
/// nobody believes is worse than no alert.
///
/// Regex SOURCE STRINGS are ported byte-for-byte from the JS patterns
/// (modulo the flag rewrite below, which changes nothing about what a
/// pattern matches): JS `/pattern/gi` becomes Rust `"(?i)pattern"` and
/// `/pattern/gim` becomes `"(?im)pattern"`, since the `regex` crate has no
/// separate flags argument and JS's "global" is just how `find_iter`
/// already behaves. None of these patterns use lookaround or backreferences,
/// so none needed a lookaround substitution: RE2 (which the `regex` crate
/// uses, and which has no lookaround support at all) accepts every one of
/// them unchanged.
fn get_injection_patterns() -> Vec<InjectionPattern> {
    vec![
        // -- instruction override --------------------------------------------
        InjectionPattern {
            type_name: "instruction_override",
            regex: Regex::new(r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b").unwrap(),
        },
        InjectionPattern {
            type_name: "instruction_override",
            regex: Regex::new(r"(?i)\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b").unwrap(),
        },
        InjectionPattern {
            type_name: "instruction_override",
            regex: Regex::new(r"(?i)\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b").unwrap(),
        },
        // -- role reassignment ------------------------------------------------
        InjectionPattern {
            type_name: "role_reassignment",
            regex: Regex::new(r"(?i)\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b").unwrap(),
        },
        InjectionPattern {
            type_name: "role_reassignment",
            regex: Regex::new(r"(?i)\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b").unwrap(),
        },
        InjectionPattern {
            type_name: "role_reassignment",
            regex: Regex::new(r"(?i)\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:").unwrap(),
        },
        InjectionPattern {
            type_name: "role_reassignment",
            regex: Regex::new(r"(?i)\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b").unwrap(),
        },
        InjectionPattern {
            type_name: "role_reassignment",
            regex: Regex::new(r"(?i)\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b").unwrap(),
        },
        InjectionPattern {
            // A role header smuggled into content -- "system:" / "<|im_start|>system"
            // at the start of a line is a conversation-structure forgery, not prose.
            type_name: "role_reassignment",
            regex: Regex::new(r"(?im)^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)").unwrap(),
        },
        // -- exfiltration -----------------------------------------------------
        InjectionPattern {
            // A markdown image/link whose URL carries the content out as a query
            // parameter -- the classic zero-click exfiltration shape.
            type_name: "exfiltration_url",
            regex: Regex::new(r"(?i)!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)").unwrap(),
        },
        InjectionPattern {
            type_name: "exfiltration_url",
            regex: Regex::new(r"(?i)\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=").unwrap(),
        },
        InjectionPattern {
            type_name: "exfiltration_url",
            regex: Regex::new(r"(?i)\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+").unwrap(),
        },
    ]
}

// ============================================================================
// Traversal
// ============================================================================

fn is_identifier(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn child_path(parent: &str, key: &str) -> String {
    if is_identifier(key) {
        format!("{parent}.{key}")
    } else {
        format!("{}[{}]", parent, serde_json::to_string(key).unwrap())
    }
}

/// Scan one string: PII (via the shared detector) then injection heuristics.
/// Returns the masked string plus any findings, both keyed to `location`.
fn scan_string(
    text: &str,
    location: &str,
    custom_patterns: Option<&HashMap<String, Regex>>,
    findings: &mut Vec<ToolResultFinding>,
) -> String {
    let pii = detect_pii(text);

    if pii.count > 0 {
        // Counts per type, emitted in a stable (sorted) order so two runs
        // over the same payload produce identical findings.
        let mut per_type: HashMap<PIIType, usize> = HashMap::new();
        for m in &pii.matches {
            *per_type.entry(m.pii_type).or_insert(0) += 1;
        }
        let mut labeled: Vec<(&'static str, usize)> =
            per_type.into_iter().map(|(t, count)| (t.label(), count)).collect();
        labeled.sort_by_key(|(label, _)| *label);
        for (label, count) in labeled {
            findings.push(ToolResultFinding {
                kind: ToolResultFindingKind::Pii,
                r#type: label.to_string(),
                count,
                location: location.to_string(),
            });
        }
    }

    let mut per_injection: HashMap<&'static str, usize> = HashMap::new();
    for pattern in get_injection_patterns() {
        let count = pattern.regex.find_iter(text).count();
        if count > 0 {
            *per_injection.entry(pattern.type_name).or_insert(0) += count;
        }
    }
    let mut injection_types: Vec<&'static str> = per_injection.keys().copied().collect();
    injection_types.sort_unstable();
    for type_name in injection_types {
        findings.push(ToolResultFinding {
            kind: ToolResultFindingKind::Injection,
            r#type: format!("{INJECTION_HEURISTIC_PREFIX}{type_name}"),
            count: per_injection[type_name],
            location: location.to_string(),
        });
    }

    let mut redacted = pii.redacted_text;

    // Extra caller-supplied patterns, applied AFTER default detection and
    // redaction, for redaction only -- they never produce a finding. Applied
    // in sorted-name order for determinism, matching the Go port.
    if let Some(custom) = custom_patterns {
        let mut names: Vec<&String> = custom.keys().collect();
        names.sort();
        for name in names {
            let regex = &custom[name];
            let replacement = format!("[{}_REDACTED]", name.to_uppercase());
            redacted = regex.replace_all(&redacted, replacement.as_str()).into_owned();
        }
    }

    redacted
}

/// Walk the payload, scanning every string, and build a fresh
/// `serde_json::Value` tree with PII masked in place. See the module-level
/// docs for why this always constructs a new tree rather than trying to
/// replicate JS/Go's reference-identity reuse.
///
/// Only strings are scanned. Numbers, booleans, and null pass through
/// untouched -- a bank account stored as a JSON number is NOT detected.
fn walk(
    value: &serde_json::Value,
    location: &str,
    depth: usize,
    max_depth: usize,
    custom_patterns: Option<&HashMap<String, Regex>>,
    findings: &mut Vec<ToolResultFinding>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(scan_string(s, location, custom_patterns, findings))
        }
        serde_json::Value::Array(arr) if depth < max_depth => {
            let items = arr
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let child_loc = format!("{location}[{i}]");
                    walk(item, &child_loc, depth + 1, max_depth, custom_patterns, findings)
                })
                .collect();
            serde_json::Value::Array(items)
        }
        serde_json::Value::Object(map) if depth < max_depth => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, item) in map.iter() {
                let child_loc = child_path(location, key);
                out.insert(
                    key.clone(),
                    walk(item, &child_loc, depth + 1, max_depth, custom_patterns, findings),
                );
            }
            serde_json::Value::Object(out)
        }
        // Numbers, booleans, null, or an array/object at/past max_depth:
        // passed through unscanned and unmodified.
        _ => value.clone(),
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Scan a tool result for PII and prompt injection before it is appended to
/// model context. Pure and synchronous: makes no network call, and cannot
/// mutate `input.payload` (it is only ever borrowed).
///
/// For the receipt-linked form (`attested_by: "client"`,
/// `capture_mode: "edge"`), use [`Tork::scan_tool_result`], which wraps this
/// and records the scan.
pub fn scan_tool_result(
    input: &ToolResultScanInput,
    options: &ToolResultScanOptions,
) -> ToolResultScanResult {
    let max_depth = options.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
    let mut findings = Vec::new();
    let sanitized = walk(
        &input.payload,
        "$",
        0,
        max_depth,
        options.custom_patterns.as_ref(),
        &mut findings,
    );

    let injection_count: usize = findings
        .iter()
        .filter(|f| f.kind == ToolResultFindingKind::Injection)
        .map(|f| f.count)
        .sum();
    let blocked = options.block_on_injection && injection_count > 0;

    if blocked {
        let mut types: Vec<&str> = findings
            .iter()
            .filter(|f| f.kind == ToolResultFindingKind::Injection)
            .map(|f| f.r#type.as_str())
            .collect();
        types.sort_unstable();
        types.dedup();

        let reason = format!(
            "Blocked: {} prompt-injection heuristic match(es) [{}] in the result of tool \"{}\". \
             These are heuristic pattern matches ({}), not a verified determination. sanitized is \
             null so no masked copy can be appended to context by accident.",
            injection_count,
            types.join(", "),
            input.tool_name,
            INJECTION_RULESET,
        );

        return ToolResultScanResult {
            sanitized: serde_json::Value::Null,
            findings,
            blocked: true,
            reason: Some(reason),
        };
    }

    ToolResultScanResult {
        sanitized,
        findings,
        blocked: false,
        reason: None,
    }
}

// ============================================================================
// Receipt block
// ============================================================================

/// Counts by type for one finding kind. `injection` type keys keep their
/// `heuristic:` prefix. A `BTreeMap` is used (rather than `HashMap`)
/// specifically so key order is alphabetical on serialization, with no
/// separate sort step needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultScanFindingCounts {
    pub injection: BTreeMap<String, usize>,
    pub pii: BTreeMap<String, usize>,
}

/// Total match count per kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultScanTotals {
    pub injection: usize,
    pub pii: usize,
}

/// The `tool_result_scan` block recorded on the receipt.
///
/// snake_case, keys emitted in alphabetical order -- guaranteed here by
/// declaring the struct fields in alphabetical order, since `serde_json`
/// serializes struct fields in declaration order -- optional keys OMITTED
/// entirely rather than emitted null (`reason`, `server_uri`). The same
/// discipline as the JS SDK's TORK-DNA-v2 canonical form, and for the same
/// reason: every SDK that mirrors this must produce a byte-identical block
/// for the same scan.
///
/// It carries COUNTS ONLY. No payload, no matched substring, no location
/// path, no tool argument ever appears here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultScanReceiptBlock {
    /// Always `"client"`. This scan ran in the caller's process; Tork did not execute it.
    pub attested_by: String,
    pub blocked: bool,
    /// Always `"edge"` -- the capture_mode this SDK's client-side work is recorded under.
    pub capture_mode: String,
    pub findings: ToolResultScanFindingCounts,
    /// Identifier of the injection ruleset that produced the injection counts.
    pub injection_ruleset: String,
    /// Present only when blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Always `"rust"`.
    pub sdk_language: String,
    pub sdk_version: String,
    /// Present only when the caller supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_uri: Option<String>,
    pub tool_name: String,
    pub totals: ToolResultScanTotals,
}

fn counts_by_type(findings: &[ToolResultFinding], kind: ToolResultFindingKind) -> BTreeMap<String, usize> {
    let mut totals: BTreeMap<String, usize> = BTreeMap::new();
    for finding in findings {
        if finding.kind != kind {
            continue;
        }
        *totals.entry(finding.r#type.clone()).or_insert(0) += finding.count;
    }
    totals
}

/// Parameters to [`build_tool_result_scan_block`].
pub struct BuildToolResultScanBlockParams<'a> {
    pub tool_name: &'a str,
    pub server_uri: Option<&'a str>,
    pub result: &'a ToolResultScanResult,
    pub sdk_version: &'a str,
}

/// Build the receipt block for a completed scan. Field declaration order
/// above IS the emitted key order: alphabetical, with optional keys omitted.
pub fn build_tool_result_scan_block(params: BuildToolResultScanBlockParams) -> ToolResultScanReceiptBlock {
    let pii = counts_by_type(&params.result.findings, ToolResultFindingKind::Pii);
    let injection = counts_by_type(&params.result.findings, ToolResultFindingKind::Injection);
    let pii_total: usize = pii.values().sum();
    let injection_total: usize = injection.values().sum();

    ToolResultScanReceiptBlock {
        attested_by: "client".to_string(),
        blocked: params.result.blocked,
        capture_mode: "edge".to_string(),
        findings: ToolResultScanFindingCounts { injection, pii },
        injection_ruleset: INJECTION_RULESET.to_string(),
        reason: params.result.reason.clone(),
        sdk_language: "rust".to_string(),
        sdk_version: params.sdk_version.to_string(),
        server_uri: params.server_uri.map(|s| s.to_string()),
        tool_name: params.tool_name.to_string(),
        totals: ToolResultScanTotals {
            injection: injection_total,
            pii: pii_total,
        },
    }
}

/// Distinct PII types in a scan result, for the attestation canonical form.
pub fn scan_pii_types(findings: &[ToolResultFinding]) -> Vec<String> {
    let mut types: Vec<String> = findings
        .iter()
        .filter(|f| f.kind == ToolResultFindingKind::Pii)
        .map(|f| f.r#type.clone())
        .collect();
    types.sort();
    types.dedup();
    types
}

/// Total PII match count in a scan result.
pub fn scan_pii_count(findings: &[ToolResultFinding]) -> usize {
    findings
        .iter()
        .filter(|f| f.kind == ToolResultFindingKind::Pii)
        .map(|f| f.count)
        .sum()
}

/// Total injection match count in a scan result.
pub fn scan_injection_count(findings: &[ToolResultFinding]) -> usize {
    findings
        .iter()
        .filter(|f| f.kind == ToolResultFindingKind::Injection)
        .map(|f| f.count)
        .sum()
}

// ============================================================================
// Client (Tork) linkage
// ============================================================================

/// Outcome of [`Tork::scan_tool_result`]: the scan result plus the
/// [`GovernanceReceipt`] that records it.
#[derive(Debug, Clone)]
pub struct ScanToolResultOutcome {
    pub sanitized: serde_json::Value,
    pub findings: Vec<ToolResultFinding>,
    pub blocked: bool,
    /// Present only when blocked.
    pub reason: Option<String>,
    pub receipt: GovernanceReceipt,
}

/// The four-way action mapping shared with the JS and Go SDKs: blocked ->
/// deny, an injection finding present -> escalate, otherwise a PII finding
/// present -> redact, otherwise -> allow. Injection takes priority over PII
/// when a scan contains both, matching a payload that is both leaking data
/// and carrying an attempted takeover.
fn tool_result_scan_action(scan: &ToolResultScanResult) -> GovernanceAction {
    if scan.blocked {
        return GovernanceAction::Deny;
    }

    let mut has_injection = false;
    let mut has_pii = false;
    for finding in &scan.findings {
        match finding.kind {
            ToolResultFindingKind::Injection => has_injection = true,
            ToolResultFindingKind::Pii => has_pii = true,
        }
    }

    if has_injection {
        GovernanceAction::Escalate
    } else if has_pii {
        GovernanceAction::Redact
    } else {
        GovernanceAction::Allow
    }
}

impl Tork {
    /// Scan a tool result for PII and prompt injection, then record the scan
    /// as a [`GovernanceReceipt`] carrying a `tool_result_scan` block
    /// (`attested_by: "client"`, `capture_mode: "edge"`).
    ///
    /// The action on the returned receipt follows the four-way mapping in
    /// [`tool_result_scan_action`]. Statistics ([`Tork::get_stats`]) are
    /// updated exactly as `govern` updates them: one call, one
    /// PII-detected flag, one action tally.
    pub fn scan_tool_result(
        &mut self,
        input: ToolResultScanInput,
        options: ToolResultScanOptions,
    ) -> ScanToolResultOutcome {
        let start_time = Instant::now();

        let scan = scan_tool_result(&input, &options);
        let action = tool_result_scan_action(&scan);

        // NOTE (Rust-specific, not part of the byte-identical tool_result_scan
        // block contract): hashing a canonical JSON encoding of the
        // payload/sanitized value for the receipt's input_hash/output_hash is
        // this SDK's own choice for those two Receipt-level fields (mirroring
        // the Go port's same choice), consistent with how `govern` already
        // hashes text. It does not affect the tool_result_scan block itself,
        // which carries counts only. serde_json's default (non-preserve_order)
        // Map is BTreeMap-backed, so `.to_string()` here is deterministic
        // regardless of the payload's original key order.
        let input_hash = hash_text(&input.payload.to_string());
        let output_hash = if scan.blocked {
            hash_text("")
        } else {
            hash_text(&scan.sanitized.to_string())
        };

        let processing_time_ns = start_time.elapsed().as_nanos() as u64;

        let block = build_tool_result_scan_block(BuildToolResultScanBlockParams {
            tool_name: &input.tool_name,
            server_uri: input.server_uri.as_deref(),
            result: &scan,
            sdk_version: crate::SDK_VERSION,
        });

        let receipt = GovernanceReceipt {
            receipt_id: generate_receipt_id(),
            timestamp: Utc::now(),
            input_hash,
            output_hash,
            action,
            policy_version: self.get_config().policy_version.clone(),
            processing_time_ns,
            session_context: None,
            tool_result_scan: Some(block),
        };

        self.stats.total_calls += 1;
        if scan_pii_count(&scan.findings) > 0 {
            self.stats.total_pii_detected += 1;
        }
        self.stats.total_processing_time_ns += processing_time_ns;
        match action {
            GovernanceAction::Allow => self.stats.action_counts.allow += 1,
            GovernanceAction::Deny => self.stats.action_counts.deny += 1,
            GovernanceAction::Redact => self.stats.action_counts.redact += 1,
            GovernanceAction::Escalate => self.stats.action_counts.escalate += 1,
        }

        ScanToolResultOutcome {
            sanitized: scan.sanitized,
            findings: scan.findings,
            blocked: scan.blocked,
            reason: scan.reason,
            receipt,
        }
    }
}
