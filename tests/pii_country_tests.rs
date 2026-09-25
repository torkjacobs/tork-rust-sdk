//! Country-layer parity tests.
//!
//! The fixtures are generated from the cloud's own evidence, not written here:
//!
//!   `pii_unit_cases.json`  one valid sample per registry pattern, a
//!                          checksum-broken variant for each pattern whose
//!                          checksum is a gate, and the Indonesian boundary
//!                          cases.
//!   `pii_vectors.json`     all 2,092 inputs of the cloud's golden snapshot:
//!                          every country-corpus sentence for all 249 ISO
//!                          jurisdictions, and the whole 1,523-line business
//!                          false-positive corpus.
//!
//! `expectedOutput` is the COUNTRY LAYER alone. Where the cloud's own output
//! differs, the case carries `cloudOutput` and a `divergence` naming the cause,
//! so the fixture states its distance from the cloud instead of hiding it.

use serde_json::Value;
use std::collections::HashSet;
use std::fs;

use tork_governance::pii_checksums::checksum_fn;
use tork_governance::pii_country::{
    apply_redactions, detect_country_pii, detect_country_pii_with,
    detect_country_pii_with_ranges, has_whole_word_context_around, infer_regions,
    labelled_as_reference, patterns_for_regions, redaction_spans_of, CONTEXT_WINDOW,
    KEYWORD_WINDOW_AFTER, KEYWORD_WINDOW_BEFORE,
};
use tork_governance::pii_registry::{
    Pattern, CONTENT_HASH, COUNTRIES, PATTERNS, REGISTRY_VERSION, SIGNALS,
};

const NIK: &str = "3171010101900001";

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/testdata/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&fs::read_to_string(&path).expect("fixture")).expect("json")
}

fn vectors() -> Value {
    fixture("pii_vectors.json")
}

fn pattern_by_name(name: &str) -> Option<&'static Pattern> {
    PATTERNS.iter().find(|p| p.name == name)
}

fn redact(content: &str) -> String {
    apply_redactions(content, &redaction_spans_of(&detect_country_pii(content)))
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

// ── the bundle ──────────────────────────────────────────────────────────────

#[test]
fn is_the_version_and_content_the_fixtures_were_generated_from() {
    let v = vectors();
    assert_eq!(REGISTRY_VERSION, v["bundleVersion"].as_str().unwrap());
    assert_eq!(CONTENT_HASH, v["contentHash"].as_str().unwrap());
}

#[test]
fn carries_54_patterns_across_24_profiles_with_51_signals() {
    // 51 -> 54 patterns in bundle 1.2.0: the alwaysOn Australian trio
    // (au_tfn, au_abn, au_medicare) moved from checksums.json-only into
    // `patterns` itself. Signal count is unchanged -- alwaysOn patterns are
    // not activation-gated, so they needed no new signal.
    assert_eq!(PATTERNS.len(), 54);
    assert_eq!(COUNTRIES.len(), 24);
    assert_eq!(SIGNALS.len(), 51);
}

#[test]
fn covers_indonesia_added_in_1_1_0() {
    let id = COUNTRIES.iter().find(|c| c.code == "ID").expect("Indonesia is missing");
    assert!(id.patterns.contains(&"id_nik"));
    let nik = pattern_by_name("id_nik").expect("id_nik is missing");
    assert_eq!(nik.label, "NIK");
    assert!(nik.whole_word_keywords.contains(&"nik"));
}

#[test]
fn reads_its_windows_from_the_bundle_and_they_are_not_all_the_same() {
    assert_eq!(KEYWORD_WINDOW_BEFORE, 60);
    assert_eq!(KEYWORD_WINDOW_AFTER, 40);
    assert_eq!(CONTEXT_WINDOW, 60);
    assert_ne!(KEYWORD_WINDOW_BEFORE, KEYWORD_WINDOW_AFTER);
}

#[test]
fn names_a_checksum_function_for_every_pattern_that_declares_one() {
    for p in PATTERNS {
        if let Some(name) = p.checksum {
            assert!(checksum_fn(name).is_some(), "{} -> {}", p.name, name);
        }
    }
}

#[test]
fn uses_only_the_portable_regex_subset() {
    let forbidden = [
        ("(?=", "lookahead"), ("(?!", "negative lookahead"), ("(?<=", "lookbehind"),
        ("(?<!", "negative lookbehind"), ("\\p{", "unicode property escape"), ("(?>", "atomic group"),
    ];
    let sources: Vec<&str> = PATTERNS.iter().map(|p| p.regex).chain(SIGNALS.iter().map(|s| s.regex)).collect();
    for src in sources {
        for (bad, why) in forbidden {
            assert!(!src.contains(bad), "{src} uses {why}");
        }
    }
}

// ── per-pattern unit cases ──────────────────────────────────────────────────

#[test]
fn per_pattern_unit_cases() {
    let cases = fixture("pii_unit_cases.json");
    let arr = cases.as_array().unwrap();
    assert!(!arr.is_empty());
    for c in arr {
        let name = c["pattern"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        let p = pattern_by_name(name).unwrap_or_else(|| panic!("{name} is not in the bundle"));
        let found = detect_country_pii_with(input, &[p]);
        let hit = found.iter().find(|m| m.name == name);
        if c["expectDetected"].as_bool().unwrap() {
            let hit = hit.unwrap_or_else(|| panic!("expected {name} to match {input:?}"));
            assert_eq!(&input[hit.start_index..hit.end_index], c["sample"].as_str().unwrap());
            assert_eq!(hit.redaction, c["redaction"].as_str().unwrap());
        } else {
            assert!(hit.is_none(), "expected {name} NOT to match {input:?}");
        }
    }
}

// ── golden-snapshot parity ──────────────────────────────────────────────────

#[test]
fn reproduces_the_cloud_on_every_corpus_vector() {
    let v = vectors();
    let mut checked = 0;
    for c in v["cases"].as_array().unwrap() {
        if c["kind"] == "business-fp" {
            continue;
        }
        checked += 1;
        let id = c["id"].as_str().unwrap();
        let input = c["input"].as_str().unwrap();
        assert_eq!(infer_regions(input), strings(&c["expectedRegions"]), "activation: {id}");
        let matches = detect_country_pii(input);
        assert_eq!(
            apply_redactions(input, &redaction_spans_of(&matches)),
            c["expectedOutput"].as_str().unwrap(),
            "redaction: {id}"
        );
        let mut labels: Vec<String> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        for m in &matches {
            if !labels.contains(&m.label) { labels.push(m.label.clone()); }
            if !names.contains(&m.name) { names.push(m.name.clone()); }
        }
        assert_eq!(labels, strings(&c["expectedLabels"]), "labels: {id}");
        assert_eq!(names, strings(&c["expectedNames"]), "names: {id}");
    }
    assert!(checked > 500, "only {checked} corpus vectors");
}

#[test]
fn adds_no_false_positive_to_the_business_corpus() {
    let v = vectors();
    let mut n = 0;
    for c in v["cases"].as_array().unwrap() {
        if c["kind"] != "business-fp" {
            continue;
        }
        n += 1;
        let input = c["input"].as_str().unwrap();
        assert_eq!(infer_regions(input), strings(&c["expectedRegions"]), "activation: {}", c["id"]);
        let m = detect_country_pii(input);
        assert!(m.is_empty(), "{}: false positive {} in {input:?}", c["id"], m[0].name);
    }
    assert!(n > 1500, "business corpus = {n} lines");
}

#[test]
fn diverges_from_the_cloud_only_for_l0_reasons_the_au_bundle_gap_is_closed() {
    // Bundle 1.2.0 ships au_tfn, au_abn and au_medicare as real `patterns`
    // entries (all alwaysOn), so the "BUNDLE GAP" cause this fixture used to
    // carry -- and the mis-tagged "L0" cases for the AU trio, which were
    // never truly cloud-only, just gated on activation the alwaysOn rule
    // never needed -- are both gone. Every remaining divergence is a real L0
    // cloud-only exclusion (phones, addresses, France, etc.), stated as such.
    let v = vectors();
    let mut gaps: HashSet<String> = HashSet::new();
    let mut l0 = 0;
    for c in v["cases"].as_array().unwrap() {
        let d = match c["divergence"].as_str() {
            Some(d) => d,
            None => continue,
        };
        assert!(d.starts_with("L0:"), "{}: unexplained divergence {d}", c["id"]);
        l0 += 1;
        if d.contains("BUNDLE GAP") {
            gaps.insert(c["id"].as_str().unwrap().split('/').nth(1).unwrap().to_string());
        }
    }
    assert!(gaps.is_empty(), "AU bundle gap should be 0, found: {gaps:?}");
    assert!(l0 > 0, "expected real L0-only divergences to remain");
}

#[test]
fn nothing_is_ever_partially_redacted() {
    let v = vectors();
    for c in v["cases"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        let matches = detect_country_pii(input);
        let out = apply_redactions(input, &redaction_spans_of(&matches));
        for m in &matches {
            let raw = &input[m.start_index..m.end_index];
            assert!(!out.contains(raw), "{}: {raw:?} survived", c["id"]);
        }
    }
}

// ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────────

#[test]
fn detects_the_short_spelling_which_is_a_whole_word_keyword_only() {
    let s = format!("NIK {NIK} untuk pendaftaran rekening di Jakarta, Indonesia.");
    assert_eq!(infer_regions(&s), vec!["ID".to_string()]);
    assert_eq!(redact(&s), "NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.");
}

#[test]
fn detects_the_long_spelling_which_is_an_ordinary_substring_keyword() {
    let s = format!("Nomor Induk Kependudukan {NIK} untuk pendaftaran.");
    assert!(redact(&s).contains("[NIK_REDACTED]"));
}

#[test]
fn nik_inside_an_ordinary_indonesian_word_does_not_open_the_gate() {
    for word in ["teknik", "elektronik", "klinik", "pabrik", "piknik"] {
        let s = format!("Faktur {word} {NIK} untuk pelanggan.");
        assert!(detect_country_pii(&s).is_empty(), "{word} opened the gate");
    }
}

#[test]
fn a_bare_nik_is_not_redacted() {
    assert!(detect_country_pii(NIK).is_empty());
}

// ── the rules 1.1.0 added to the SDK half of the contract ───────────────────

#[test]
fn rule_6_a_checksum_failing_identifier_is_redacted_generically() {
    let s = "South African ID number 8001015009088 for the FICA check.";
    let out = redact(s);
    assert!(!out.contains("8001015009088"), "released in clear: {out}");
    assert!(out.contains("[NATIONAL_ID_REDACTED]"), "no near miss: {out}");
}

#[test]
fn rule_7_a_column_header_is_the_context_for_a_bare_value_cell() {
    let csv = "Name,CNIC,City\nAli,42201-1234567-1,Karachi\nSana,42201-7654321-2,Lahore\nOmar,42201-1111111-3,Multan";
    assert!(!redact(csv).contains("42201-1234567-1"));
}

#[test]
fn rule_7_a_generic_header_does_not_act_as_context() {
    let csv = "Name,Order ID Number,City\nAli,42201-1234567-1,Karachi\nSana,42201-7654321-2,Lahore\nOmar,42201-1111111-3,Multan";
    assert!(detect_country_pii(csv).is_empty());
}

#[test]
fn rule_7b_a_closer_commercial_label_closes_the_gate() {
    let s = "Please do not send your CNIC. Use the job number 4220112345671.";
    let at = s.find("4220112345671").unwrap();
    assert!(labelled_as_reference(s, at, at + 13, &["cnic"]));
    assert!(redact(s).contains("4220112345671"));
}

#[test]
fn rule_7b_can_only_close_a_gate_never_open_one() {
    assert!(detect_country_pii("Order 12345678901234 with no identifier word anywhere.").is_empty());
}

#[test]
fn rule_5_a_country_match_supersedes_a_wider_l0_range_it_contains() {
    let s = "CPF 529.982.247-25 para a nota fiscal no Brasil.";
    let at = s.find("529.982.247-25").unwrap();
    let regions = infer_regions(s);
    let refs: Vec<&str> = regions.iter().map(|x| x.as_str()).collect();
    let res = detect_country_pii_with_ranges(s, &patterns_for_regions(&refs), &[(at - 1, at + 14)]);
    assert!(res.matches.iter().any(|m| m.name == "br_cpf"));
    assert_eq!(res.superseded_ranges.len(), 1);
}

#[test]
fn whole_word_matching_respects_boundaries() {
    assert!(has_whole_word_context_around("nik 123", 4, 7, &["nik"]));
    assert!(!has_whole_word_context_around("teknik 123", 7, 10, &["nik"]));
}

// ── rule 1a: Australia's alwaysOn trio, added in bundle 1.2.0 ──────────────

#[test]
fn au_tfn_is_detected_in_context_with_a_valid_checksum() {
    let s = "My tax file number is 876 543 210 for the ATO return.";
    assert_eq!(redact(s), "My tax file number is [TFN_REDACTED] for the ATO return.");
}

#[test]
fn au_abn_is_detected_even_though_its_own_sentence_activates_no_region() {
    // This is the README's own example: the ABN's shape and keywords match no
    // Australian activation signal, so infer_regions returns nothing. Only
    // rule 1a -- alwaysOn, not gated by rule 1 -- catches it.
    let s = "Supplier ABN 51 824 753 556 appears on the Australian invoice.";
    assert!(infer_regions(s).is_empty(), "this sentence should activate no region");
    assert_eq!(redact(s), "Supplier ABN [ABN_REDACTED] appears on the Australian invoice.");
}

#[test]
fn au_tfn_with_a_failing_checksum_is_redacted_as_a_near_miss_not_released() {
    let s = "My tax file number is 876 543 211 for the ATO return.";
    let out = redact(s);
    assert!(!out.contains("876 543 211"), "released in clear: {out}");
    assert_eq!(out, "My tax file number is [NATIONAL_ID_REDACTED] for the ATO return.");
}

#[test]
fn au_abn_with_a_failing_checksum_is_dropped_not_near_missed() {
    // au_abn's kind is "company", not one of the 10 nearMissFallback
    // patterns (health_id / national_id / tax_id): a bad check digit here is
    // a data-quality problem, not a privacy one, so nothing is redacted.
    let s = "Supplier ABN 51 824 753 557 appears on the Australian invoice.";
    assert_eq!(redact(s), s);
}

#[test]
fn au_medicare_is_detected_with_its_keyword() {
    let s = "Patient Medicare number 2123 45670 1 for the bulk-billed visit.";
    assert_eq!(redact(s), "Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.");
}

#[test]
fn au_medicare_checksum_is_advisory_and_never_rejects_a_match() {
    // Services Australia publishes no digit layout and no check algorithm;
    // checksums.json marks au_medicare advisoryFor, not requiredBy. A
    // checksum-failing Medicare number must still be redacted, never dropped.
    let s = "Patient Medicare number 2123 45671 1 for the bulk-billed visit.";
    assert_eq!(redact(s), "Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.");
}
