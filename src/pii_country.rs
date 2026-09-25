//! The country layer: 24 country profiles, 51 patterns, 20 check digits.
//!
//! This implements the seven rules that `generated/sdk-registry/README.md`
//! marks **SDK**, from the bundle alone. Bundle 1.1.0 carries the data all
//! seven need -- the activation signals, the country map, the three windows,
//! the whole-word vocabulary, the near-miss policy, the table constants and the
//! reference labels -- so nothing here is hand-written registry data and no
//! window is hard-coded.
//!
//! 1. ACTIVATE   a country's patterns run only when one of its signals fires.
//! 2. MATCH      the regex, case-sensitively, globally.
//! 3. KEYWORD    whole-word (symmetric `CONTEXT_WINDOW`) or column verdict or
//!               the ASYMMETRIC substring window (60 before, 40 after); then
//!               7b may close the gate again.
//! 4. CHECKSUM   when required. Advisory checksums never reject.
//! 5. SUPERSEDE  a match containing every range it overlaps takes them.
//! 6. NEAR MISS  a checksum-failing identifier is redacted generically.
//! 7. COLUMN     in a delimited table a bare value cell is judged by its header.
//! 7b. NEAREST LABEL  a closer commercial label closes the gate.
//!
//! Still cloud-only, by design: the universal (L0) patterns, the slot, context,
//! gravity and name layers, industry profiles and org configuration.
//!
//! Offsets are BYTE offsets, matching the `regex` crate.

use crate::pii_checksums::checksum_fn;
use crate::pii_registry::{
    Pattern, CONTENT_HASH, CONTEXT_WINDOW as BUNDLE_CONTEXT_WINDOW, COUNTRIES,
    GENERIC_ID_KEYWORDS, KEYWORD_WINDOW_AFTER as BUNDLE_AFTER,
    KEYWORD_WINDOW_BEFORE as BUNDLE_BEFORE, LABEL_REACH, LABEL_WINDOW, LOCAL_ID_KEYWORDS,
    NEAR_MISS_REDACTION, NEAR_MISS_TYPE, PATTERNS, REFERENCE_LABELS, REGISTRY_VERSION, SIGNALS,
    TABLE_DELIMITERS, TABLE_MAX_HEADER_LENGTH, TABLE_MAX_HEADER_WORDS, TABLE_MIN_COMMA_COLUMNS,
    TABLE_MIN_ROWS,
};
use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Characters before a match that count as nearby for the substring gate.
pub const KEYWORD_WINDOW_BEFORE: usize = BUNDLE_BEFORE;
/// Characters after a match that count. Deliberately NOT the same number.
pub const KEYWORD_WINDOW_AFTER: usize = BUNDLE_AFTER;
/// The symmetric window: whole-word keywords and the near-miss gate.
pub const CONTEXT_WINDOW: usize = BUNDLE_CONTEXT_WINDOW;

pub use crate::pii_registry::{CONTENT_HASH as BUNDLE_CONTENT_HASH, REGISTRY_VERSION as BUNDLE_VERSION};

/// One country identifier found in the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryPIIMatch {
    /// Registry pattern name, e.g. `za_id_number`, or `national_id_near_miss`.
    pub name: String,
    /// ISO 3166-1 alpha-2, or `EU` for the bloc. Empty for a near miss.
    pub country: String,
    /// The shared redaction label. The receipt block hashes labels.
    pub label: String,
    /// The registry type, or `national_id_near_miss` for a rule 6 span.
    pub pii_type: String,
    pub redaction: String,
    pub start_index: usize,
    pub end_index: usize,
}

/// A span of the original text and the token that replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionSpan {
    pub start_index: usize,
    pub end_index: usize,
    pub redaction: String,
}

struct Compiled {
    patterns: Vec<Regex>,
    signals: Vec<Regex>,
    signal_order: Vec<&'static str>,
    generic: HashSet<&'static str>,
    national_id_words: Vec<&'static str>,
}

fn compiled() -> &'static Compiled {
    static C: OnceLock<Compiled> = OnceLock::new();
    C.get_or_init(|| {
        let patterns = PATTERNS
            .iter()
            .map(|p| Regex::new(p.regex).expect("bundle pattern must compile"))
            .collect();
        let signals = SIGNALS
            .iter()
            .map(|s| {
                RegexBuilder::new(s.regex)
                    .case_insensitive(s.flags.contains('i'))
                    .build()
                    .expect("bundle signal must compile")
            })
            .collect();
        let mut signal_order: Vec<&'static str> = Vec::new();
        for s in SIGNALS {
            if !signal_order.contains(&s.country) {
                signal_order.push(s.country);
            }
        }
        let generic: HashSet<&'static str> = GENERIC_ID_KEYWORDS.iter().copied().collect();
        let mut national_id_words: Vec<&'static str> = GENERIC_ID_KEYWORDS.to_vec();
        national_id_words.extend_from_slice(LOCAL_ID_KEYWORDS);
        Compiled { patterns, signals, signal_order, generic, national_id_words }
    })
}

fn pattern_index(name: &str) -> Option<usize> {
    PATTERNS.iter().position(|p| p.name == name)
}

fn is_alnum_ascii(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Clamp to a char boundary at or below `i`, so slicing never splits a code point.
fn floor_boundary(s: &str, mut i: usize) -> usize {
    if i > s.len() {
        i = s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Clamp to a char boundary at or above `i`.
fn ceil_boundary(s: &str, mut i: usize) -> usize {
    if i > s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn window_before(content: &str, start: usize, width: usize) -> String {
    let lo = floor_boundary(content, start.saturating_sub(width));
    content[lo..start].to_lowercase()
}

fn window_after(content: &str, end: usize, width: usize) -> String {
    let hi = ceil_boundary(content, end.saturating_add(width));
    content[end..hi].to_lowercase()
}

fn window_around(content: &str, start: usize, end: usize, width: usize) -> String {
    let lo = floor_boundary(content, start.saturating_sub(width));
    let hi = ceil_boundary(content, end.saturating_add(width));
    content[lo..hi].to_lowercase()
}

/// A pattern's whole vocabulary: the substring keywords and the whole-word ones.
fn all_keywords_of(p: &Pattern) -> Vec<&'static str> {
    if p.whole_word_keywords.is_empty() {
        p.keywords.to_vec()
    } else {
        let mut v = p.keywords.to_vec();
        v.extend_from_slice(p.whole_word_keywords);
        v
    }
}

/// The half of a vocabulary that names ONE country's identifier.
fn specific_keywords(keywords: &[&'static str]) -> Vec<&'static str> {
    let generic = &compiled().generic;
    keywords.iter().copied().filter(|k| !generic.contains(k)).collect()
}

/// Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it.
fn has_nearby_context(content: &str, start: usize, end: usize, keywords: &[&str]) -> bool {
    let before = window_before(content, start, KEYWORD_WINDOW_BEFORE);
    let after = window_after(content, end, KEYWORD_WINDOW_AFTER);
    keywords.iter().any(|k| before.contains(k) || after.contains(k))
}

/// Symmetric `CONTEXT_WINDOW` either side, substring. Used by rule 6.
fn has_context_around(content: &str, start: usize, end: usize, keywords: &[&str]) -> bool {
    let w = window_around(content, start, end, CONTEXT_WINDOW);
    keywords.iter().any(|k| w.contains(k))
}

/// Rule 3, whole-word half: symmetric `CONTEXT_WINDOW`, a boundary each side.
///
/// This is the gate Indonesia needs: `nik` sits inside *teknik*, *elektronik*,
/// *klinik* and *pabrik*, so a substring test would open the gate on a ledger.
pub fn has_whole_word_context_around(
    content: &str,
    start: usize,
    end: usize,
    words: &[&str],
) -> bool {
    if words.is_empty() {
        return false;
    }
    let w = window_around(content, start, end, CONTEXT_WINDOW);
    let bytes = w.as_bytes();
    for word in words {
        let mut from = 0usize;
        while let Some(rel) = w[from..].find(word) {
            let i = from + rel;
            let before_ok = i == 0 || !is_alnum_ascii(bytes[i - 1]);
            let j = i + word.len();
            let after_ok = j >= bytes.len() || !is_alnum_ascii(bytes[j]);
            if before_ok && after_ok {
                return true;
            }
            from = i + 1;
            if from >= w.len() {
                break;
            }
        }
    }
    false
}

fn document_has_whole_word(content: &str, words: &[&str]) -> bool {
    !words.is_empty() && has_whole_word_context_around(content, 0, content.len(), words)
}

// ── rule 1: activation ──────────────────────────────────────────────────────

/// The countries this text activates, in the bundle's signal order.
pub fn infer_regions(content: &str) -> Vec<String> {
    let c = compiled();
    let lower = content.to_lowercase();
    let mut regions: Vec<String> = Vec::new();
    for code in &c.signal_order {
        for (i, s) in SIGNALS.iter().enumerate() {
            if s.country != *code {
                continue;
            }
            if !c.signals[i].is_match(content) {
                continue;
            }
            let by_substring = !s.keywords.is_empty() && s.keywords.iter().any(|k| lower.contains(k));
            let by_whole_word = document_has_whole_word(content, s.whole_word_keywords);
            // Both lists empty means the shape alone is distinctive enough.
            if (!s.keywords.is_empty() || !s.whole_word_keywords.is_empty())
                && !by_substring
                && !by_whole_word
            {
                continue;
            }
            let target = if s.activates.is_empty() { *code } else { s.activates };
            if !regions.iter().any(|r| r == target) {
                regions.push(target.to_string());
            }
            break; // one signal per country is enough
        }
    }
    regions
}

/// The patterns those regions switch on, de-duplicated, in registry order.
///
/// Rule 1a: a pattern whose `always_on` is true runs on every document,
/// whatever rule 1 activated, and runs BEFORE the activated country patterns
/// so an activated pattern can still supersede it under rule 5. Today that is
/// exactly three Australian patterns (`au_tfn`, `au_abn`, `au_medicare`) --
/// see generated/sdk-registry/README.md rule 1a. Without this, a document
/// that never fires an Australian activation signal (the ABN's own corpus
/// sentence activates no region) would never run them at all.
pub fn patterns_for_regions(regions: &[&str]) -> Vec<&'static Pattern> {
    let mut out: Vec<&'static Pattern> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for p in PATTERNS {
        if p.always_on && seen.insert(p.name) {
            out.push(p);
        }
    }
    for code in regions {
        let upper = code.to_uppercase();
        if let Some(country) = COUNTRIES.iter().find(|c| c.code == upper) {
            for name in country.patterns {
                if seen.contains(name) {
                    continue;
                }
                if let Some(i) = pattern_index(name) {
                    seen.insert(name);
                    out.push(&PATTERNS[i]);
                }
            }
        }
    }
    out
}

// ── rule 7: the column is the context ───────────────────────────────────────

struct TableScope {
    start: usize,
    end: usize,
    header: String,
    row_start: usize,
    row_end: usize,
}

fn looks_like_header(cells: &[&str], delimiter: &str) -> bool {
    let minimum = if delimiter == "," { TABLE_MIN_COMMA_COLUMNS } else { 2 };
    if cells.len() < minimum {
        return false;
    }
    cells.iter().all(|c| {
        let t = c.trim();
        if t.is_empty() || t.len() > TABLE_MAX_HEADER_LENGTH {
            return false;
        }
        if !t.chars().any(|ch| ch.is_alphabetic()) {
            return false;
        }
        if t.chars().all(|ch| ch.is_ascii_digit() || " .-/+".contains(ch)) {
            return false;
        }
        if t.contains('.') || t.contains('?') || t.contains('!') {
            return false;
        }
        t.split_whitespace().count() <= TABLE_MAX_HEADER_WORDS
    })
}

fn table_scopes(content: &str) -> Vec<TableScope> {
    let lines: Vec<&str> = content.split('\n').collect();
    if lines.len() < TABLE_MIN_ROWS {
        return Vec::new();
    }
    let mut offsets = Vec::with_capacity(lines.len());
    let mut at = 0usize;
    for line in &lines {
        offsets.push(at);
        at += line.len() + 1;
    }
    for delimiter in TABLE_DELIMITERS {
        let header_cells: Vec<&str> = lines[0].split(delimiter).collect();
        if !looks_like_header(&header_cells, delimiter) {
            continue;
        }
        let width = header_cells.len();
        let mut data_rows: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            if line.split(delimiter).count() != width {
                return Vec::new();
            }
            data_rows.push(i);
        }
        if data_rows.len() < TABLE_MIN_ROWS - 1 {
            continue;
        }
        let mut scopes = Vec::new();
        for row in data_rows {
            let cells: Vec<&str> = lines[row].split(delimiter).collect();
            let row_start = offsets[row];
            let row_end = row_start + lines[row].len();
            let mut cell_start = row_start;
            for (col, cell) in cells.iter().enumerate() {
                scopes.push(TableScope {
                    start: cell_start,
                    end: cell_start + cell.len(),
                    header: header_cells[col].trim().to_lowercase(),
                    row_start,
                    row_end,
                });
                cell_start += cell.len() + delimiter.len();
            }
        }
        return scopes;
    }
    Vec::new()
}

/// A whole-word match, not a substring.
fn header_names(header: &str, keywords: &[&str]) -> bool {
    let bytes = header.as_bytes();
    for kw in keywords {
        if let Some(i) = header.find(kw) {
            let before_ok = i == 0 || !is_alnum_ascii(bytes[i - 1]);
            let j = i + kw.len();
            let after_ok = j >= bytes.len() || !is_alnum_ascii(bytes[j]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// `None` when the window should be consulted as usual.
fn column_verdict(
    content: &str,
    scopes: &[TableScope],
    start: usize,
    end: usize,
    all: &[&str],
    specific: &[&str],
) -> Option<bool> {
    if scopes.is_empty() {
        return None;
    }
    let cell = scopes.iter().find(|s| start >= s.start && end <= s.end)?;
    // A cell whose own row names the identifier is prose in a delimited block.
    let row_text = content[cell.row_start..cell.row_end].to_lowercase();
    if all.iter().any(|k| row_text.contains(k)) {
        return None;
    }
    Some(!specific.is_empty() && header_names(&cell.header, specific))
}

// ── rule 7b: nearest label wins ─────────────────────────────────────────────

fn closest_before(before: &str, keywords: &[&str]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for kw in keywords {
        if let Some(i) = before.rfind(kw) {
            let d = before.len() - (i + kw.len());
            if best.is_none() || d < best.unwrap() {
                best = Some(d);
            }
        }
    }
    best
}

fn closest_after(after: &str, keywords: &[&str]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for kw in keywords {
        if let Some(i) = after.find(kw) {
            if best.is_none() || i < best.unwrap() {
                best = Some(i);
            }
        }
    }
    best
}

/// Whether the number is labelled as a commercial reference more closely than
/// as an identifier. It can only ever close a gate, never open one.
pub fn labelled_as_reference(
    content: &str,
    start: usize,
    end: usize,
    identifier_keywords: &[&str],
) -> bool {
    let before = window_before(content, start, LABEL_WINDOW);
    let reference = match closest_before(&before, REFERENCE_LABELS) {
        Some(r) if r <= LABEL_REACH => r,
        _ => return false,
    };
    if identifier_keywords.is_empty() {
        return true;
    }
    if let Some(id_before) = closest_before(&before, identifier_keywords) {
        if id_before <= reference {
            return false;
        }
    }
    let after = window_after(content, end, LABEL_WINDOW);
    if let Some(id_after) = closest_after(&after, identifier_keywords) {
        if id_after <= reference {
            return false;
        }
    }
    true
}

// ── the pass ────────────────────────────────────────────────────────────────

/// The span with leading and trailing non-alphanumeric characters removed.
fn trimmed_core(content: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = content.as_bytes();
    let (mut s, mut e) = (start, end);
    while s < e && !is_alnum_ascii(bytes[s]) {
        s += 1;
    }
    while e > s && !is_alnum_ascii(bytes[e - 1]) {
        e -= 1;
    }
    if s == e {
        (start, end)
    } else {
        (s, e)
    }
}

/// The matches, and the caller's own L0 ranges that a country match superseded.
pub struct CountryPIIResult {
    pub matches: Vec<CountryPIIMatch>,
    pub superseded_ranges: Vec<(usize, usize)>,
}

/// Country matches for `content`, de-overlapped and ordered by position.
pub fn detect_country_pii(content: &str) -> Vec<CountryPIIMatch> {
    let regions = infer_regions(content);
    let refs: Vec<&str> = regions.iter().map(|s| s.as_str()).collect();
    detect_country_pii_with(content, &patterns_for_regions(&refs))
}

/// Run an explicit pattern set, bypassing activation.
pub fn detect_country_pii_with(content: &str, active: &[&'static Pattern]) -> Vec<CountryPIIMatch> {
    detect_country_pii_with_ranges(content, active, &[]).matches
}

/// The full pass. Pass your own L0 spans so rule 5 can supersede them.
pub fn detect_country_pii_with_ranges(
    content: &str,
    active: &[&'static Pattern],
    existing_ranges: &[(usize, usize)],
) -> CountryPIIResult {
    if active.is_empty() {
        return CountryPIIResult { matches: Vec::new(), superseded_ranges: Vec::new() };
    }
    let c = compiled();
    let tables = table_scopes(content);
    let mut active_existing: Vec<(usize, usize)> = existing_ranges.to_vec();
    let mut superseded: Vec<(usize, usize)> = Vec::new();
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    let mut found: Vec<CountryPIIMatch> = Vec::new();
    let mut near_misses: Vec<(usize, usize)> = Vec::new();

    for pattern in active {
        let idx = match pattern_index(pattern.name) {
            Some(i) => i,
            None => continue,
        };
        for m in c.patterns[idx].find_iter(content) {
            let (start, end) = (m.start(), m.end());
            if start == end {
                continue;
            }

            // Rules 3, 7 and 7b.
            if pattern.requires_keyword && !pattern.keywords.is_empty() {
                let all = all_keywords_of(pattern);
                let specific = specific_keywords(&all);
                let ok = if has_whole_word_context_around(content, start, end, pattern.whole_word_keywords) {
                    true
                } else {
                    match column_verdict(content, &tables, start, end, &all, &specific) {
                        Some(v) => v,
                        None => has_nearby_context(content, start, end, pattern.keywords),
                    }
                };
                if !ok {
                    continue;
                }
                if labelled_as_reference(content, start, end, pattern.keywords) {
                    continue;
                }
            }

            // Rule 4, and rule 6's candidate.
            if pattern.checksum_required {
                if let Some(name) = pattern.checksum {
                    if let Some(f) = checksum_fn(name) {
                        if !f(&content[start..end]) {
                            if pattern.near_miss_fallback {
                                let extra = if pattern.near_miss_keywords.is_empty() {
                                    pattern.keywords
                                } else {
                                    pattern.near_miss_keywords
                                };
                                let mut vocabulary = c.national_id_words.clone();
                                vocabulary.extend_from_slice(extra);
                                if has_context_around(content, start, end, &vocabulary) {
                                    near_misses.push((start, end));
                                }
                            }
                            continue;
                        }
                    }
                }
            }

            // Rule 5.
            let overlapping: Vec<(usize, usize)> = active_existing
                .iter()
                .chain(claimed.iter())
                .copied()
                .filter(|(rs, re)| start < *re && end > *rs)
                .collect();
            if !overlapping.is_empty() {
                let supersedes_all = overlapping.iter().all(|(rs, re)| {
                    let (cs, ce) = trimmed_core(content, *rs, *re);
                    start <= cs && end >= ce
                });
                if !supersedes_all {
                    continue;
                }
                for o in &overlapping {
                    if let Some(i) = active_existing.iter().position(|r| r == o) {
                        superseded.push(active_existing.remove(i));
                    }
                    if let Some(i) = claimed.iter().position(|r| r == o) {
                        claimed.remove(i);
                    }
                    found.retain(|f| (f.start_index, f.end_index) != *o);
                }
            }

            claimed.push((start, end));
            found.push(CountryPIIMatch {
                name: pattern.name.to_string(),
                country: pattern.country.to_string(),
                label: pattern.label.to_string(),
                pii_type: pattern.pii_type.to_string(),
                redaction: pattern.redaction.to_string(),
                start_index: start,
                end_index: end,
            });
        }
    }

    // Rule 6, last: a near miss can only ever fill a hole.
    let mut taken: Vec<(usize, usize)> = active_existing.iter().chain(claimed.iter()).copied().collect();
    for (cs, ce) in near_misses {
        if taken.iter().any(|(rs, re)| cs < *re && ce > *rs) {
            continue;
        }
        taken.push((cs, ce));
        found.push(CountryPIIMatch {
            name: NEAR_MISS_TYPE.to_string(),
            country: String::new(),
            label: "NATIONAL_ID".to_string(),
            pii_type: NEAR_MISS_TYPE.to_string(),
            redaction: NEAR_MISS_REDACTION.to_string(),
            start_index: cs,
            end_index: ce,
        });
    }

    found.sort_by_key(|f| f.start_index);
    CountryPIIResult { matches: found, superseded_ranges: superseded }
}

/// Turn country matches into redaction spans.
pub fn redaction_spans_of(matches: &[CountryPIIMatch]) -> Vec<RedactionSpan> {
    matches
        .iter()
        .map(|m| RedactionSpan {
            start_index: m.start_index,
            end_index: m.end_index,
            redaction: m.redaction.clone(),
        })
        .collect()
}

/// Replace every span with its redaction, right to left.
///
/// Right to left is what keeps the earlier indices valid, and splicing whole
/// spans in one pass is what guarantees no partial redaction: a digit can never
/// be left standing beside a redaction token, because nothing is ever matched
/// against text a previous replacement has already rewritten.
pub fn apply_redactions(text: &str, spans: &[RedactionSpan]) -> String {
    if spans.is_empty() {
        return text.to_string();
    }
    let mut ordered: Vec<&RedactionSpan> = spans.iter().collect();
    ordered.sort_by_key(|s| s.start_index);
    let mut out = text.to_string();
    for s in ordered.iter().rev() {
        out = format!("{}{}{}", &out[..s.start_index], s.redaction, &out[s.end_index..]);
    }
    out
}

/// The bundle this SDK shipped.
pub fn bundle_identity() -> (&'static str, &'static str) {
    (REGISTRY_VERSION, CONTENT_HASH)
}
