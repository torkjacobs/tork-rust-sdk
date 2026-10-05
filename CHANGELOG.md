# Changelog

## 0.5.0 - 2026-10-03

### Added
- Agent telemetry fields `agent_id`, `agent_role`, `session_id`, `session_turn`
  (integer) via `GovernOptions::session_context` (`SessionContext`). Passed
  through to `GovernanceResult` and the receipt when set; omitted from
  serialised output when not set (`GovernanceResult.session_context` previously
  serialised as `null`).
- `tests/pii_types_and_session_tests.rs`: a positive and a negative example for
  every declared PII type, plus pass-through/omission tests for the telemetry
  fields.

### PII types (S01 parity check)
All 10 declared types (ssn, credit_card, email, phone, address, ip_address,
date_of_birth, passport, drivers_license, bank_account) have a live pattern;
none removed.

## 0.4.0 - 2026-09-25

### Added
- PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).
- **The country layer: 24 country profiles, 54 patterns, 20 check digits.**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID.
- `au_tfn`, `au_abn` and `au_medicare` now ship as real bundle patterns
  (`always_on: true`) instead of being named by `checksums.json` alone.
  `patterns_for_regions` runs them on every document per rule 1a, closing the
  "AU bundle gap" -- the ABN's own corpus sentence activates no Australian
  region at all, so only the alwaysOn rule catches it.
- New public API, all pure and local: `detect_country_pii`,
  `detect_country_pii_with`, `infer_regions`, `patterns_for_regions`,
  `apply_redactions`, `detect_pii_in_regions`, `Tork::govern_in_regions`, the
  `pii_checksums` / `pii_registry` / `pii_activation` modules, and the
  `CountryPIIMatch` / `RedactionSpan` types.
- `PIIDetectionResult` gains `country_matches`, `country_labels` and `regions`,
  all `#[serde(default)]` and skipped when empty, so existing serialised
  receipts still deserialise. Nothing was removed or renamed.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-RUST-PARTIAL-REDACTION.** Until 0.3.0 each pattern was redacted with its
  own `replace_all` over text a previous pattern had already rewritten, while
  `matches` carried indices into the *original* text. Two patterns matching
  overlapping spans could leave half an identifier standing beside a redaction
  token -- digits exposed in output the caller had been told was redacted.
  Matches are now collected against the original text, overlaps are resolved
  before anything is rewritten, and the surviving spans are spliced right to
  left in one pass. `nothing_is_ever_partially_redacted` asserts the invariant
  across all 2,092 vectors.
- **`Tork::detect_pii_internal` was a second copy of `detect_pii`**, carrying
  the same bug. It now delegates, so there is one implementation of the
  redaction rules and one place to fix them. The unused cached `patterns` field
  on `Tork` went with it.
- **`govern_with_options` ignored `region`.** It called `govern(input)` and then
  copied `region` and `industry` onto the result, so the option was echoed back
  to the caller without ever selecting a pattern. It now drives detection.
- **README install pin.** The README pinned `tork-governance = "0.1.0"`; the
  crate is at 0.2.0 on crates.io and this release is 0.4.0.

### Notes
- This release folds in 0.3.0, which is in this repository but was never
  published to crates.io (crates.io is at 0.2.0).
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## 0.3.0 - 2026-09-03

### Added
- feat: `scan_tool_result` / `Tork::scan_tool_result` — on-device PII + prompt-injection scanning for MCP/tool output, ported from `tork-js-sdk`'s `scanToolResult` (DECIDED-TACT2-V2-C). Tier 1 PII vocabulary (10 basic types), `tork-injection-heuristics-v1` heuristic ruleset, byte-identical `tool_result_scan` receipt block.
- feat: `PIIType::label()` and `PIIType::all()`.
- feat: `SDK_VERSION` constant.

## 0.2.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
