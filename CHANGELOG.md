# Changelog

## 0.3.0 - 2026-09-03

### Added
- feat: `scan_tool_result` / `Tork::scan_tool_result` — on-device PII + prompt-injection scanning for MCP/tool output, ported from `tork-js-sdk`'s `scanToolResult` (DECIDED-TACT2-V2-C). Tier 1 PII vocabulary (10 basic types), `tork-injection-heuristics-v1` heuristic ruleset, byte-identical `tool_result_scan` receipt block.
- feat: `PIIType::label()` and `PIIType::all()`.
- feat: `SDK_VERSION` constant.

## 0.2.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
