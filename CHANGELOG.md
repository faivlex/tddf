# Changelog

All notable changes to TDDF are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Calendar Versioning](https://calver.org/) (`YYYY.M.PATCH`).

## [Unreleased]

## [2026.4.1] — 2026-05-12

### Added

- Initial public release.
- Deterministic, local-first behaviour regression test runner for AI agents. Scenarios in YAML; pass/fail by what the agent actually does, not by LLM-as-judge.
- Adapters: `command`, `langgraph`, `openai_agents`, `claude_agent_sdk`, `hermes`, `openclaw`.
- Trap families: web injection, document masking, workspace poisoning, confused deputy, sensitive-tool access, multi-turn context poisoning.
- Composable scenarios — trap families × delivery techniques (HTML comment, `display:none`, `aria-label`, `<meta>`, Markdown comment, white-on-white text) × encoding strategies (base64, ROT13, leetspeak, homoglyph).
- Severity levels with `--fail-severity` threshold for CI gating.
- Real MCP server: JSON-RPC 2.0, streamable HTTP **and** stdio transports, all five core methods, JSON-Schema tool descriptors. Plain-HTTP query-param fallback preserved for pedagogical examples.
- Semantic evaluator — pin attacker tool-call patterns via `expected_attacker_calls` with `equals` / `contains` / `one_of` / `after` constraints. Composes additively with the structural FAIL triggers.
- External benchmark importers: `tddf import injecagent` (data-stealing + direct-harm cases) and `tddf import agentdojo` (banking / workspace / slack / travel suites). Bundled curated subsets ship out of the box for zero-setup demos.
- Regression baselines (`tddf baseline save` / `tddf run --baseline`) and per-scenario observable snapshots (`tddf snapshot save` / `tddf snapshot show`).
- Watch mode — `tddf watch` re-runs affected scenarios on file change.
- Autonomous assessment — `tddf assess` discovers a target's capabilities and generates a deterministic starter scenario set.
- GitHub Action for CI integration (`uses: faivlex/tddf@v1`) — runs the suite, uploads JUnit and scenario artifacts, gates failure by severity.
- Compliance framework metadata on scenarios and trap families: OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS, ISO 42001, EU AI Act. Surfaced in results and JUnit output for downstream compliance workflows.
- Bundled third-party data: AgentDojo curated subset (MIT, © Debenedetti et al. 2024) and InjecAgent curated subset (MIT, © Qiusi Zhan 2023). Full attribution in [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

### Security

- Loopback-only binding for mock web, attacker capture, and MCP servers.
- GitHub private vulnerability reporting + `security@faivlex.com` for disclosure. 90-day coordinated disclosure window. See [`SECURITY.md`](SECURITY.md).
- No telemetry. No traces uploaded. No LLM-as-judge.

[Unreleased]: https://github.com/faivlex/tddf/compare/v2026.4.1...HEAD
[2026.4.1]: https://github.com/faivlex/tddf/releases/tag/v2026.4.1
