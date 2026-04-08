# TDDF Source Map

This file maps the research sources in `tddf.md` to the shipped trap library and the next import targets.

## Scope

- `research/source-map.yaml` is the normalized planning artifact.
- This Markdown file is the human summary.
- Task `14` should build its importer and registry work on top of these mappings rather than re-deciding source priority from scratch.

## Authorship Policy

- Current shipped TDDF scenarios are first-party local compositions.
- They are inspired by the cited papers and benchmark families but are not direct imports of upstream benchmark case files.
- Any future imported payloads must carry upstream repo, pinned revision, original case id, attribution, and license notes before they are redistributed in TDDF-native form.

## Shipped Trap Classes

| Trap class | Shipped scenarios | Primary sources | Import candidates | Current authorship |
| --- | --- | --- | --- | --- |
| Web-standard obfuscation | `hidden-content-exfiltration`, `metadata-obfuscation-demo` | Greshake 2023, Verma and Yadav 2025, WASP 2025, Johnson 2025 | `git-disl/InjecAgent` | First-party adaptation |
| Syntactic masking | `markdown-masking-demo`, `poisoned-workspace-search` | Keuper 2025 | `leondz/garak` | First-party adaptation |
| Workspace poisoning | `poisoned-workspace-search` | Zou 2025, Clop and Teglia 2024, Wang 2025a | `git-disl/InjecAgent`, `ethz-spylab/agentdojo` | First-party adaptation |
| Multi-turn context poisoning | `multi-turn-context-poisoning` | Zou 2025, Chen 2024, Wang 2023, Zhao 2024 | `git-disl/InjecAgent` | First-party adaptation |
| Confused deputy exfiltration | `confused-deputy-finance-demo` | Shapira 2025, EchoLeak 2025, Alizadeh 2025, Cohen 2024 | `ethz-spylab/agentdojo`, `git-disl/InjecAgent` | First-party adaptation |
| MCP tool abuse | MCP-backed scenarios across web/document/workspace/multi-turn flows | Alizadeh 2025, Shapira 2025 | `modelcontextprotocol/servers`, `ethz-spylab/agentdojo` | First-party harness aligned to cited literature |

## Deferred Trap Classes

| Trap class | Status | Source family | Why deferred |
| --- | --- | --- | --- |
| Oversight evasion | deferred | Weinberg 2025, Shen 2024, OECD.AI 2025, jailbreak corpora | Still backlog product work and requires tighter provenance checks on jailbreak datasets |
| Multimodal steganography | deferred | Bagdasaryan 2023, Qi 2024 | TDDF does not yet have a multimodal harness |
| Systemic multi-agent traps | deferred | Gu 2024, Cui and Du 2025 | TDDF does not yet orchestrate multi-agent systems natively |

## Import Priority For Task 14

| Rank | Source | Why it is next |
| --- | --- | --- |
| 1 | `git-disl/InjecAgent` | Best first importer for content injection and behavioural-control payload families that already match TDDF's runtime model |
| 2 | `ethz-spylab/agentdojo` | Best next importer for confused-deputy, finance, inbox, and tool-calling scenarios |
| 3 | `modelcontextprotocol/servers` | Best backend source for reusable MCP environment profiles, though not a payload dataset itself |
| 4 | `leondz/garak` | Strong follow-on source for syntactic masking and encoded payload variants |
| 5 | `verazuo/jailbreak_llms` or similar | Keep deferred until oversight-evasion work starts and provenance is clearer |

## Provenance And Licensing Rules

- Papers and incident reports are citation-only references for the built-in trap library.
- Repository import candidates stay in `review_required` state until task `14` verifies license terms and records pinned upstream revisions.
- Mixed-provenance jailbreak collections stay deferred until redistribution rights are explicit.
- Official MCP server repositories should be treated as environment backends, not as trap datasets.

## What Task 09 Now Covers

- Every shipped trap class maps to named source papers or benchmark families.
- External repositories are prioritized for the first importer pass.
- Legal and attribution risk is surfaced before ingestion work begins.

## What Task 14 Still Needs To Add

- Pinned upstream revisions
- Importer code
- Normalized trap registry output
- `use:` or trap-id reference support in future config planning
