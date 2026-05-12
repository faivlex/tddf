# Security Policy

TDDF is a defensive testing harness. Vulnerabilities in TDDF itself — in the evaluator, the attacker capture listener, the MCP server, or any other component that could be abused against a TDDF user — are taken seriously.

## Reporting a vulnerability

**Do not file a public issue for security reports.** Use one of the private channels below:

1. **Preferred — GitHub private vulnerability reporting**: open a draft advisory at <https://github.com/gonzalosr/tddf/security/advisories/new>. This is end-to-end private until publication.
2. **Email**: `security@TBD` *(this address will be live once task 48 — domain registration — completes; until then, please use channel 1 above).*

Please include:

- A clear description of the issue and the impact you observed or believe is possible.
- A minimal reproduction (config, command, expected vs actual behaviour). Redact any real secrets.
- Affected TDDF version (`tddf --version`), Python version, OS.
- Whether the issue is already public (research disclosure, conference talk, blog post, etc.) and any embargo timeline.

## What to expect

- Acknowledgement within **3 business days**.
- Initial triage and severity assessment within **7 business days**.
- For confirmed valid reports, a coordinated disclosure window of up to **90 days** before public advisory, unless the issue is already public or actively exploited.
- A GitHub Security Advisory will be published once a fix is available, crediting the reporter unless they prefer to remain anonymous.

## Supported versions

TDDF uses [Calendar Versioning](https://calver.org/) (`YYYY.M.PATCH`). Security fixes are applied to the latest published release. Older releases are not patched; please upgrade.

## Out of scope

The following are not vulnerabilities in TDDF:

- An agent under test failing a TDDF scenario. That is TDDF working correctly — file the issue against the agent, not TDDF.
- Behaviour observed when TDDF is run against systems you do not own. TDDF is for testing your own agents; misuse against third parties is not a TDDF defect (see the Intended Use notice in the README).
- Findings in the bundled curated payloads (`THIRD_PARTY_LICENSES.md`) that reproduce the upstream research as designed.

## Hardening notes for operators

- TDDF binds mock servers to `127.0.0.1` by default and uses ephemeral ports. Do not expose these to a public interface.
- The attacker capture listener records request bodies; if your agent under test handles real secrets, run TDDF in a sandboxed environment.
- The `tddf mcp-server` stdio transport executes inside your shell — apply the same trust boundary you would to any local MCP server.
