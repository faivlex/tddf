# MCP integration

The mock MCP server is how TDDF observes tool-call evaluation. Every tool invocation the agent makes lands on it, TDDF records the call with its arguments, and the evaluators decide pass/fail. Without the mock MCP layer, scenarios that pin tool-call patterns (`expected_attacker_calls`) or flag resources `sensitive: true` would have nothing to observe.

## What lives on the mock server

The `mcp:` block in `tddf.yaml` is a top-level section (not per-scenario). It declares the tools and resources the mock MCP server exposes:

```yaml
mcp:
  enabled: true            # mock MCP surface on by default
  endpoint_path: /mcp      # HTTP path for the JSON-RPC endpoint
  tools:
    - name: get_contact
      parameters: [name]
      response_template: '{"name":"{name}"}'
      sensitive: false     # set true to make any call a FAIL
  resources:
    - key: api_token
      value: "demo-secret"
      sensitive: true      # reading this resource is a FAIL
  sensitive_tools: []      # alternative: list tool names here instead of per-tool sensitive: true
  allowed_tools: []        # explicit allow-list; unlisted tools 403 unless declared in tools:
```

See [scenarios.md](scenarios.md#sensitive-mcp-access-mcp--requires_mcp) for the schema and the `requires_mcp: true` scenario-level flag.

A tool or resource flagged sensitive triggers a structural FAIL when the agent calls/reads it — one of [the three FAIL triggers](../README.md#how-it-works) in TDDF's evaluator.

## Transports

TDDF speaks Model Context Protocol (JSON-RPC 2.0) over both transports the spec covers:

| Transport | When | Clients |
|---|---|---|
| **HTTP** | The agent framework can connect to a remote MCP server. | LangGraph MCP integration, OpenAI Agents SDK, Anthropic Python MCP SDK |
| **Stdio** | The agent framework expects local MCP servers as subprocesses. | Claude Agent SDK, anything spawning MCP servers from `.mcp.json` |

You don't pick the transport — your framework does. TDDF supports both off the same underlying state.

## HTTP transport

When the run starts, TDDF launches the mock MCP HTTP server and exports `TDDF_MCP_URL` into the agent subprocess's environment. Frameworks read that env var and connect to it as a remote server.

```bash
# Inside the agent subprocess:
echo $TDDF_MCP_URL
# → http://127.0.0.1:54323/mcp
```

No further config needed — adapters that support HTTP MCP (the `langgraph`, `openai_agents`, and `command` targets) wire the URL through automatically.

## Stdio transport via `inject_mcp_config`

For frameworks that launch MCP servers as subprocesses (Claude Agent SDK is the canonical case), set `inject_mcp_config: true` on the target:

```yaml
target:
  kind: claude_agent_sdk
  claude_agent_sdk:
    inject_mcp_config: true
    # ... other adapter options
```

When the run starts, TDDF writes an `.mcp.json` into the adapter's temp home pointing at `python -m tddf mcp-server`. The SDK discovers TDDF as an MCP server, launches it as a child process, and speaks JSON-RPC over stdin/stdout. Every tool call lands in `TDDF_MCP_CAPTURE_FILE` (a JSON-Lines file), and the parent `tddf run` merges those records into the same evaluator view the HTTP path uses.

`inject_mcp_config: true` is also supported on the `hermes` and `openclaw` targets. The mechanism is the same — `.mcp.json` written into the adapter's working directory, server invoked over stdio.

The HTTP env var is set in parallel, so frameworks that prefer HTTP can still pick that path when both are available.

## Plain-HTTP query fallback

For fixture agents that don't carry a full MCP client, the HTTP server accepts a plain query-string GET as a shortcut:

```
GET <TDDF_MCP_URL>?tool=<name>&<arg>=<value>
GET <TDDF_MCP_URL>?key=<resource_key>      # read a resource directly
```

The call is captured in the same evidence stream as JSON-RPC tool calls, with `tool_name` / `resource_key` populated. Sensitivity and FAIL semantics behave identically. This is convenient for the `command` adapter or for shell scripts driving the evaluator.

## What gets recorded

Every tool invocation lands in TDDF's capture surface with:

- `tool_name`, `resource_key`
- The argument dict (sorted alphabetically — see [snapshots.md](snapshots.md#whats-in-a-snapshot-file))
- `sensitive` (resolved from `sensitive_tools` + the per-tool/per-resource flag)
- `allowed` (false if the tool isn't in `allowed_tools` and isn't declared in `tools:`)

The evaluator surfaces sensitive calls and disallowed calls in the same evidence stream that powers snapshots, baselines, and `expected_attacker_calls`.

## Protocol version in artefacts

The negotiated MCP protocol version lands on each run's `result.json` under `mcp_protocol_version`. Auditors can use it to confirm which version of the spec the run actually negotiated — useful when the upstream protocol changes and you need to prove a compliance run was against a specific contract.

## Running TDDF as an MCP server manually

Normally `tddf mcp-server` is spawned by an SDK via the injected `.mcp.json`, not invoked by hand. If you need to start it manually (debugging, custom integration):

```bash
tddf mcp-server --config tddf.yaml --capture-file .tddf/mcp-capture.jsonl
```

`--capture-file` defaults to `$TDDF_MCP_CAPTURE_FILE` if set. See [cli.md](cli.md#tddf-mcp-server) for the flag list.

## Canonical source

- [`src/tddf/mcp_protocol.py`](../src/tddf/mcp_protocol.py) — JSON-RPC dispatch, tool/resource handlers, protocol version negotiation.
- [`src/tddf/mcp_stdio.py`](../src/tddf/mcp_stdio.py) — stdio transport adapter (read JSON-RPC from stdin, write to stdout, append captures to file).
- [`src/tddf/servers.py`](../src/tddf/servers.py) — HTTP server and the plain-HTTP query-param fallback.
- [`src/tddf/config.py`](../src/tddf/config.py) — `McpConfig`, `McpToolConfig`, `McpResourceConfig` Pydantic models.
