from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
from dataclasses import asdict, is_dataclass
from pathlib import Path


def _normalize_for_json(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _normalize_for_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_normalize_for_json(item) for item in value]
    if is_dataclass(value):
        return _normalize_for_json(asdict(value))
    if hasattr(value, "model_dump"):
        return _normalize_for_json(value.model_dump())
    if hasattr(value, "__dict__") and value.__dict__:
        return _normalize_for_json(vars(value))
    return repr(value)


def _resolve_reference(ref: str) -> object:
    module_name, attr_path = ref.split(":", 1)
    module = importlib.import_module(module_name)
    target: object = module
    for part in attr_path.split("."):
        target = getattr(target, part)
    if callable(target) and not isinstance(target, type):
        return target()
    return target


def _build_prompt_payload(args: argparse.Namespace) -> object:
    prompt = os.environ.get("TDDF_PROMPT", "")
    if args.input_template is not None:
        template = json.loads(args.input_template)
        mapping = {
            "prompt": prompt,
            "web_url": os.environ.get("TDDF_WEB_URL", ""),
            "document_path": os.environ.get("TDDF_DOCUMENT_PATH", ""),
            "workspace_path": os.environ.get("TDDF_WORKSPACE_PATH", ""),
            "attacker_url": os.environ.get("TDDF_ATTACKER_URL", ""),
            "mcp_url": os.environ.get("TDDF_MCP_URL", ""),
            "session_id": os.environ.get("TDDF_SESSION_ID", ""),
            "step_index": os.environ.get("TDDF_STEP_INDEX", "0"),
        }

        def substitute(value: object) -> object:
            if isinstance(value, str):
                return value.format(**mapping)
            if isinstance(value, list):
                return [substitute(item) for item in value]
            if isinstance(value, dict):
                return {str(key): substitute(item) for key, item in value.items()}
            return value

        return substitute(template)

    if args.input_mode == "messages":
        return [
            {
                "type": "user",
                "message": {"role": "user", "content": prompt},
                "parent_tool_use_id": None,
                "session_id": os.environ.get("TDDF_SESSION_ID", "default"),
            }
        ]
    return prompt


async def _as_async_iterable(messages: list[dict[str, object]]):
    for message in messages:
        yield message


def _load_resume_session_id(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    payload = json.loads(path.read_text())
    if isinstance(payload, dict):
        session_id = payload.get("session_id")
        if isinstance(session_id, str):
            return session_id
    return None


def _store_resume_session_id(path: Path | None, session_id: str | None) -> None:
    if path is None or session_id is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"session_id": session_id}, indent=2) + "\n")


def _build_transport(args: argparse.Namespace) -> object | None:
    if args.transport is None:
        return None
    return _resolve_reference(args.transport)


async def main_async() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-mode", choices=["prompt", "messages"], required=True)
    parser.add_argument("--input-template")
    parser.add_argument("--allowed-tools", required=True)
    parser.add_argument("--disallowed-tools", required=True)
    parser.add_argument("--permission-mode")
    parser.add_argument("--system-prompt")
    parser.add_argument("--model")
    parser.add_argument("--max-turns", type=int)
    parser.add_argument("--include-partial-messages", action="store_true")
    parser.add_argument("--cli-path")
    parser.add_argument("--setting-sources")
    parser.add_argument("--extra-args", required=True)
    parser.add_argument("--use-session", action="store_true")
    parser.add_argument("--transport")
    args = parser.parse_args()

    from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, SystemMessage, query

    session_state_path = None
    session_state_env = os.environ.get("TDDF_CLAUDE_AGENT_SESSION_FILE")
    if session_state_env:
        session_state_path = Path(session_state_env)

    resume_session_id = (
        _load_resume_session_id(session_state_path) if args.use_session else None
    )

    mcp_servers: dict[str, object] = {}
    mcp_url = os.environ.get("TDDF_CLAUDE_AGENT_MCP_URL")
    if mcp_url:
        mcp_servers["tddf"] = {"type": "http", "url": mcp_url}

    options = ClaudeAgentOptions(
        allowed_tools=json.loads(args.allowed_tools),
        disallowed_tools=json.loads(args.disallowed_tools),
        permission_mode=args.permission_mode,
        system_prompt=args.system_prompt,
        model=args.model,
        max_turns=args.max_turns,
        include_partial_messages=args.include_partial_messages,
        cli_path=args.cli_path,
        setting_sources=args.setting_sources.split(",")
        if args.setting_sources
        else None,
        extra_args=json.loads(args.extra_args),
        cwd=os.getcwd(),
        env={},
        mcp_servers=mcp_servers,
        resume=resume_session_id,
    )

    payload = _build_prompt_payload(args)
    if isinstance(payload, list):
        payload = _as_async_iterable(payload)
    transport = _build_transport(args)

    assistant_text_chunks: list[str] = []
    messages: list[dict[str, object]] = []
    result_payload: dict[str, object] | None = None
    session_id = resume_session_id

    async for message in query(prompt=payload, options=options, transport=transport):
        normalized = _normalize_for_json(message)
        messages.append(
            normalized if isinstance(normalized, dict) else {"value": normalized}
        )
        if isinstance(message, SystemMessage) and message.subtype == "init":
            init_session = message.data.get("session_id")
            if isinstance(init_session, str):
                session_id = init_session
        if hasattr(message, "content"):
            for block in getattr(message, "content", []):
                text = getattr(block, "text", None)
                if isinstance(text, str):
                    assistant_text_chunks.append(text)
        if isinstance(message, ResultMessage):
            result_payload = _normalize_for_json(message)

    _store_resume_session_id(session_state_path, session_id)

    assistant_text = "\n".join(
        chunk for chunk in assistant_text_chunks if chunk
    ).strip()
    if assistant_text:
        print(assistant_text)

    trace = {
        "input_mode": args.input_mode,
        "used_resume": resume_session_id is not None,
        "session_id": session_id,
        "message_count": len(messages),
        "messages": messages,
        "result_subtype": result_payload.get("subtype")
        if isinstance(result_payload, dict)
        else None,
        "result": result_payload,
        "assistant_text": assistant_text,
    }
    print(
        "TDDF_CLAUDE_AGENT_SDK_TRACE="
        + json.dumps(trace, sort_keys=True, ensure_ascii=False)
    )
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
