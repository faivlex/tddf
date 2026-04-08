from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import json
import os
from dataclasses import asdict, is_dataclass


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


def _resolve_agent(agent_ref: str) -> object:
    module_name, attr_path = agent_ref.split(":", 1)
    module = importlib.import_module(module_name)
    target: object = module
    for part in attr_path.split("."):
        target = getattr(target, part)
    if callable(target) and not hasattr(target, "name"):
        target = target()
    return target


def _build_input_payload(args: argparse.Namespace) -> object:
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
        return [{"role": "user", "content": prompt}]
    return prompt


async def _maybe_await(value: object) -> object:
    if inspect.isawaitable(value):
        return await value
    return value


async def _build_session(args: argparse.Namespace) -> object | None:
    if not args.use_session:
        return None
    session_id = os.environ.get("TDDF_SESSION_ID")
    if not session_id:
        return None

    if args.session_backend != "sqlite":
        raise ValueError(
            f"Unsupported OpenAI Agents session backend: {args.session_backend}"
        )

    from agents import SQLiteSession

    db_path = os.environ.get("TDDF_OPENAI_AGENTS_SESSION_DB_PATH")
    if db_path:
        return SQLiteSession(session_id, db_path)
    return SQLiteSession(session_id)


def _normalize_stream_event(event: object) -> dict[str, object]:
    normalized: dict[str, object] = {
        "type": getattr(event, "type", type(event).__name__)
    }
    if hasattr(event, "name"):
        normalized["name"] = getattr(event, "name")
    if hasattr(event, "new_agent"):
        normalized["new_agent"] = _normalize_for_json(getattr(event, "new_agent"))
    if hasattr(event, "item"):
        normalized["item"] = _normalize_for_json(getattr(event, "item"))
    if hasattr(event, "data"):
        normalized["data"] = _normalize_for_json(getattr(event, "data"))
    return normalized


async def main_async() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    parser.add_argument("--input-mode", choices=["messages", "prompt"], required=True)
    parser.add_argument("--input-template")
    parser.add_argument("--max-turns", type=int, required=True)
    parser.add_argument("--run-config", required=True)
    parser.add_argument("--use-session", action="store_true")
    parser.add_argument("--session-backend", choices=["sqlite"], default="sqlite")
    parser.add_argument("--tracing-disabled", action="store_true")
    args = parser.parse_args()

    if args.tracing_disabled:
        try:
            from agents import set_tracing_disabled

            set_tracing_disabled(True)
        except Exception:
            pass

    from agents import RunConfig, Runner

    agent = _resolve_agent(args.agent)
    payload = _build_input_payload(args)
    session = await _build_session(args)
    run_config_payload = json.loads(args.run_config)
    run_config = RunConfig(**run_config_payload) if run_config_payload else None

    run_kwargs: dict[str, object] = {"input": payload, "max_turns": args.max_turns}
    if session is not None:
        run_kwargs["session"] = session
    if run_config is not None:
        run_kwargs["run_config"] = run_config

    result = Runner.run_streamed(agent, **run_kwargs)
    events: list[dict[str, object]] = []
    async for event in result.stream_events():
        events.append(_normalize_stream_event(event))

    session_item_count: int | None = None
    if session is not None and hasattr(session, "get_items"):
        items = await _maybe_await(session.get_items())
        if isinstance(items, list):
            session_item_count = len(items)

    trace = {
        "agent": args.agent,
        "input_mode": args.input_mode,
        "input_payload": _normalize_for_json(payload),
        "max_turns": args.max_turns,
        "tracing_disabled": args.tracing_disabled,
        "session_enabled": session is not None,
        "session_backend": args.session_backend if session is not None else None,
        "session_id": os.environ.get("TDDF_SESSION_ID"),
        "session_item_count": session_item_count,
        "event_count": len(events),
        "events": events,
        "new_item_count": len(getattr(result, "new_items", [])),
        "new_items": _normalize_for_json(getattr(result, "new_items", [])),
        "raw_response_count": len(getattr(result, "raw_responses", [])),
        "raw_responses": _normalize_for_json(getattr(result, "raw_responses", [])),
        "last_agent_name": getattr(getattr(result, "last_agent", None), "name", None),
        "last_response_id": getattr(result, "last_response_id", None),
        "interruptions_count": len(getattr(result, "interruptions", [])),
        "final_output": _normalize_for_json(getattr(result, "final_output", None)),
        "is_complete": getattr(result, "is_complete", True),
    }
    if getattr(result, "final_output", None) is not None:
        print(
            json.dumps(
                {"final_output": _normalize_for_json(result.final_output)},
                ensure_ascii=False,
            )
        )
    print(
        "TDDF_OPENAI_AGENTS_TRACE="
        + json.dumps(trace, sort_keys=True, ensure_ascii=False)
    )
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
