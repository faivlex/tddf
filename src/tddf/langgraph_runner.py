from __future__ import annotations

import argparse
import importlib
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
    if hasattr(value, "value") and hasattr(value, "interrupts"):
        return {
            "value": _normalize_for_json(getattr(value, "value")),
            "interrupts": _normalize_for_json(getattr(value, "interrupts")),
        }
    if hasattr(value, "__dict__") and value.__dict__:
        return _normalize_for_json(vars(value))
    return repr(value)


def _resolve_target(graph_ref: str) -> object:
    module_name, attr_path = graph_ref.split(":", 1)
    module = importlib.import_module(module_name)
    target: object = module
    for part in attr_path.split("."):
        target = getattr(target, part)
    if (
        callable(target)
        and not hasattr(target, "stream")
        and not hasattr(target, "invoke")
    ):
        target = target()
    if (
        hasattr(target, "compile")
        and not hasattr(target, "stream")
        and not hasattr(target, "invoke")
    ):
        target = target.compile()
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

    if args.input_mode == "prompt":
        return prompt
    return {"messages": [{"role": "user", "content": prompt}]}


def _stream_target(
    target: object,
    payload: object,
    config: dict[str, object] | None,
    context: dict[str, object],
    stream_modes: list[str],
) -> tuple[bool, list[object], object | None]:
    if not hasattr(target, "stream"):
        return False, [], _invoke_target(target, payload, config, context)

    kwargs: dict[str, object] = {
        "stream_mode": stream_modes,
        "version": "v2",
    }
    if context:
        kwargs["context"] = context

    call_args = [payload]
    if config is not None:
        call_args.append(config)

    try:
        iterator = target.stream(*call_args, **kwargs)
    except TypeError:
        kwargs.pop("context", None)
        iterator = target.stream(*call_args, **kwargs)

    parts: list[object] = []
    final_output: object | None = None
    for part in iterator:
        normalized = _normalize_for_json(part)
        parts.append(normalized)
        if isinstance(normalized, dict) and normalized.get("type") == "values":
            final_output = normalized.get("data")
    return True, parts, final_output


def _invoke_target(
    target: object,
    payload: object,
    config: dict[str, object] | None,
    context: dict[str, object],
) -> object | None:
    if not hasattr(target, "invoke"):
        raise TypeError(
            "Resolved LangGraph target does not expose stream() or invoke()."
        )

    kwargs: dict[str, object] = {"version": "v2"}
    if context:
        kwargs["context"] = context
    call_args = [payload]
    if config is not None:
        call_args.append(config)

    try:
        result = target.invoke(*call_args, **kwargs)
    except TypeError:
        kwargs.pop("context", None)
        result = target.invoke(*call_args, **kwargs)

    return _normalize_for_json(result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", required=True)
    parser.add_argument("--input-mode", choices=["messages", "prompt"], required=True)
    parser.add_argument("--input-template")
    parser.add_argument("--stream-modes", required=True)
    parser.add_argument("--configurable", required=True)
    parser.add_argument("--context", required=True)
    parser.add_argument("--use-thread-id", action="store_true")
    args = parser.parse_args()

    target = _resolve_target(args.graph)
    payload = _build_prompt_payload(args)
    configurable = json.loads(args.configurable)
    if args.use_thread_id and "TDDF_SESSION_ID" in os.environ:
        configurable.setdefault("thread_id", os.environ["TDDF_SESSION_ID"])
    config = {"configurable": configurable} if configurable else None
    context = json.loads(args.context)
    stream_modes = [mode for mode in args.stream_modes.split(",") if mode]

    used_streaming, stream_parts, final_output = _stream_target(
        target, payload, config, context, stream_modes
    )
    if final_output is None and not used_streaming:
        final_output = _invoke_target(target, payload, config, context)

    trace = {
        "graph": args.graph,
        "input_mode": args.input_mode,
        "used_streaming": used_streaming,
        "stream_modes": stream_modes,
        "thread_id": configurable.get("thread_id") if configurable else None,
        "configurable": _normalize_for_json(configurable),
        "context": _normalize_for_json(context),
        "input_payload": _normalize_for_json(payload),
        "stream_part_count": len(stream_parts),
        "stream_parts": stream_parts,
        "final_output": _normalize_for_json(final_output),
    }
    if final_output is not None:
        print(
            json.dumps(
                {"final_output": _normalize_for_json(final_output)}, ensure_ascii=False
            )
        )
    print(
        "TDDF_LANGGRAPH_TRACE=" + json.dumps(trace, sort_keys=True, ensure_ascii=False)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
