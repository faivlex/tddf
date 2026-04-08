from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any


class FakeTransport:
    def __init__(self) -> None:
        self._ready = False
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    async def connect(self) -> None:
        self._ready = True

    async def write(self, data: str) -> None:
        payload = json.loads(data)
        payload_type = payload.get("type")
        if payload_type == "control_request":
            request_id = payload.get("request_id")
            request = payload.get("request", {})
            if request.get("subtype") == "initialize":
                await self._queue.put(
                    {
                        "type": "control_response",
                        "response": {
                            "subtype": "success",
                            "request_id": request_id,
                            "response": {"commands": []},
                        },
                    }
                )
            return
        if payload_type == "user":
            await self._queue.put(
                {
                    "type": "system",
                    "subtype": "init",
                    "data": {"session_id": "docker-claude-session"},
                }
            )
            await self._queue.put(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "text",
                                "text": "Claude Agent SDK real package smoke",
                            }
                        ],
                        "model": "claude-sonnet-4-5",
                        "session_id": "docker-claude-session",
                    },
                }
            )
            await self._queue.put(
                {
                    "type": "result",
                    "subtype": "success",
                    "duration_ms": 100,
                    "duration_api_ms": 80,
                    "is_error": False,
                    "num_turns": 1,
                    "session_id": "docker-claude-session",
                    "result": "done",
                    "total_cost_usd": 0.001,
                }
            )
            await self._queue.put(None)

    def read_messages(self) -> AsyncIterator[dict[str, Any]]:
        return self._read_messages()

    async def _read_messages(self) -> AsyncIterator[dict[str, Any]]:
        while True:
            item = await self._queue.get()
            if item is None:
                return
            yield item

    async def close(self) -> None:
        self._ready = False
        await self._queue.put(None)

    def is_ready(self) -> bool:
        return self._ready

    async def end_input(self) -> None:
        return None


def build_transport() -> FakeTransport:
    return FakeTransport()
