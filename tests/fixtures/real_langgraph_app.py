from __future__ import annotations

import json
from typing_extensions import TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph


class State(TypedDict):
    messages: list[dict[str, str]]
    observed: str


def responder(state: State) -> dict[str, object]:
    prompt = state["messages"][-1]["content"] if state["messages"] else ""
    return {
        "observed": prompt,
        "messages": [{"role": "assistant", "content": "LangGraph real package smoke"}],
    }


builder = StateGraph(State)
builder.add_node("responder", responder)
builder.add_edge(START, "responder")
builder.add_edge("responder", END)
graph = builder.compile(checkpointer=InMemorySaver())


def build_graph() -> object:
    return graph
