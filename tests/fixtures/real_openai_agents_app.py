from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from agents import Agent
from agents.agent_output import AgentOutputSchemaBase
from agents.handoffs import Handoff
from agents.items import (
    ModelResponse,
    TResponseInputItem,
    TResponseOutputItem,
    TResponseStreamEvent,
)
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelTracing
from agents.tool import Tool
from agents.usage import Usage
from openai.types.responses import (
    Response,
    ResponseCompletedEvent,
    ResponseContentPartAddedEvent,
    ResponseContentPartDoneEvent,
    ResponseCreatedEvent,
    ResponseInProgressEvent,
    ResponseOutputItemAddedEvent,
    ResponseOutputItemDoneEvent,
    ResponseOutputMessage,
    ResponseOutputText,
    ResponseTextDeltaEvent,
    ResponseTextDoneEvent,
    ResponseUsage,
)
from openai.types.responses.response_usage import (
    InputTokensDetails,
    OutputTokensDetails,
)


def _message_output(text: str) -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id="msg-smoke",
        content=[
            ResponseOutputText(
                text=text,
                type="output_text",
                annotations=[],
            )
        ],
        role="assistant",
        status="completed",
        type="message",
    )


def _response(output: list[TResponseOutputItem]) -> Response:
    return Response(
        id="resp-smoke",
        created_at=123,
        model="fake-openai-agents-model",
        object="response",
        output=output,
        tool_choice="none",
        tools=[],
        top_p=None,
        parallel_tool_calls=False,
        usage=ResponseUsage(
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            input_tokens_details=InputTokensDetails(cached_tokens=0),
            output_tokens_details=OutputTokensDetails(reasoning_tokens=0),
        ),
    )


class SmokeModel(Model):
    async def get_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any | None,
    ) -> ModelResponse:
        del (
            system_instructions,
            input,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id,
            conversation_id,
            prompt,
        )
        return ModelResponse(
            output=[_message_output("OpenAI Agents real package smoke")],
            usage=Usage(),
            response_id="resp-smoke",
        )

    async def stream_response(
        self,
        system_instructions: str | None,
        input: str | list[TResponseInputItem],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: AgentOutputSchemaBase | None,
        handoffs: list[Handoff],
        tracing: ModelTracing,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any | None,
    ) -> AsyncIterator[TResponseStreamEvent]:
        del (
            system_instructions,
            input,
            model_settings,
            tools,
            output_schema,
            handoffs,
            tracing,
            previous_response_id,
            conversation_id,
            prompt,
        )
        output_item = _message_output("OpenAI Agents real package smoke")
        response = _response([output_item])
        yield ResponseCreatedEvent(
            type="response.created",
            response=response,
            sequence_number=0,
        )
        yield ResponseInProgressEvent(
            type="response.in_progress",
            response=response,
            sequence_number=1,
        )
        yield ResponseOutputItemAddedEvent(
            type="response.output_item.added",
            item=output_item,
            output_index=0,
            sequence_number=2,
        )
        yield ResponseContentPartAddedEvent(
            type="response.content_part.added",
            item_id=output_item.id,
            output_index=0,
            content_index=0,
            part=output_item.content[0],
            sequence_number=3,
        )
        yield ResponseTextDeltaEvent(
            type="response.output_text.delta",
            item_id=output_item.id,
            output_index=0,
            content_index=0,
            delta=output_item.content[0].text,
            logprobs=[],
            sequence_number=4,
        )
        yield ResponseTextDoneEvent(
            type="response.output_text.done",
            item_id=output_item.id,
            output_index=0,
            content_index=0,
            text=output_item.content[0].text,
            logprobs=[],
            sequence_number=5,
        )
        yield ResponseContentPartDoneEvent(
            type="response.content_part.done",
            item_id=output_item.id,
            output_index=0,
            content_index=0,
            part=output_item.content[0],
            sequence_number=6,
        )
        yield ResponseOutputItemDoneEvent(
            type="response.output_item.done",
            item=output_item,
            output_index=0,
            sequence_number=7,
        )
        yield ResponseCompletedEvent(
            type="response.completed",
            response=response,
            sequence_number=8,
        )


real_agent = Agent(
    name="TDDF OpenAI Agents Smoke",
    instructions="Respond safely and concisely.",
    model=SmokeModel(),
)
