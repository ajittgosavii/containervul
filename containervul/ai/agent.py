"""Agentic AI orchestrator — Claude tool-use loop for autonomous vulnerability analysis."""

from __future__ import annotations

import json
import logging
from typing import Generator, List, Optional

from containervul.ai.prompts import AGENT_SYSTEM_PROMPT
from containervul.ai.tools import TOOL_DEFINITIONS, ToolExecutor
from containervul.config import settings
from containervul.models import AgentEvent

logger = logging.getLogger(__name__)


class VulnerabilityAgent:
    """An autonomous agent that uses Claude's tool_use to scan, analyze, and remediate
    container vulnerabilities across multi-cloud environments."""

    def __init__(self, tool_executor: Optional[ToolExecutor] = None, api_key: str = ""):
        self._api_key = api_key or settings.claude_api_key
        self._executor = tool_executor or ToolExecutor()
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError:
                raise RuntimeError("anthropic SDK not installed")
            except Exception as exc:
                raise RuntimeError(f"Failed to initialize Claude client: {exc}")
        return self._client

    def run(self, user_message: str, max_turns: int = 0) -> Generator[AgentEvent, None, None]:
        """Execute an agent loop: send user message, process tool calls, repeat until done.

        Yields AgentEvent objects for each step (response text, tool calls, errors).
        """
        max_turns = max_turns or settings.agent_max_turns
        messages: List[dict] = [{"role": "user", "content": user_message}]

        for turn in range(max_turns):
            try:
                response = self.client.messages.create(
                    model=settings.claude_model,
                    max_tokens=settings.claude_max_tokens,
                    system=AGENT_SYSTEM_PROMPT,
                    tools=TOOL_DEFINITIONS,
                    messages=messages,
                )
            except Exception as exc:
                yield AgentEvent(type="error", content=f"API error: {exc}")
                return

            # Emit text blocks
            text_parts: List[str] = []
            tool_uses: List[dict] = []
            for block in response.content:
                if hasattr(block, "text"):
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_uses.append({
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

            if text_parts:
                yield AgentEvent(type="response", content="\n".join(text_parts))

            # If no tool calls, the agent is done
            if response.stop_reason == "end_turn" or not tool_uses:
                yield AgentEvent(type="complete", content="Agent finished")
                return

            # Execute tool calls and collect results
            tool_results: List[dict] = []
            for tool_call in tool_uses:
                result_str = self._executor.execute(tool_call["name"], tool_call["input"])

                yield AgentEvent(
                    type="tool_call",
                    tool_name=tool_call["name"],
                    tool_input=tool_call["input"],
                    tool_result=result_str[:2000],  # Truncate for display
                )

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_call["id"],
                    "content": result_str,
                })

            # Append assistant message and tool results for next turn
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        yield AgentEvent(type="complete", content=f"Agent stopped after {max_turns} turns")

    def run_sync(self, user_message: str, max_turns: int = 0) -> List[AgentEvent]:
        """Convenience method: run the agent and collect all events."""
        return list(self.run(user_message, max_turns))
