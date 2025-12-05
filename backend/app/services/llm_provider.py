"""
LLM Provider - Thin wrapper around ModelPool for backwards compatibility.

DEPRECATED: This module is maintained for backwards compatibility only.
For new code, use ModelPool.simple_chat_completion() and
ModelPool.simple_chat_with_tools() directly from
app.services.orchestration.model_orchestrator.

Example migration:
    # Old (deprecated):
    from app.services.llm_provider import llm_provider
    result = await llm_provider.chat_completion(messages)

    # New (preferred):
    from app.services.orchestration.model_orchestrator import ModelPool
    result = await ModelPool.simple_chat_completion(messages)
"""
from typing import List, Dict, Any, Optional
from app.services.orchestration.model_orchestrator import ModelPool


class LLMProvider:
    """
    DEPRECATED: Thin wrapper around ModelPool for backwards compatibility.

    For new code, use ModelPool.simple_chat_completion() and
    ModelPool.simple_chat_with_tools() directly.
    """

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 4096,
        output_mode: str = "markers",
        json_schema: Optional[str] = None,
        _retry_max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        DEPRECATED: Use ModelPool.simple_chat_completion() for new code.

        Make a chat completion request to the LLM.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            model: Model to use (defaults to settings.LLM_MODEL)
            temperature: Sampling temperature (None = use API default for the model)
            max_tokens: Maximum tokens in response
            output_mode: Response format mode:
                - "markers": Default, no special formatting (uses *DRAFT:, *VOTE: markers)
                - "json": Use response_format: {"type": "json_object"}
                - "guided_json": Use vLLM guided_json with schema (strictest)
            json_schema: JSON schema string for guided_json mode
            _retry_max_tokens: Internal override for retry on token errors

        Returns:
            Dict with 'content' key containing the response text
        """
        return await ModelPool.simple_chat_completion(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            output_mode=output_mode,
            json_schema=json_schema,
            _retry_max_tokens=_retry_max_tokens,
        )

    async def chat_completion_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        tool_choice: str = "auto",
        _retry_max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        DEPRECATED: Use ModelPool.simple_chat_with_tools() for new code.

        Make a chat completion request with tool calling support.

        Args:
            messages: List of message dicts (can include tool results)
            tools: List of tool definitions in OpenAI format
            model: Model to use (defaults to settings.LLM_MODEL)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            tool_choice: Tool choice mode ("auto", "none", or specific tool)
            _retry_max_tokens: Internal override for retry on token errors

        Returns:
            Dict with 'content' and 'tool_calls' keys
        """
        return await ModelPool.simple_chat_with_tools(
            messages=messages,
            tools=tools,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            tool_choice=tool_choice,
            _retry_max_tokens=_retry_max_tokens,
        )


# Global singleton for backwards compatibility
# DEPRECATED: For new code, use ModelPool.simple_* methods directly
llm_provider = LLMProvider()
