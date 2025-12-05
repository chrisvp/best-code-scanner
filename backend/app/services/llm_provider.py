from openai import AsyncOpenAI, BadRequestError
import httpx
import json
from typing import List, Dict, Any, Optional
from app.core.config import settings
from app.services.token_utils import is_max_tokens_error, calculate_retry_max_tokens

class LLMProvider:
    def __init__(self):
        self.base_url = settings.LLM_BASE_URL
        self.api_key = settings.LLM_API_KEY
        self.verify_ssl = settings.LLM_VERIFY_SSL
        self.default_model = settings.LLM_MODEL

    def get_client(self) -> AsyncOpenAI:
        # Create a custom httpx client to handle SSL verification skipping and set timeout
        # 300 second timeout for LLM requests (large diffs take time)
        http_client = httpx.AsyncClient(verify=self.verify_ssl, timeout=300.0)

        return AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            http_client=http_client
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 4096,
        output_mode: str = "markers",  # "markers", "json", or "guided_json"
        json_schema: Optional[str] = None,  # JSON schema string for guided_json mode
        _retry_max_tokens: Optional[int] = None,  # Internal: override for retry
    ) -> Dict[str, Any]:
        """
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

        Returns:
            Dict with 'content' key containing the response text
        """
        client = self.get_client()
        model = model or self.default_model
        effective_max_tokens = _retry_max_tokens if _retry_max_tokens is not None else max_tokens

        try:
            # Build kwargs, only include temperature if explicitly set
            kwargs = {
                "model": model,
                "messages": messages,
                "max_tokens": effective_max_tokens,
            }
            if temperature is not None:
                kwargs["temperature"] = temperature

            # Apply output mode formatting
            if output_mode == "json":
                # Use OpenAI-compatible response_format
                kwargs["response_format"] = {"type": "json_object"}
            elif output_mode == "guided_json" and json_schema:
                # Use vLLM's guided_json parameter for strict schema enforcement
                try:
                    schema = json.loads(json_schema) if isinstance(json_schema, str) else json_schema
                    kwargs["extra_body"] = {"guided_json": schema}
                except json.JSONDecodeError:
                    # If schema is invalid, fall back to regular json mode
                    kwargs["response_format"] = {"type": "json_object"}

            try:
                response = await client.chat.completions.create(**kwargs)
            except BadRequestError as e:
                # Check if this is a max_tokens error that we can retry
                error_message = str(e)
                if _retry_max_tokens is None and is_max_tokens_error(error_message):
                    new_max_tokens = calculate_retry_max_tokens(error_message)
                    if new_max_tokens and new_max_tokens > 100:
                        print(f"[LLM RETRY] max_tokens error, retrying with {new_max_tokens}")
                        await client.close()
                        return await self.chat_completion(
                            messages=messages,
                            model=model,
                            temperature=temperature,
                            max_tokens=max_tokens,
                            output_mode=output_mode,
                            json_schema=json_schema,
                            _retry_max_tokens=new_max_tokens
                        )
                raise  # Re-raise if we can't retry

            content = response.choices[0].message.content if response.choices else ""

            return {
                "content": content,
                "model": model,
                "output_mode": output_mode,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                }
            }
        finally:
            await client.close()

llm_provider = LLMProvider()
