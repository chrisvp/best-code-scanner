from openai import AsyncOpenAI
import httpx
from typing import List, Dict, Any, Optional
from app.core.config import settings

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
    ) -> Dict[str, Any]:
        """
        Make a chat completion request to the LLM.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            model: Model to use (defaults to settings.LLM_MODEL)
            temperature: Sampling temperature (None = use API default for the model)
            max_tokens: Maximum tokens in response

        Returns:
            Dict with 'content' key containing the response text
        """
        client = self.get_client()
        model = model or self.default_model

        try:
            # Build kwargs, only include temperature if explicitly set
            kwargs = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
            }
            if temperature is not None:
                kwargs["temperature"] = temperature

            response = await client.chat.completions.create(**kwargs)

            content = response.choices[0].message.content if response.choices else ""

            return {
                "content": content,
                "model": model,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                }
            }
        finally:
            await client.close()

llm_provider = LLMProvider()
