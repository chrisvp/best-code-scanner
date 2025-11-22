from openai import AsyncOpenAI
import httpx
from app.core.config import settings

class LLMProvider:
    def __init__(self):
        self.base_url = settings.LLM_BASE_URL
        self.api_key = settings.LLM_API_KEY
        self.verify_ssl = settings.LLM_VERIFY_SSL

    def get_client(self) -> AsyncOpenAI:
        # Create a custom httpx client to handle SSL verification skipping and set timeout
        http_client = httpx.AsyncClient(verify=self.verify_ssl, timeout=60.0)
        
        return AsyncOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            http_client=http_client
        )

llm_provider = LLMProvider()
