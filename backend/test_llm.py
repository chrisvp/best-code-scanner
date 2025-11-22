import asyncio
from app.services.llm_provider import llm_provider
from app.core.config import settings

async def test_llm():
    try:
        client = llm_provider.get_client()
        print(f"Testing model: {settings.LLM_VERIFICATION_MODEL}")
        response = await client.chat.completions.create(
            model=settings.LLM_VERIFICATION_MODEL,
            messages=[{"role": "user", "content": "Say 'Verified' if you can hear me."}],
            max_tokens=10
        )
        print(f"Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_llm())
