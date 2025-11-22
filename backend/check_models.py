import asyncio
import httpx

async def list_models():
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get('https://192.168.33.158:5000/v1/models')
            print(f"Status: {response.status_code}")
            print(f"Models: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(list_models())
