import asyncio
import httpx

async def list_models():
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get('https://192.168.33.158:5000/v1/models')
            with open('models_output.txt', 'w') as f:
                f.write(f"Status: {response.status_code}\n")
                f.write(f"Models: {response.text}\n")
            print("Done")
    except Exception as e:
        with open('models_output.txt', 'w') as f:
            f.write(f"Error: {e}\n")
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(list_models())
