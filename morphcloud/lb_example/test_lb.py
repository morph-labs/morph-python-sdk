import asyncio

import httpx

LB_URL = "https://lb-morphvm-bylwz286.http.cloud.morph.so/process"  # Update if your LB URL is different


async def send_request(client: httpx.AsyncClient, request_id: int) -> str:
    payload = {"data": {"message": "yeehaw"}}
    try:
        response = await client.post(LB_URL, json=payload)
        response.raise_for_status()
        return f"Request {request_id}: {response.text}"
    except Exception as e:
        return f"Request {request_id} failed: {e}"


async def main():
    async with httpx.AsyncClient() as client:
        tasks = [send_request(client, i) for i in range(20)]
        # Process tasks as they complete.
        for coro in asyncio.as_completed(tasks):
            result = await coro
            print(result)


if __name__ == "__main__":
    asyncio.run(main())
