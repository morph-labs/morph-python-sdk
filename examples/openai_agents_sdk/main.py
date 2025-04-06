import os
import asyncio

from agents import Agent, Runner
from agents.mcp import MCPServerStdio

from morphcloud.computer import Computer

computer = Computer.new(ttl_seconds=3600)

async def run():
    async with MCPServerStdio(
        params=dict(
            command="morphcloud",
            args=["instance", "computer-mcp", computer._instance.id],
            env=dict(MORPH_API_KEY=os.getenv("MORPH_API_KEY"))
        ),
    ) as mcp_server:
        agent = Agent(
            name="Assistant",
            instructions="You are a helpful assistant with access to a computer.",
            mcp_servers=[mcp_server],
        )
        result = await Runner.run(agent, "Go to google.com and take a screenshot of the page and tell me what you see")

        print(result)


asyncio.run(run())

computer.shutdown()
