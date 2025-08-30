import os
import asyncio

from agents import Agent, Runner
from agents.mcp import MCPServerStdio

from morphcloud.computer import Computer

computer = Computer.new(ttl_seconds=3600)

print(computer.desktop_url())

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
        result = await Runner.run(agent, "Search for the Stanford law school hackathon #5 page and find out who the organizers are.")

        print(result)


asyncio.run(run())

computer.shutdown()
