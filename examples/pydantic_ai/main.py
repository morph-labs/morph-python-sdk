import os
import asyncio

from morphcloud.computer import Computer

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio

computer = Computer.new(ttl_seconds=3600)

server = MCPServerStdio(
    command="morphcloud",
    args=["instance", "computer-mcp", computer._instance.id],
    env=dict(MORPH_API_KEY=os.getenv("MORPH_API_KEY"))
)
agent = Agent('openai:gpt-4o', mcp_servers=[server])


async def main():
    async with agent.run_mcp_servers():
        result = await agent.run('Go to google.com and take a screenshot of the page')
    print(result.data)
    #> There are 9,208 days between January 1, 2000, and March 18, 2025.

asyncio.run(main())
