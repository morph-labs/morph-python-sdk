# import base64
#
# from morphcloud.computers import Computer
#
# computer = Computer.new(ttl_seconds=3600)
#
# computer.browser.goto("https://www.google.com")
#
# pngb64 = computer.browser.screenshot()
#
# with open("screenshot.png", "wb") as f:
#     f.write(base64.b64decode(pngb64))
#
# computer.shutdown()
#
from agents import Agent, Runner

from morphcloud.computers import Computer

computer = Computer.new(ttl_seconds=3600)
print(computer._instance.id)

agent = Agent(
    name="Assistant",
    instructions="You are a helpful assistant with access to a computer.",
    mcp_servers=[computer.mcp()]
)
result = Runner.run_sync(agent, "Using google find out when the stanford law hackathon is happening.")
print(result.final_output)

computer.shutdown()
