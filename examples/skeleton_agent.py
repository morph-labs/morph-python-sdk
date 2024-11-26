import json
import os
from typing import Optional

import anthropic

from morphcloud import Runtime


class SimpleAgent:
    def __init__(self, api_key: str, runtime: Optional[Runtime] = None):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.runtime = runtime
        # Get tools in Anthropic format
        if self.runtime:
            self.tools = (
                self.runtime.actions.as_anthropic_tools()
            )  # Fixed: use actions property
        else:
            self.tools = []
        self.messages = []  # Initialize an empty list to store conversation history

    def set_runtime(self, runtime: Runtime):
        self.runtime = runtime
        self.tools = (
            self.runtime.actions.as_anthropic_tools()
        )  # Fixed: use actions property

    def refresh_tools(self):
        if self.runtime and self.tools:
            self.tools = (
                self.runtime.actions.as_anthropic_tools()
            )  # Fixed: use actions property

    def run(self, prompt: str) -> str:
        print("User:", prompt)
        self.messages.append({"role": "user", "content": prompt})
        while True:
            response = self.client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1000,
                temperature=0,
                tools=self.tools,
                messages=self.messages,
            )

            last_content = response.content[-1]

            if last_content.type == "text":
                self.messages.append(
                    {"role": "assistant", "content": last_content.text}
                )
                return last_content.text

            if last_content.type == "tool_use":
                tool_use = last_content
                function_name = tool_use.name
                function_args = tool_use.input

                # Fixed: Use execute attribute and proper method calling
                method = getattr(self.runtime.execute, function_name)
                result = method(**function_args)

                self.messages.append(
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "text",
                                "text": f"<thinking>Using the {function_name} tool.</thinking>",
                            },
                            {
                                "type": "tool_use",
                                "id": tool_use.id,
                                "name": function_name,
                                "input": function_args,
                            },
                        ],
                    }
                )

                self.messages.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_use.id,
                                "content": str(result),
                            }
                        ],
                    }
                )

                print("Tool use:", function_name, function_args)
                print("Tool Response:", result)
                print("")
                print("")
                # IMPORTANT: After each tool use, refresh tools! Since the environment can change, we need to refresh the tools.
                self.refresh_tools()
            else:
                self.messages.append(
                    {"role": "assistant", "content": "Unexpected response type"}
                )


if __name__ == "__main__":
    api_key = os.environ.get("ANTHROPIC_API_KEY", "sk-ant-YOUR_KEY_HERE")
    if not api_key:
        raise ValueError("Please set the ANTHROPIC_API_KEY environment variable")

    # Use context manager for proper cleanup
    with Runtime.create(snapshot_id="snapshot_y31d9j6o") as runtime:
        agent = SimpleAgent(api_key=api_key, runtime=runtime)
        print("Agent initialized")
        response = agent.run("What is the current directory?")
        print(response)
        response = agent.run(
            "Let's create a python file called 'greet.py' and add a function called 'greet' that prints 'Hello, World!'"
        )
        print(response)
        response = agent.run("Can you execute the greet function using the terminal?")
        print(response)
