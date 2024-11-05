import json
import os

from examples.skeleton_agent import SimpleAgent
from morphcloud import Runtime

agent = SimpleAgent(api_key=os.environ.get("ANTHROPIC_API_KEY", "sk-ant-YOUR_KEY_HERE"))
snapshot_id = ""

# Create initial runtime with git setup
with Runtime.create(
    setup=["sudo apt update", "sudo apt install -y git"], vcpus=2, memory=3000
) as runtime:
    agent.set_runtime(runtime)
    response = agent.run(
        "Could you please clone the repository https://github.com/maxvonhippel/AttackerSynthesis.git into your current workspace?"
    )
    print(response)

    # Take a snapshot of the current state using the snapshot interface
    snapshot_result = runtime.snapshot.create()
    snapshot_id = snapshot_result.get("id")
    print(f"Created snapshot: {snapshot_id}")

    response = agent.run(
        "Great! Now let's find a function that chooses a bit name. After that, please find all references to that function in the codebase and synthesize all your insights."
    )
    print(response)

    response = agent.run(
        "What assumptions does the function make about the input and output of the function?"
    )
    print(response)

# Create a new runtime from the snapshot and use direct tool execution
with Runtime.create(snapshot_id=snapshot_id) as runtime:
    # List files using execute interface
    list_files_result = runtime.execute.list_file_tree()
    print(list_files_result)

    # Perform semantic search
    search_result = runtime.execute.semantic_search(
        query="a function that selects a bit name", max_results=10
    )

    if search_result.get("success") and search_result.get("result", {}).get("results"):
        # Select the first result from the semantic search
        first_result = search_result["result"]["results"][0]
        file_path = first_result["path"]
        line_range = first_result["lineRange"].split(" - ")

        # Get code links for the found result
        code_links_result = runtime.execute.get_code_links(
            file=file_path,
            line_start=int(line_range[0]),
            line_end=int(line_range[1]),
            identifier=first_result["name"],
        )

        print(code_links_result)

# Runtime instances are automatically stopped and deleted when the with blocks are exited
