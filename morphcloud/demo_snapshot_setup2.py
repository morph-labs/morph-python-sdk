#!/usr/bin/env python3
# demo_snapshot_setup_refactored.py

import asyncio
import base64
import heapq
import json
import logging
import random
import sys
import termios  # For Unix/Linux/MacOS
import time
import traceback
import tty  # For Unix/Linux/MacOS
import webbrowser
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

from rich import print

from morphcloud.api import MorphCloudClient, Snapshot

# ---------------------------------------------------------------------------
# Best-First Search Framework using an asyncio.PriorityQueue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SearchNode:
    """Immutable node in the best-first search."""

    priority: float
    snapshot_id: str
    instruction: str
    previous_attempts: Tuple[str, ...] = field(default_factory=tuple)
    verification_logs: str = ""
    depth: int = 0

    def with_updates(self, **kwargs):
        """Return a new node with updated fields."""
        if "previous_attempts" in kwargs and isinstance(
            kwargs["previous_attempts"], list
        ):
            kwargs["previous_attempts"] = tuple(kwargs["previous_attempts"])
        return SearchNode(**{**self.__dict__, **kwargs})


class Config(NamedTuple):
    """Immutable configuration for the search."""

    client: Any
    base_snapshot_id: str
    instruction: str
    verification_command: Optional[str] = None
    max_parallelism: int = 3
    n_branches: int = 3
    max_depth: int = 5
    timeout_per_node: int = 180
    poll_interval: int = 2


async def process_node(
    node: SearchNode, config: Config
) -> Tuple[List[SearchNode], bool, Optional[Any], str]:
    """
    Process a single search node.

    Uses Snapshot._cache_effect to cache results based on node state.
    Returns:
      - A list of new nodes (if verification failed),
      - A boolean indicating whether verification passed,
      - The resulting snapshot (if verified), and
      - The collected verification logs.
    """
    snapshot = await config.client.snapshots.aget(node.snapshot_id)

    # Define the node processor as a function that works with Snapshot._cache_effect
    def node_processor(
        instance: "Instance",
        instruction: str,
        prev_attempts_str: str,
        verification_logs: str,
        depth: int,
        verification_command: str,
        timeout: int,
        poll_interval: int,
    ) -> None:
        """
        Process a search node on the given instance.

        This function will run on the instance, execute the agent with instructions,
        verify the results, and store the outcome for later retrieval.

        Args:
            instance: The VM instance to work with
            instruction: The instruction to run
            prev_attempts_str: Previous attempts as a string
            verification_logs: Logs from previous verification attempts
            depth: Current search depth
            verification_command: Command to verify success
            timeout: Timeout for verification
            poll_interval: Time between verification attempts
        """
        import base64
        import json
        import time

        from rich import print

        try:
            # Import the agent module
            from swe_standalone import MorphAgent

            # Create the agent
            agent = MorphAgent.from_instance(instance)

            # Add context from previous attempts
            if verification_logs:
                agent.add_user_message_sync(
                    f"Previous attempt failed with logs:\n{verification_logs}"
                )

            if prev_attempts_str:
                prev_attempts = prev_attempts_str.split("|")
                if prev_attempts:
                    agent.add_user_message_sync(
                        f"Previous approaches: {', '.join(prev_attempts)}. Try a new approach."
                    )

            # Run the agent with the provided instruction
            print(
                f"[bold blue]Running agent with instruction: {instruction[:100]}...[/bold blue]"
            )
            agent.run_sync(instruction)

            # Verify the result
            logs_collected = ""
            verified = False

            if verification_command:
                print(
                    f"[bold yellow]Verifying with command: {verification_command}[/bold yellow]"
                )
                start_time = time.time()

                while time.time() - start_time < timeout:
                    try:
                        res = instance.exec(verification_command)
                        if res.exit_code == 0:
                            verified = True
                            print(f"[bold green]Verification succeeded![/bold green]")
                            break
                        else:
                            error_out = (res.stdout or "") + (res.stderr or "")
                            logs_collected += f"\n[Failure at {time.time() - start_time:.1f}s]: {error_out}\n"
                            print(
                                f"[red]Verification failed: {error_out[:100]}...[/red]"
                            )
                    except Exception as e:
                        logs_collected += f"\n[Error]: {str(e)}\n"
                        print(
                            f"[bold red]Error during verification: {str(e)}[/bold red]"
                        )

                    time.sleep(poll_interval)
            else:
                # If no verification command is provided, assume success
                verified = True
                print(
                    "[bold green]No verification command provided, assuming success[/bold green]"
                )

            # Save the results to files for later retrieval
            result_data = {"verified": verified, "logs": logs_collected}

            # Save results as a JSON file
            result_json = json.dumps(result_data, ensure_ascii=False)
            b64_json = base64.b64encode(result_json.encode("utf-8")).decode("ascii")
            instance.exec(
                f"echo '{b64_json}' | base64 -d > /tmp/node_process_result.json"
            )

            # Also create indicator files for quick checking
            if verified:
                instance.exec("touch /tmp/node_process_verified")
            else:
                instance.exec("touch /tmp/node_process_failed")

            print(
                f"[bold {'green' if verified else 'red'}]Node processing {'succeeded' if verified else 'failed'}[/bold {'green' if verified else 'red'}]"
            )

        except Exception as e:
            import traceback

            error_msg = (
                f"Exception in node_processor: {str(e)}\n{traceback.format_exc()}"
            )
            print(f"[bold red]{error_msg}[/bold red]")
            # Save the error information
            instance.exec(f"echo '{error_msg}' > /tmp/node_process_error.txt")
            instance.exec("touch /tmp/node_process_failed")

    # Create a string representation of previous attempts for caching purposes
    prev_attempts_str = (
        "|".join(node.previous_attempts) if node.previous_attempts else ""
    )

    try:
        # Execute node_processor via _cache_effect
        print(f"[bold magenta]Processing node at depth {node.depth}[/bold magenta]")
        result_snapshot = await asyncio.to_thread(
            snapshot._cache_effect,
            fn=node_processor,
            instruction=node.instruction,
            prev_attempts_str=prev_attempts_str,
            verification_logs=node.verification_logs,
            depth=node.depth,
            verification_command=config.verification_command,
            timeout=config.timeout_per_node,
            poll_interval=config.poll_interval,
        )

        # Start an instance from the result snapshot to read the results
        print(
            f"[bold cyan]Reading results from snapshot {result_snapshot.id}[/bold cyan]"
        )
        instance = await config.client.instances.astart(result_snapshot.id)

        try:
            await instance.await_until_ready(timeout=300)

            # Check for indicator files to determine verification status
            verified_check = await asyncio.to_thread(
                lambda: instance.exec(
                    "test -f /tmp/node_process_verified && echo 'true' || echo 'false'"
                ).stdout.strip()
            )
            verified = verified_check == "true"

            # Read the logs
            logs = ""
            result_file_check = await asyncio.to_thread(
                lambda: instance.exec(
                    "test -f /tmp/node_process_result.json && echo 'true' || echo 'false'"
                ).stdout.strip()
            )

            if result_file_check == "true":
                try:
                    import base64
                    import json

                    result_json = await asyncio.to_thread(
                        lambda: instance.exec(
                            "cat /tmp/node_process_result.json"
                        ).stdout
                    )
                    if result_json:
                        result_data = json.loads(result_json)
                        logs = result_data.get("logs", "")
                except Exception as e:
                    logs = f"Error reading result data: {str(e)}"
            else:
                # Check if there was an error
                error_file_check = await asyncio.to_thread(
                    lambda: instance.exec(
                        "test -f /tmp/node_process_error.txt && echo 'true' || echo 'false'"
                    ).stdout.strip()
                )
                if error_file_check == "true":
                    error_content = await asyncio.to_thread(
                        lambda: instance.exec("cat /tmp/node_process_error.txt").stdout
                    )
                    logs = f"Error during processing: {error_content}"
                else:
                    logs = "No result data found."

            # Return the results
            return ([], verified, result_snapshot if verified else None, logs)

        finally:
            await instance.astop()

    except Exception as e:
        import traceback

        error_message = f"Error in process_node: {str(e)}\n{traceback.format_exc()}"
        print(f"[bold red]{error_message}[/bold red]")
        return ([], False, None, error_message)


async def bfs_agentrpc(
    snapshot,
    instruction: str,
    verification_command: Optional[str] = None,
    max_parallelism: int = 3,
    n_branches: int = 3,
    max_depth: int = 5,
    timeout_per_node: int = 180,
    poll_interval: int = 2,
) -> Snapshot:
    """
    Best-first search–based agent RPC implementation.

    Uses a shared asyncio.PriorityQueue so that all workers see the same state.
    Returns a snapshot that successfully passes verification.
    """
    config = Config(
        client=snapshot._api._client,
        base_snapshot_id=snapshot.id,
        instruction=instruction,
        verification_command=verification_command,
        max_parallelism=max_parallelism,
        n_branches=n_branches,
        max_depth=max_depth,
        timeout_per_node=timeout_per_node,
        poll_interval=poll_interval,
    )
    # Create a shared priority queue and add the initial node.
    queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
    initial_node = SearchNode(
        priority=1.0,
        snapshot_id=config.base_snapshot_id,
        instruction=config.instruction,
    )
    await queue.put((initial_node.priority, initial_node))

    completion_event = asyncio.Event()
    result_future = asyncio.Future()  # Will hold the successful snapshot

    async def worker(worker_id: int):
        while not completion_event.is_set():
            try:
                # Wait for the next node (with a timeout so we can check the event)
                prio, node = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                # If the queue is empty, check for termination.
                if queue.empty():
                    break
                else:
                    continue

            # Use our refactored process_node function
            _, verified, snap_result, logs = await process_node(node, config)
            if verified:
                if not completion_event.is_set():
                    result_future.set_result(snap_result)
                    completion_event.set()
            else:
                if node.depth < config.max_depth:
                    # Generate new approaches and add new nodes to the queue
                    approaches = await brainstorm_approaches(logs, config)
                    for approach in approaches:
                        new_priority = node.priority * 0.8 + random.random() * 0.2
                        new_node = SearchNode(
                            priority=new_priority,
                            snapshot_id=node.snapshot_id,
                            instruction=f"{config.instruction}\nSpecific approach: {approach}",
                            previous_attempts=node.previous_attempts + (approach,),
                            verification_logs=logs,
                            depth=node.depth + 1,
                        )
                        await queue.put((new_node.priority, new_node))
            queue.task_done()
        return

    # Start worker tasks.
    workers = [asyncio.create_task(worker(i)) for i in range(config.max_parallelism)]
    # Wait until the queue is fully processed or a result is found.
    try:
        await asyncio.wait_for(queue.join(), timeout=3600)  # 1-hour global timeout
    except asyncio.TimeoutError:
        print(
            "[bold yellow]Global search timeout reached. Terminating search.[/bold yellow]"
        )

    # Set completion event to cancel any remaining workers
    if not completion_event.is_set():
        completion_event.set()

    # Cancel any remaining workers
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    if result_future.done():
        return result_future.result()
    else:
        raise RuntimeError(
            f"Task '{instruction}' did not succeed after {config.max_depth} levels of search."
        )


async def brainstorm_approaches(logs: str, config: Config) -> List[str]:
    """
    Have the agent brainstorm new approaches based on verification logs.

    Args:
        logs: Error logs from the failed verification
        config: Configuration object containing client and other settings

    Returns:
        A list of strings, each representing a different approach
    """
    instruction = config.instruction
    n = config.n_branches
    from swe_standalone import MorphAgent

    # Define the processor function that will be used with _cache_effect
    def brainstorming_processor(
        instance: "Instance", logs: str, instruction: str, n: int
    ) -> None:
        """
        Processor function to run brainstorming on the instance.

        Args:
            instance: The VM instance
            logs: Error logs from failed verification
            instruction: Original instruction
            n: Number of approaches to generate
        """
        import json
        import time

        from swe_standalone import MorphAgent

        agent = MorphAgent.from_instance(instance)

        # Create a unique filename for the output
        output_file = f"/tmp/brainstorm_results_{int(time.time())}.json"

        # Create the brainstorming prompt
        brainstorming_prompt = f"""\
The previous attempt to complete the following task failed with these logs:

{logs}

Please brainstorm exactly {n} different specific approaches to solve this task.
Each approach should be distinct and address the issues shown in the logs.

Original task: {instruction}

Write your approaches as a JSON array to the file {output_file}.
The JSON should be an array of strings, where each string is an approach.

Example:
[
  "Install nginx directly from apt and configure it to serve a static page",
  "Use Docker to run an nginx container that serves the content"
]

After writing the file, output "BRAINSTORMING_COMPLETE" so I know you've finished.
"""
        # Run the agent
        response = agent.run_sync(brainstorming_prompt)

        # Check if the output file exists and is valid JSON
        validate_cmd = f"if [ -f {output_file} ]; then cat {output_file} | python3 -m json.tool >/dev/null && echo 'VALID' || echo 'INVALID'; else echo 'MISSING'; fi"
        validate_result = instance.exec(validate_cmd)

        # If the file doesn't exist or contains invalid JSON, create a fallback
        if validate_result.stdout.strip() != "VALID":
            fallback_approaches = [f"Alternative approach {i+1}" for i in range(n)]
            instance.exec(f"echo '{json.dumps(fallback_approaches)}' > {output_file}")

    # Create a snapshot where we'll run the brainstorming
    # Using _cache_effect ensures we don't repeat brainstorming for identical failures
    try:
        # Get a snapshot to use as the base for brainstorming
        base_snapshot = await config.client.snapshots.aget(config.base_snapshot_id)

        # Generate a unique identifier for the logs to use in caching
        log_hash = str(hash(logs) % 10000)
        instruction_hash = str(hash(instruction) % 10000)

        # Use _cache_effect to run or retrieve cached brainstorming results
        brainstorm_snapshot = await asyncio.to_thread(
            base_snapshot._cache_effect,
            fn=brainstorming_processor,
            logs=logs,
            instruction=instruction,
            n=n,
        )

        # Start an instance to read the results
        instance = await config.client.instances.astart(brainstorm_snapshot.id)
        try:
            await instance.await_until_ready()

            # Read the output file
            output_file_glob = "/tmp/brainstorm_results_*.json"
            find_result = await asyncio.to_thread(
                lambda: instance.exec(
                    f"ls -t {output_file_glob} | head -1"
                ).stdout.strip()
            )

            if find_result:
                result = await asyncio.to_thread(
                    lambda: instance.exec(f"cat {find_result}").stdout
                )

                if result:
                    try:
                        approaches = json.loads(result)
                        if isinstance(approaches, list) and all(
                            isinstance(a, str) for a in approaches
                        ):
                            return approaches[:n]
                    except json.JSONDecodeError:
                        print(f"[bold red]Error parsing brainstorming JSON[/bold red]")

            # Fallback if we couldn't get valid results
            return [f"Alternative approach {i+1}" for i in range(n)]

        finally:
            await instance.astop()

    except Exception as e:
        print(f"[bold red]Error during brainstorming: {str(e)}[/bold red]")
        # Fallback to generic approaches
        return [f"Alternative approach {i+1}" for i in range(n)]


# ---------------------------------------------------------------------------
# Extend Snapshot with BFS Agent RPC
# ---------------------------------------------------------------------------
def extend_snapshot_with_bfs(snapshot_class):
    """Extend the Snapshot class with the bfs_agentrpc method."""
    snapshot_class.bfs_agentrpc = lambda self, *args, **kwargs: asyncio.run(
        bfs_agentrpc(self, *args, **kwargs)
    )
    return snapshot_class


# ---------------------------------------------------------------------------
# Demo main() function
# ---------------------------------------------------------------------------
def main():
    from morphcloud.api import MorphCloudClient, Snapshot

    # Extend Snapshot with our new bfs_agentrpc.
    extend_snapshot_with_bfs(Snapshot)

    client = MorphCloudClient()
    base_snapshot = client.snapshots.get("snapshot_zo8cptbg")

    snap1 = (
        base_snapshot.setup("apt-get update")
        .setup("apt-get install -y python3-pip")
        .setup("pip3 install uvicorn flask")
        .setup("echo 'Hello, world' > /hello.txt")
    )
    print(f"[demo] Final snapshot ID after first chain: {snap1.id}")

    # Demo using the new process_node function
    print(
        "[bold green]Running verification test using refactored process_node...[/bold green]"
    )
    node = SearchNode(
        priority=1.0,
        snapshot_id=snap1.id,
        instruction="Set up a Flask hello world app on port 8000",
    )
    config = Config(
        client=client,
        base_snapshot_id=snap1.id,
        instruction=node.instruction,
        verification_command="curl -s http://localhost:8000 | grep -q 'Hello'",
        timeout_per_node=180,
    )
    _, verified, result_snapshot, logs = asyncio.run(process_node(node, config))
    if verified:
        print(f"[bold green]Verification succeeded![/bold green]")
        print(f"Result snapshot ID: {result_snapshot.id}")
    else:
        print(f"[bold red]Verification failed with logs:[/bold red]")
        print(logs)

    # Demo using the bfs_agentrpc
    print("[bold green]Running BFS Agent RPC test...[/bold green]")
    final_snap = snap1.bfs_agentrpc(
        instruction="Set up nginx as a web server on port 80",
        verification_command="curl -s -o /dev/null -w '%{http_code}' http://localhost:80 | grep -q '^200$'",
        max_parallelism=2,
        n_branches=2,
        max_depth=3,
    )  # caches the first successful VM that passes the validation
    print(
        f"[bold green]Successfully configured snapshot via bfs_agentrpc:[/bold green] {final_snap.id}"
    )


if __name__ == "__main__":
    main()
