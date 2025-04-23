# demo_snapshot_setup.py
import asyncio
import functools
import sys
import termios  # For Unix/Linux/MacOS
import time
import tty  # For Unix/Linux/MacOS
import webbrowser

import httpx
from rich import print

from morphcloud.api import MorphCloudClient, Snapshot


class SnapshotAIMixin:
    """
    A mixin for MorphCloud Snapshot class that adds AI-assisted setup capabilities.

    This mixin provides an `ai_exec` method that uses the MorphAgent to execute
    natural language instructions and ensures the setup is properly completed.
    """

    def ai_exec(
        self, instruction, validation_command=None, timeout=180, poll_interval=2
    ):
        """
        Uses MorphAgent to configure the VM based on natural language instructions
        and optionally validates the setup with a command.

        Args:
            instruction (str): Natural language instruction for the AI agent
            validation_command (str, optional): A command to execute on the VM to verify
                                              the setup was successful. Should return exit code 0
                                              when setup is correct.
            timeout (int): Maximum time in seconds to wait for validation
            poll_interval (int): Time in seconds between validation attempts

        Returns:
            The resulting snapshot after the AI setup is complete

        Raises:
            TimeoutError: If validation doesn't succeed within timeout
        """

        def _ai_exec_effect(
            instance, instruction, validation_command, timeout, poll_interval
        ):
            import asyncio
            import time

            from rich import print
            from swe_standalone import MorphAgent

            agent = MorphAgent.from_instance(instance)
            start_time = time.time()

            # Run the AI agent with the given instruction
            asyncio.run(agent.run(instruction))

            # If no validation command is provided, assume success
            if validation_command is None:
                print(
                    f"[AI Setup] [bold green]Completed instruction: {instruction}[/bold green]"
                )
                return

            # Validate the setup by polling with the validation command
            while time.time() - start_time < timeout:
                ssh_result = instance.exec(validation_command)

                if ssh_result.exit_code == 0:
                    print(
                        f"[AI Setup] [bold green]Successfully validated: {instruction}[/bold green]"
                    )
                    return

                time.sleep(poll_interval)

            raise TimeoutError(
                f"AI setup did not complete successfully within {timeout} seconds. "
                f"Instruction: '{instruction}'"
            )

        # Use the existing _cache_effect method to run our setup function
        return self._cache_effect(
            _ai_exec_effect,
            instruction=instruction,
            validation_command=validation_command,
            timeout=timeout,
            poll_interval=poll_interval,
        )


def dummy_tasker_callback(instance):
    """
    cedes control to the user to gather input for a modification to be made to the VM before proceeding.

    it should block on input() and then immediately write the gathered input to /tmp/tasker_input.txt on the VM.
    """
    # Get input from the user
    user_input = input("Please enter modification to be made to the VM: ")

    # Write the input to a file on the VM using the instance's exec method
    write_command = f"echo '{user_input}' > /tmp/tasker_input.txt"
    result = instance.exec(write_command)

    # Check if the command executed successfully
    if result.exit_code == 0:
        print("Input successfully written to /tmp/tasker_input.txt on the VM.")
    else:
        print(f"Error writing to VM: {result.stderr}")

    return user_input


def dummy_tasker_callback2(instance, instruction: str):
    """
    Displays an instruction, opens a browser to the instance's desktop service,
    and waits for user to complete modifications via VNC.

    Args:
        instance: The VM instance
        instruction: Instruction to show the user about what modifications to make

    Raises:
        RuntimeError: If the desktop service is not registered for this instance
    """
    import sys
    import webbrowser

    from rich import print

    # Print the instruction for the user
    print(f"\n[bold yellow]INSTRUCTION:[/bold yellow] {instruction}")

    # Prompt user to press any key to continue
    print("\nPress any key to open the desktop service in your browser...")
    _wait_for_keypress()

    # Try to get the desktop service URL from the networking.http_services list
    try:
        # Find the desktop service in the http_services list
        desktop_service = None
        for service in instance.networking.http_services:
            if service.name == "desktop":
                desktop_service = service
                break

        if not desktop_service:
            raise RuntimeError("Desktop service not registered for this instance")

        # Open the browser to the desktop URL
        desktop_url = desktop_service.url
        print(f"[bold blue]Opening desktop service at: {desktop_url}[/bold blue]")
        webbrowser.open(desktop_url)

    except Exception as e:
        print(f"[bold red]ERROR: {str(e)}[/bold red]")
        raise RuntimeError(f"Failed to access desktop service: {str(e)}")

    # Wait for user to complete their modifications
    print(
        "\nMake your modifications via the desktop interface, then press any key to continue..."
    )
    _wait_for_keypress()

    print("[bold green]✓ User modifications completed via desktop service[/bold green]")


def _wait_for_keypress():
    """Helper function to wait for a keypress in a cross-platform way"""
    try:
        # For Windows
        import msvcrt

        msvcrt.getch()
    except ImportError:
        # For Unix/Linux/MacOS
        import sys
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def verify_webserver_setup(instance):
    """
    Uses MorphAgent (from swe_standalone) to configure a FastAPI hello world
    server on port 9007 as a systemd service, then loops until a GET request
    to 'http://localhost:9007' (inside the VM) returns 200.
    """
    from swe_standalone import MorphAgent

    agent = MorphAgent.from_instance(instance)

    timeout = 180  # seconds
    start_time = time.time()

    while time.time() - start_time < timeout:
        # Attempt to set up the webserver:
        asyncio.run(
            agent.run(
                "set up a fastapi hello world server listening on port 9007 as a systemd service"
            )
        )

        # Now check from inside the instance, using a small bash one-liner:
        #
        #     curl -s -o /dev/null -w '%{http_code}' http://localhost:9007
        #
        # That prints only the HTTP status code. We want exit code 0 only if it's "200".
        # One quick approach:
        #
        #    test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:9007) = 200
        #
        # i.e. "test <curl output> = 200"
        #
        # Or we can pipe it to grep:
        #
        #    curl -s -o /dev/null -w '%{http_code}' http://localhost:9007 | grep -q '^200$'
        #
        # Either way, the exit code is 0 if the status is 200, else non-zero.
        #
        cmd = r"test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:9007) = 200"
        ssh_result = instance.exec(cmd)

        if ssh_result.exit_code == 0:
            print("[demo] [bold green]Webserver is up![/bold green]")
            return

        time.sleep(2)

    raise TimeoutError("Webserver did not become available within the timeout period.")


def main():
    client = MorphCloudClient()

    # Retrieve a base snapshot (for example, an Ubuntu image snapshot).
    # base_snapshot = client.snapshots.get("snapshot_sx4g8yhr")
    # base_snapshot = client.snapshots.get("snapshot_fjmhali7")
    # base_snapshot = client.snapshots.get("snapshot_zo8cptbg")
    base_snapshot = client.snapshots.get("snapshot_zfv9az4v")
    Snapshot.__bases__ = (SnapshotAIMixin,) + Snapshot.__bases__

    # --- First chain: Build a series of setup commands.
    snap1 = (
        base_snapshot.setup("apt-get update && echo 'hello world!'")
        .setup("echo 'hi' && apt-get install -y python3-pip")  # cached
        .setup("apt-get install -y python3.11-venv")  # cached
        .ai_exec(
            "create a python3.11 virtual env at /root/morphenv and automatically source it in ~/.bashrc"
        )
        .setup("pip install uvicorn flask black")
        .setup("echo 'Hello, world' > /hello.txt")
    )  # this returns a snapshot
    print(f"[demo] Final snapshot ID after first chain: {snap1.id}")
    # exit()
    # --- Second chain: Repeat the same commands; these should hit the cache.
    # exit()

    snap2 = (
        base_snapshot.setup("apt-get update && echo 'hello world!'")
        .setup("apt-get install -y python3-pip")  # cached
        .setup("apt-get install -y python3.11-venv")  # cached
        .ai_exec(
            "create a python3.11 virtual env at /root/morphenv and automatically source it in ~/.bashrc"
        )
        .setup("pip install uvicorn flask")
        .setup("echo 'Hello, world' > /hello.txt")
    )

    print(f"[demo] Final snapshot ID after second chain: {snap2.id}")
    print(
        "Observe: If caching works, the snapshot IDs should be identical to the first chain."
    )

    # --- Third chain: Change an early command to force a rebuild from that step onward.
    snap3 = (
        base_snapshot.setup("apt-get update && echo 'hello world!'")
        .setup("apt-get install -y python3-pip")  # cached
        .setup("apt-get install -y python3.11-venv")  # cached
        .ai_exec(
            "create a python3.11 virtual env at /root/morphenv and automatically source it in ~/.bashrc"
        )
        .setup("pip install flask uvicorn isort")
        .setup("echo 'Hello, world' > /hello.txt")
    )
    print(f"[demo] Final snapshot ID after third chain: {snap3.id}")
    print("Observe: Changing an early command yields a different snapshot.")

    # --- Fourth chain: Use _cache_effect with verify_webserver_setup.
    # This effect sets up a FastAPI webserver on port 9007 and waits until it responds.
    # snap_webserver = snap3._cache_effect(verify_webserver_setup)
    snap_webserver = snap3.ai_exec(
        "set up a fastapi hello world server on port 9007 as a systemd service",
        validation_command=r"test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:9007) = 200",
    )
    print(f"[demo] Final snapshot ID after webserver setup chain: {snap_webserver.id}")
    print(
        "Observe: Running the webserver setup should cache the snapshot; subsequent calls will re-use it."
    )

    # def tasker_callback(instance):
    #     return functools.partial(
    #         dummy_tasker_callback2,
    #         instruction="Set up the docs and modify the getting started guide to say 'yeehaw'",
    #     )(instance)

    # snap_tasker = snap3._cache_effect(tasker_callback)

    # print("final tasker snapshot id: ", snap_tasker.id)

    # # Then in your code
    # snap_with_nginx = snap3.ai_exec(
    #     "set up nginx as a reverse proxy for the FastAPI app on port 9007",
    #     validation_command="curl -s -o /dev/null -w '%{http_code}' http://localhost:80 | grep -q '^200$'"
    # ).ai_exec("install a remote desktop using tigerVNC and noVNC running on port 6080 using XFCE. take a screenshot of it to verify")
    # .ai_exec("MAKE SURE THE TESTS PASS")


def make_cloud_dev_env(base_snapshot, github_url):
    snap = CLIENT.snapshots.get(base_snapshot).setup(
        f"git clone {github_url}"
    )  # + whatever setup you want

    return CLIENT.instances.start(snap)


# def demo_ai_exec():

#     # # Or without validation, just running the AI agent instruction
#     # snap_with_config = snap_with_nginx.ai_exec(
#     #     "create a config file at /etc/myapp/config.json with basic settings"
#     # )


if __name__ == "__main__":
    main()
