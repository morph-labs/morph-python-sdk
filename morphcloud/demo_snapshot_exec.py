#!/usr/bin/env python3
"""
demo_snapshot_setup.py

Demonstrates Morph Cloud snapshot chaining, caching, and AI‑assisted provisioning.
Run with:
    python demo_snapshot_setup.py
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Callable, Dict, Optional

from rich import print

from morphcloud.api import Instance, MorphCloudClient, Snapshot

# --------------------------------------------------------------------------- #
# Snapshot helpers                                                            #
# --------------------------------------------------------------------------- #


def get_initial_snapshot(
    name: str,
    client: MorphCloudClient,
    vcpus: int,
    memory: int,
    disk_size: int,
    image_id: str,
) -> Snapshot:
    """
    Get or create an initial snapshot with the given specs, using a metadata-based cache.
    """
    # Calculate a hash from all input parameters to use as cache key
    hash_input = f"{name}:{vcpus}:{memory}:{disk_size}:{image_id}"
    initial_snapshot_hash = hashlib.sha256(hash_input.encode()).hexdigest()

    # Look for existing snapshot
    existing_snapshots = client.snapshots.list(
        metadata={"initial_snapshot_hash": initial_snapshot_hash}
    )

    if existing_snapshots:
        print(f"Found existing initial snapshot with hash {initial_snapshot_hash}")
        return existing_snapshots[0]

    # Create new snapshot
    print(f"Creating new initial snapshot with hash {initial_snapshot_hash}")
    new_snapshot = client.snapshots.create(
        image_id=image_id,
        vcpus=vcpus,
        memory=memory,
        disk_size=disk_size,
        metadata={"initial_snapshot_hash": initial_snapshot_hash},
    )

    return new_snapshot


class SnapshotAIMixin:
    """Adds AI‑assisted provisioning helpers to :class:`morphcloud.api.Snapshot`."""

    def ai_exec(
        self,
        instruction: str,
        validation_command: Optional[str] = None,
        *,
        timeout: int = 180,
        poll_interval: int = 2,
    ) -> "Snapshot":
        """Execute *instruction* via MorphAgent and optionally validate the result.

        Parameters
        ----------
        instruction:
            Natural‑language instruction for the agent.
        validation_command:
            Shell command whose **exit code** must be *0* once the
            instruction is fulfilled. Validation is skipped when *None*.
        timeout:
            Seconds to wait for *validation_command* to succeed.
        poll_interval:
            Seconds between validation checks.
        """

        def _ai_exec_effect(
            instance, instruction, validation_command, timeout, poll_interval
        ):
            """Inner function executed inside Morph Cloud effect caching."""
            from rich import \
                print as rprint  # local import, avoids bleeding globals
            from swe_standalone import MorphAgent

            agent = MorphAgent.from_instance(instance)
            start = time.time()

            asyncio.run(agent.run(instruction))

            if validation_command is None:
                rprint(f"[ai_exec] [green]\N{CHECK MARK} {instruction}[/green]")
                return

            while time.time() - start < timeout:
                if instance.exec(validation_command).exit_code == 0:
                    rprint(
                        f"[ai_exec] [green]\N{CHECK MARK} validated {instruction}[/green]"
                    )
                    return
                time.sleep(poll_interval)

            raise TimeoutError(
                f"'{instruction}' failed validation within {timeout}s using "
                f"command: {validation_command!r}"
            )

        return self._cache_effect(
            _ai_exec_effect,
            instruction=instruction,
            validation_command=validation_command,
            timeout=timeout,
            poll_interval=poll_interval,
        )


# --------------------------------------------------------------------------- #
# Utility callbacks                                                           #
# --------------------------------------------------------------------------- #


def dummy_tasker_callback(instance):
    """Gather a line of input from the user and write it to the VM."""
    user_input = input("Enter modification to be made to the VM: ")

    result = instance.exec(f"echo '{user_input}' > /tmp/tasker_input.txt")
    if result.exit_code == 0:
        print("[tasker] input written to /tmp/tasker_input.txt")
    else:
        print(f"[tasker] [red]failed to write: {result.stderr}[/red]")
    return user_input


def dummy_tasker_callback2(instance, instruction: str):
    """Show *instruction*, open the desktop service, and wait for user sign‑off."""
    from webbrowser import open as open_browser

    print(f"\n[bold yellow]INSTRUCTION:[/bold yellow] {instruction}")
    _wait_for_keypress("Press any key to open the desktop...")

    service = _get_desktop_service(instance)
    print(f"[blue]Opening desktop at {service.url}[/blue]")
    open_browser(service.url)

    _wait_for_keypress("Make your changes, then press any key to continue…")
    print("[green]\N{CHECK MARK} User sign‑off[/green]")


def _get_desktop_service(instance):
    for service in instance.networking.http_services:
        if service.name == "desktop":
            return service
    raise RuntimeError("Desktop service not registered for this instance")


def _wait_for_keypress(prompt: str = "Press any key to continue…") -> None:
    print(prompt)
    try:  # Windows
        import msvcrt

        msvcrt.getch()
    except ImportError:  # Unix
        import sys
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


# --------------------------------------------------------------------------- #
# Demo effects                                                                #
# --------------------------------------------------------------------------- #


def verify_webserver_setup(instance):
    """Provision a FastAPI service on port *9007* and wait until it is healthy."""
    from swe_standalone import MorphAgent

    agent = MorphAgent.from_instance(instance)
    deadline = time.time() + 180

    while time.time() < deadline:
        asyncio.run(
            agent.run(
                "set up a fastapi hello world server listening on port 9007 as a systemd service"
            )
        )

        check = (
            "test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:9007) = 200"
        )
        if instance.exec(check).exit_code == 0:
            print("[demo] [green]Webserver is up![/green]")
            return
        time.sleep(2)

    raise TimeoutError("Webserver did not become available in time.")


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #


def main() -> None:
    client = MorphCloudClient()

    # base_snapshot = client.snapshots.get("snapshot_zfv9az4v")
    base_snapshot = get_initial_snapshot(
        "morphagent-base-2x4x4",
        client=client,
        vcpus=2,
        memory=4096,
        disk_size=4096,
        image_id="morphvm-minimal",
    )
    Snapshot.__bases__ = (SnapshotAIMixin,) + Snapshot.__bases__

    # # First chain ------------------------------------------------------------ #
    # snap1 = (
    #     base_snapshot.setup("apt-get update && echo 'hello world!'")
    #     .setup("echo 'hi' && apt-get install -y python3-pip")
    #     .setup("apt-get install -y python3.11-venv")
    #     .ai_exec(
    #         "create a python3.11 virtual env at /root/morphenv and automatically source it in ~/.bashrc"
    #     )
    #     .setup("pip install uvicorn flask black")
    #     .setup("echo 'Hello, world' > /hello.txt")
    # )
    # print(f"[demo] snapshot after first chain: {snap1.id}")

    # # Second chain (cache hit) ---------------------------------------------- #
    # snap2 = (
    #     base_snapshot.setup("apt-get update && echo 'hello world!'")
    #     .setup("apt-get install -y python3-pip")
    #     .setup("apt-get install -y python3.11-venv")
    #     .ai_exec(
    #         "create a python3.11 virtual env at /root/morphenv and automatically source it in ~/.bashrc"
    #     )
    #     .setup("pip install uvicorn flask")
    #     .setup("echo 'Hello, world' > /hello.txt")
    # )
    # print(f"[demo] snapshot after second chain: {snap2.id}  (should match first)")

    # Third chain (cache miss) ---------------------------------------------- #
    snap3 = (
        base_snapshot.setup("apt-get update && echo 'hello world!'")
        .setup("apt-get install -y python3-pip")
        .setup("apt-get install -y python3.11-venv")
        .ai_exec(
            "create a python3.11 virtual env at /root/morphenv and automatically source it in ~/.bashrc"
        )
        .setup("pip install flask uvicorn isort")
        .setup("echo 'Hello hello world' > /hello.txt")
    )
    print(f"[demo] snapshot after third chain: {snap3.id}  (different)")

    # Fourth chain: provision webserver ------------------------------------- #
    snap_webserver = snap3.ai_exec(
        "please (1) restart the chronyd service and (2) set up a fastapi hello world server on port 9007 as a systemd service.",
        validation_command=(
            "test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:9007) = 200"
        ),
    )
    print(f"[demo] snapshot after webserver chain: {snap_webserver.id}")
    # snap_gradio = snap_webserver.ai_exec("please set up a hello world gradio app and ensure that it's working on port 9008 as a systemd service")
    # print(f"[demo] snapshot after webserver chain: {snap_gradio.id}")


# --------------------------------------------------------------------------- #
# Convenience helper                                                          #
# --------------------------------------------------------------------------- #


def make_cloud_dev_env(base_snapshot_id: str, github_url: str):
    """Spin up an instance cloned from *base_snapshot_id* with a repository checked out."""
    client = MorphCloudClient()
    snap = client.snapshots.get(base_snapshot_id).setup(f"git clone {github_url}")
    return client.instances.start(snap)


if __name__ == "__main__":
    main()
