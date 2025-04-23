import asyncio
import hashlib
import hmac
import time
from typing import Any, Callable, Dict, Optional

import fire
from rich import print

from morphcloud.api import Instance, MorphCloudClient, Snapshot


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


def _main():
    client = MorphCloudClient()
    Snapshot.__bases__ = (SnapshotAIMixin,) + Snapshot.__bases__
    base_snapshot = get_initial_snapshot(
        "morphagent-base-2x4x4",
        client=client,
        vcpus=2,
        memory=4096,
        disk_size=4096,
        image_id="morphvm-minimal",
    )
    snapshot = client.snapshots.get("snapshot_790jgwaz")

    # Install dependencies (cached via snapshot.exec -> _cache_effect)
    snapshot = snapshot.exec("apt-get update -y")
    snapshot = snapshot.exec(
        "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl tar git docker.io jq make"
    )

    # ---- NEW: Install Google Cloud CLI ----
    print("Setting up Google Cloud SDK repository...")
    # Add Google Cloud public key keyring
    snapshot = snapshot.setup(
        "curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg"
    )
    # Add the gcloud CLI distribution URI
    snapshot = snapshot.setup(
        'echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list'
    )

    # Update package list again and install gcloud CLI
    print("Installing google-cloud-cli...")
    # Combine update and install to ensure the new source is used
    snapshot = snapshot.setup(
        "apt-get update -y && apt-get install -y google-cloud-cli"
    )
    snapshot = snapshot.ai_exec(
        "please (1) restart the chronyd service and (2) set up a fastapi hello world server on port 9007 as a systemd service.",
        validation_command=(
            "test $(curl -s -o /dev/null -w '%{http_code}' http://localhost:9007) = 200"
        ),
    )
    snapshot = snapshot.ai_exec("install a SQLite database and test it")
    print(f"[demo] snapshot after webserver chain: {snapshot.id}")
    print("Google Cloud CLI installed.")
    print(f"{snapshot.id=}")


if __name__ == "__main__":
    fire.Fire(_main)
