#!/usr/bin/env -S uv run
"""
Smoke-test script for Snapshot.abuild.

Usage:
  MORPH_API_KEY=... python3 scripts/abuild_smoke.py
  MORPH_API_KEY=... MORPH_SSH_TOTAL_TIMEOUT_SECS=30 python3 scripts/abuild_smoke.py --no-cleanup
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import os
import re
import sys
import time

import morphcloud
from morphcloud.api import MorphCloudClient, console


async def _pick_base_image(client: MorphCloudClient) -> str:
    images = await client.images.alist()
    if not images:
        raise RuntimeError("No images available in this account.")
    image = next((img for img in images if "ubuntu" in img.id.lower()), images[0])
    return image.id


def _default_base_digest(*, base_image_id: str, vcpus: int, memory: int, disk_size: int) -> str:
    # Keep it stable + reasonably short; only allow safe characters.
    safe_image = re.sub(r"[^A-Za-z0-9_.-]+", "-", base_image_id).strip("-")
    digest = f"abuild_smoke:{safe_image}:{vcpus}vcpu:{memory}mb:{disk_size}mb"
    return digest[:128]


async def main() -> int:
    parser = argparse.ArgumentParser(description="Run a small Snapshot.abuild smoke test.")
    parser.add_argument("--base-url", default=os.environ.get("MORPH_BASE_URL"))
    parser.add_argument("--vcpus", type=int, default=1)
    parser.add_argument("--memory", type=int, default=512)
    parser.add_argument("--disk-size", type=int, default=8192)
    parser.add_argument("--no-cleanup", action="store_true", help="Leave created snapshots behind.")
    parser.add_argument(
        "--base-digest",
        default=os.environ.get("MORPH_ABUILD_BASE_DIGEST"),
        help="Stable digest for the base snapshot (defaults to a value derived from image+resources).",
    )
    parser.add_argument(
        "--delete-base-snapshot",
        action="store_true",
        help="Delete the base snapshot even when using a stable digest.",
    )
    args = parser.parse_args()

    api_key = os.environ.get("MORPH_API_KEY")
    if not api_key:
        console.print("[red]MORPH_API_KEY must be set.[/red]")
        return 2

    console.print(f"[dim]morphcloud.__file__={morphcloud.__file__}[/dim]")
    try:
        console.print(f"[dim]morphcloud version={importlib.metadata.version('morphcloud')}[/dim]")
    except Exception:
        pass

    client = MorphCloudClient(api_key=api_key, base_url=args.base_url)

    run_id = f"abuild_smoke_{int(time.time())}"
    console.print(f"[bold]Run:[/bold] {run_id}")

    base_image_id = await _pick_base_image(client)
    console.print(f"[bold]Base image:[/bold] {base_image_id}")

    base_digest = args.base_digest or _default_base_digest(
        base_image_id=base_image_id,
        vcpus=args.vcpus,
        memory=args.memory,
        disk_size=args.disk_size,
    )
    console.print(f"[bold]Base digest:[/bold] {base_digest}")

    base_snapshot = await client.snapshots.acreate(
        image_id=base_image_id,
        vcpus=args.vcpus,
        memory=args.memory,
        disk_size=args.disk_size,
        digest=base_digest,
    )
    console.print(f"[bold]Base snapshot:[/bold] {base_snapshot.id}")

    # Keep the steps simple + fast. The key is exercising the SSH connect path
    # (including retries/timeouts if the gateway is degraded).
    steps = [
        f"echo '{run_id}: step1'",
        "uname -a",
        "id",
    ]

    final_snapshot = None
    try:
        final_snapshot = await base_snapshot.abuild(steps)
        console.print(f"[bold green]Final snapshot:[/bold green] {final_snapshot.id}")
        return 0
    finally:
        if args.no_cleanup:
            console.print("[yellow]Cleanup skipped (--no-cleanup).[/yellow]")
            return 0

        # Best-effort cleanup: delete per-step snapshots (by digest). Keep the base snapshot by
        # default so repeated runs can reuse it via the stable digest.
        try:
            digests = base_snapshot._compute_all_digests(steps)  # type: ignore[attr-defined]
        except Exception:
            digests = []

        for d in digests:
            try:
                candidates = await client.snapshots.alist(digest=d)
            except Exception:
                continue
            for snap in candidates:
                try:
                    await snap.adelete()
                except Exception:
                    pass

        if args.delete_base_snapshot:
            try:
                await base_snapshot.adelete()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
