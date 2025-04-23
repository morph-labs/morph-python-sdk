#!/usr/bin/env python3
"""
tuskify_branches_cached.py
---------------------------
Tusk-ify every branch of a GitHub repo using Morph Cloud snapshots with the
built-in `_cache_effect` mechanism.

Snapshot metadata added:

  * tuskify-branch-name  = <branch>
  * tuskify-commit-hash  = <commit SHA>

Designed for cron – incremental and idempotent.
"""

from __future__ import annotations

import os
from typing import Dict

import requests

from morphcloud.api import Instance, MorphCloudClient, Snapshot


# --------------------------------------------------------------------------- #
# --- user‑editable hook ---------------------------------------------------- #
# --------------------------------------------------------------------------- #
def _setup_dev_env(vm: Instance) -> None:
    """
    Provision the VM.  Replace the body with whatever you really need
    (install deps, run tests, etc).  Keep it deterministic!
    """
    vm.exec("echo '🏗️  placeholder setup for branch‑env'")


# --------------------------------------------------------------------------- #
# --- effect function passed to _cache_effect ------------------------------- #
# --------------------------------------------------------------------------- #
def _branch_effect(
    vm: Instance,
    repo_url: str,
    branch: str,
    commit_sha: str,
) -> None:
    """
    Runs inside the live VM only *once* per unique (repo_url, branch, commit_sha)
    thanks to `_cache_effect`.
    """
    # example minimal checkout; customise as needed
    vm.exec(f"git clone --depth 1 --branch {branch} {repo_url} repo || true")
    vm.exec(
        f"cd repo && git fetch --depth 1 origin {commit_sha} && git checkout {commit_sha}"
    )

    # delegate to user hook
    _setup_dev_env(vm)


# --------------------------------------------------------------------------- #
# --- GitHub helpers -------------------------------------------------------- #
# --------------------------------------------------------------------------- #
def _branches(repo: str, token: str | None) -> Dict[str, str]:
    owner, name = repo.split("/", 1)
    hdr = {"Authorization": f"token {token}"} if token else {}
    url = f"https://api.github.com/repos/{owner}/{name}/branches"
    res = requests.get(url, headers=hdr, timeout=20)
    res.raise_for_status()
    return {b["name"]: b["commit"]["sha"] for b in res.json()}


# --------------------------------------------------------------------------- #
# --- main driver ----------------------------------------------------------- #
# --------------------------------------------------------------------------- #
BASE_IMAGE = "morphvm-minimal"
VCPUS = 2
MEMORY_MB = 2048
DISK_MB = 4096
BASE_DIGEST = f"tuskify-base-{VCPUS}-{MEMORY_MB}-{DISK_MB}"  # stable key


def run(repo: str) -> None:
    github_pat = os.getenv("GITHUB_TOKEN")
    branches = _branches(repo, github_pat)

    client = MorphCloudClient()
    base_image = (
        client.images.list()[0]
        if BASE_IMAGE == "first"
        else next(img for img in client.images.list() if img.name == BASE_IMAGE)
    )

    # Create (or fetch) a single thin base snapshot we’ll branch from
    base_snapshot: Snapshot = client.snapshots.create(
        image_id=base_image.id,
        vcpus=VCPUS,
        memory=MEMORY_MB,
        disk_size=DISK_MB,
        digest=BASE_DIGEST,  # server returns existing snapshot if present
    )

    repo_url = f"https://github.com/{repo}.git"

    for branch, sha in branches.items():
        print(f"It's Tuskin' time! ▶️  {branch:20} @ {sha[:7]} ", end="", flush=True)

        # -- cache‑aware provisioning ------------------------------------- #
        prepared: Snapshot = base_snapshot._cache_effect(
            fn=_branch_effect,
            repo_url=repo_url,
            branch=branch,
            commit_sha=sha,
        )

        # -- ensure metadata is attached ---------------------------------- #
        tags = {
            "tuskify-branch-name": branch,
            "tuskify-commit-hash": sha,
        }
        if any(prepared.metadata.get(k) != v for k, v in tags.items()):
            prepared.set_metadata(tags)

        print(f"✅  snapshot {prepared.id}")


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Tuskify all branches (cached)")
    ap.add_argument("repository", help="owner/repo (e.g. morph-labs/morph-python-sdk)")
    args = ap.parse_args()
    run(args.repository)
