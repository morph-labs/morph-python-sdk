from __future__ import annotations

"""load_balancer.py – Async autoscaling load‑balancer for durable workflows on
Morph_Cloud **with extensive structured logging**.

Run ``python -m load_balancer demo --debug`` to watch the balancer in action.
"""

####################################################################################
# Standard library & third‑party imports ###########################################
####################################################################################

import asyncio
import contextlib
import hashlib
import logging
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from morphcloud.api import Instance, MorphCloudClient, Snapshot

####################################################################################
# Logging setup ####################################################################
####################################################################################

### FIX/CHANGE: Removed stray space in log format:
LOG_FMT = "%(asctime)s | %(levelname)-8s | %(name)s: %(message)s"

logging.basicConfig(format=LOG_FMT, level=logging.INFO, force=True)
logger = logging.getLogger("load_balancer")

####################################################################################
# Domain objects ###################################################################
####################################################################################


@dataclass
class WorkflowTask:
    """Unit of work belonging to a durable workflow."""

    workflow_id: str
    payload: Any
    effect_identifier: str  # Used for chainhashing
    needs_snapshot: bool = True


####################################################################################
# Worker abstraction ###############################################################
####################################################################################


class Worker:
    """A thin wrapper around a Morph Cloud instance that executes tasks serially."""

    def __init__(
        self,
        client: MorphCloudClient,
        base_snapshot: Snapshot,
        name: str,
        idle_timeout: float = 60.0,
    ) -> None:
        self._client = client
        self._queue: asyncio.Queue[WorkflowTask] = asyncio.Queue()
        self._instance: Optional[Instance] = None
        self._current_snapshot = base_snapshot
        self.name = name
        self._idle_timeout = idle_timeout
        self._closed = asyncio.Event()
        self._task: Optional[asyncio.Task[None]] = None
        self._logger = logging.getLogger(f"worker.{self.name}")

    # ---------------------------------------------------------------- lifecycle --
    async def start(self) -> None:
        self._logger.info("starting from snapshot %s", self._current_snapshot.id)
        self._instance = await self._client.instances.astart(self._current_snapshot.id)
        await self._instance.await_until_ready()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._logger.info("shutting down")
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._instance:
            await self._instance.astop()
        self._closed.set()

    # ---------------------------------------------------------------- properties --
    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    # ----------------------------------------------------------------  API  -------
    async def enqueue(self, wf_task: WorkflowTask) -> None:
        self._logger.debug("enqueue task %s", wf_task.effect_identifier)
        await self._queue.put(wf_task)

    # --------------------------------------------------------------- main loop ----
    async def _run(self) -> None:
        self._logger.debug("runloop started")
        last_task_time = time.time()
        while True:
            try:
                timeout = max(0, self._idle_timeout - (time.time() - last_task_time))
                wf_task: WorkflowTask = await asyncio.wait_for(
                    self._queue.get(), timeout
                )
            except asyncio.TimeoutError:
                self._logger.info(
                    "idletimeout (%ss) reached, exiting", self._idle_timeout
                )
                break

            try:
                await self._execute(wf_task)
            except Exception as exc:
                self._logger.exception("task failed: %s", exc)
            finally:
                last_task_time = time.time()
                self._queue.task_done()
        self._logger.debug("runloop ended")

    # ------------------------------------------------------------- task execute --
    async def _execute(self, wf_task: WorkflowTask) -> None:
        assert self._instance is not None
        cmd = wf_task.payload if isinstance(wf_task.payload, str) else "echo 'noop'"
        self._logger.debug("exec: %s", cmd)
        resp = await self._instance.aexec(cmd)
        self._logger.debug("→ exit %s", resp.exit_code)
        self._logger.debug("→ %s", resp.stdout)
        if resp.exit_code != 0:
            raise RuntimeError(resp.stderr)

        if wf_task.needs_snapshot:
            await self._snapshot_after_effect(wf_task)

    # ------------------------------------------------------------- snapshotting --
    async def _snapshot_after_effect(self, wf_task: WorkflowTask) -> None:
        parent_digest = self._current_snapshot.digest or self._current_snapshot.id
        digest = Snapshot.compute_chain_hash(parent_digest, wf_task.effect_identifier)
        self._logger.debug("checking cache for digest %s", digest[:10])
        cached = self._client.snapshots.list(digest=digest)
        if cached:
            self._logger.info("cache hit – reuse snapshot %s", cached[0].id)
            self._current_snapshot = cached[0]
            return
        self._logger.info("snapshotting instance → digest %s", digest[:10])
        self._current_snapshot = await self._instance.asnapshot(digest=digest)


####################################################################################
# Rendezvous hashing ###############################################################
####################################################################################


def rendezvous_pick(key: str, worker_names: List[str]) -> str:
    best_score = -1
    best_worker = worker_names[0]
    for w in worker_names:
        score = int(hashlib.md5(f"{key}-{w}".encode()).hexdigest(), 16)
        if score > best_score:
            best_score = score
            best_worker = w
    return best_worker


####################################################################################
# Autoscaling controller ###########################################################
####################################################################################


@dataclass
class AutoscalingPolicy:
    min_workers: int = 1
    max_workers: int = 20
    scale_up_threshold: int = 8  # backlog per worker before scale‑up
    idle_seconds: int = 60  # terminate worker if idle this long **and** surplus


class AutoscalingLoadBalancer:
    """Routes tasks, maintains sticky mapping and scales the fleet."""

    def __init__(
        self,
        client: MorphCloudClient,
        base_snapshot: Snapshot,
        policy: AutoscalingPolicy = AutoscalingPolicy(),
    ) -> None:
        self._client = client
        self._base_snapshot = base_snapshot
        self._policy = policy
        self._workers: Dict[str, Worker] = {}
        self._sticky: Dict[str, str] = {}
        self._id_counter = 0
        self._lock = asyncio.Lock()
        self._maintainer: Optional[asyncio.Task[None]] = None
        self._logger = logging.getLogger("autoscaler")

    # ------------------------------------------------------------ context mgr ----
    async def __aenter__(self):
        await self._ensure_workers(self._policy.min_workers)
        self._maintainer = asyncio.create_task(self._maintain())
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._maintainer:
            self._maintainer.cancel()
        await asyncio.gather(
            *(w.stop() for w in self._workers.values()), return_exceptions=True
        )
        self._logger.info("balancer shut down")

    # -------------------------------------------------------------- public API ----
    async def submit(self, wf_task: WorkflowTask) -> None:
        async with self._lock:  ### Acquire lock to avoid race with _autoscale
            worker_name = self._select_worker(wf_task.workflow_id)
            await self._workers[worker_name].enqueue(wf_task)
            self._logger.debug(
                "queued task %s to %s", wf_task.effect_identifier, worker_name
            )

    # -------------------------------------------------------------- internals ----
    def _select_worker(self, workflow_id: str) -> str:
        if workflow_id in self._sticky and self._sticky[workflow_id] in self._workers:
            return self._sticky[workflow_id]
        chosen = rendezvous_pick(workflow_id, list(self._workers))
        self._sticky[workflow_id] = chosen
        return chosen

    async def _ensure_workers(self, target: int) -> None:
        while len(self._workers) < target:
            name = f"w{self._id_counter}"
            self._id_counter += 1
            w = Worker(
                self._client,
                self._base_snapshot,
                name=name,
                idle_timeout=self._policy.idle_seconds,
            )
            await w.start()
            self._workers[name] = w
            self._logger.info("worker %s started (total=%d)", name, len(self._workers))

    # --------------------------------------------------------- maintenance loop --
    async def _maintain(self) -> None:
        self._logger.debug("maintenance loop started")
        try:
            while True:
                await asyncio.sleep(5)
                async with self._lock:  ### Acquire lock before autoscaling
                    await self._autoscale()
        except asyncio.CancelledError:
            pass

    async def _autoscale(self) -> None:
        backlog = sum(w.queue_size for w in self._workers.values())
        desired = max(
            self._policy.min_workers,
            min(
                self._policy.max_workers,
                (backlog // self._policy.scale_up_threshold) + 1,
            ),
        )
        if desired > len(self._workers):
            self._logger.info("scaling up: backlog=%d → target=%d", backlog, desired)
            await self._ensure_workers(desired)
        elif desired < len(self._workers):
            idle_workers = [w for w in self._workers.values() if w.queue_size == 0]
            excess = len(self._workers) - desired
            for w in idle_workers[:excess]:
                await w.stop()
                self._workers.pop(w.name, None)
                # Clean up sticky references
                self._sticky = {k: v for k, v in self._sticky.items() if v != w.name}
                self._logger.info(
                    "worker %s stopped (total=%d)", w.name, len(self._workers)
                )


####################################################################################
# Demo driver ######################################################################
####################################################################################


async def _demo(debug: bool = False):
    if debug:
        # If you only want the entire script to log at DEBUG, do this:
        logging.getLogger().setLevel(logging.DEBUG)

    client = MorphCloudClient()
    # pick the most recent snapshot as base
    # snapshot = sorted(client.snapshots.list(), key=lambda s: s.created)[-1]
    snapshot = client.snapshots.get("snapshot_k0llwivo")
    logger.info("using base snapshot %s", snapshot.id)

    async with AutoscalingLoadBalancer(client, snapshot) as lb:
        for wf_id in range(32):
            for step in range(5):
                payload = f"echo 'wf{wf_id} step{step}'"
                task = WorkflowTask(
                    workflow_id=str(wf_id),
                    payload=payload,
                    effect_identifier=f"step-{step}",
                    needs_snapshot=(step % 2 == 0),
                )
                await lb.submit(task)

        # Wait until all queues drain
        while any(w.queue_size for w in lb._workers.values()):
            await asyncio.sleep(2)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Durable workflow autoscaler demo")
    parser.add_argument("demo", nargs="?", help="run demo", default=None)
    parser.add_argument("--debug", action="store_true", help="verbose logging")
    args = parser.parse_args()

    if args.demo == "demo":
        asyncio.run(_demo(debug=args.debug))
    else:
        print("Usage: python -m load_balancer demo [--debug]")
