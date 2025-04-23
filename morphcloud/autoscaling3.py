import asyncio
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Request:
    # Represents a single incoming request.
    # 'id' uniquely identifies the request.
    # 'payload' holds any user data or parameters for processing.
    id: int
    payload: Dict[str, Any]


@dataclass
class Response:
    # Represents a response to a processed request.
    # 'request_id' ties back to the Request.
    # 'status' indicates success/failure.
    # 'result' can carry additional data.
    request_id: int
    status: str
    result: Optional[Any] = None


class Worker:
    """
    A Worker processes individual requests asynchronously.
    We keep track of how many requests are currently active
    (active_requests) to enable a least-connections strategy.
    """

    def __init__(self, worker_id: int, responses: asyncio.Queue):
        # Unique identifier for this worker.
        self.worker_id = worker_id
        # Tracks how many requests this worker is currently processing.
        self.active_requests = 0
        # Shared queue where workers put their completed responses.
        self.responses = responses

    async def process_request(self, req: Request):
        # Increment active_requests count so that the autoscaler/dispatcher
        # sees that this worker is busy.
        self.active_requests += 1
        try:
            print(f"Worker {self.worker_id}: processing Request {req.id}")
            # Simulate some processing with a random delay to reflect
            # variable workloads.
            await asyncio.sleep(random.uniform(0.3, 1.0))
            # Create a response object capturing our result.
            response = Response(
                request_id=req.id, status="success", result={"echo": req.payload}
            )
            # Put the completed response into the shared queue.
            await self.responses.put(response)
            print(f"Worker {self.worker_id}: finished Request {req.id}")
        finally:
            # No matter what happens, decrement the active request count
            # so that other logic knows we've freed up.
            self.active_requests -= 1


class AutoScaler:
    """
    The AutoScaler dynamically manages a pool of Worker objects.
    Each incoming request spawns a separate async task that determines
    which worker (the one with the least active requests) will handle it.

    For scenarios with high request pressure:
      - We frequently spawn new async tasks (via submit_request) that pick a worker.
      - The scale_loop periodically looks at how many requests are in-flight (total_active_requests)
        and adjusts the number of workers accordingly, respecting min/max limits.
    """

    def __init__(self, min_workers: int = 2, max_workers: int = 10):
        # Bound the number of workers between min_workers and max_workers.
        self.min_workers = min_workers
        self.max_workers = max_workers
        # Holds the active Worker objects.
        self.workers: List[Worker] = []
        # Responses from all workers land here.
        self.responses = asyncio.Queue()
        # Event used to signal that we want to stop everything.
        self.stop_event = asyncio.Event()

    def total_active_requests(self) -> int:
        # Sum up all the currently active requests on each worker.
        # In periods of high load, this number can spike,
        # prompting the autoscaler to add workers.
        return sum(w.active_requests for w in self.workers)

    async def start_workers(self, count: int) -> None:
        # Spawns 'count' new workers and appends them to self.workers.
        for _ in range(count):
            w = Worker(worker_id=len(self.workers), responses=self.responses)
            self.workers.append(w)
            print(f"AutoScaler: Worker {w.worker_id} spawned.")

    def remove_idle_worker(self) -> bool:
        """
        Removes a single worker that has zero active requests.
        This helps scale back down when load subsides.
        Returns True if a worker was successfully removed, otherwise False.
        """
        for i, w in enumerate(self.workers):
            # We only remove workers who aren't busy.
            if w.active_requests == 0:
                removed_worker = self.workers.pop(i)
                print(f"AutoScaler: Worker {removed_worker.worker_id} removed.")
                return True
        return False

    async def scale_loop(self):
        """
        Runs in an infinite loop (until stop_event is set), checking the number
        of total active requests and adjusting worker count.

        In a high-load scenario, each iteration sees if total_active_requests
        is growing, then spawns new workers if needed, or tries to remove idle
        workers if load is dropping.
        """
        while not self.stop_event.is_set():
            # Gather current total active requests.
            total_requests = self.total_active_requests()
            # Current worker count.
            current_workers = len(self.workers)

            # A simple heuristic:
            # desired_workers = half of total_requests, clamped within [min_workers, max_workers].
            desired_workers = min(
                max(self.min_workers, (total_requests + 1) // 2), self.max_workers
            )

            # If we need more workers, spawn them.
            if desired_workers > current_workers:
                to_add = desired_workers - current_workers
                print(f"AutoScaler: scaling up by {to_add} workers.")
                await self.start_workers(to_add)
            # If we have more workers than desired, remove them.
            elif desired_workers < current_workers:
                to_remove = current_workers - desired_workers
                print(f"AutoScaler: scaling down by {to_remove} workers.")
                for _ in range(to_remove):
                    removed = self.remove_idle_worker()
                    # If we can't remove an idle worker,
                    # we break to avoid forcibly removing busy ones.
                    if not removed:
                        break

            # Wait a bit before the next check.
            await asyncio.sleep(1)

    async def dispatch_request(self, payload: Dict[str, Any]):
        """
        This method picks the worker that currently has the fewest active requests
        (least connections) and assigns the incoming request to it.

        If there are no workers, we just log a message. In practice, we might queue
        the request or attempt to spawn new workers right away.
        """
        if not self.workers:
            print("No workers available to handle request!")
            return

        # Create a new Request object with a random ID.
        request_id = random.randint(1000, 9999)
        req = Request(id=request_id, payload=payload)

        # Pick the worker with the fewest active_requests.
        chosen_worker = min(self.workers, key=lambda w: w.active_requests)
        print(f"Dispatching Request {request_id} to Worker {chosen_worker.worker_id}")

        # Let the chosen worker process the request.
        # This call will yield back to the event loop whenever it awaits,
        # letting other tasks run in parallel.
        await chosen_worker.process_request(req)

    async def submit_request(self, payload: Dict[str, Any]) -> None:
        """
        Each new request spawns a separate async task that runs 'dispatch_request'.

        In a scenario with significant request pressure, many such tasks may be
        created in quick succession, each one potentially choosing a different worker.
        """
        asyncio.create_task(self.dispatch_request(payload))

    async def stop(self):
        # Signal the autoscaler loop to end.
        self.stop_event.set()
        # Give a brief window to let ongoing tasks finish.
        await asyncio.sleep(2)


async def main():
    # Create an AutoScaler with initial bounds on worker counts.
    scaler = AutoScaler(min_workers=2, max_workers=6)

    # Start the minimum number of workers so we can handle requests.
    await scaler.start_workers(scaler.min_workers)

    # Start the autoscaler logic in a background task.
    asyncio.create_task(scaler.scale_loop())

    # In a scenario with heavy load, we'll be pushing many requests quickly.
    # For demonstration, we'll submit 20 requests with small delays.
    for i in range(20):
        await scaler.submit_request({"data": f"request_payload_{i}"})
        await asyncio.sleep(random.uniform(0.1, 0.3))

    # Let the system continue processing for a while.
    # With a large number of requests, you might see the autoscaler ramp up.
    await asyncio.sleep(10)

    # Stop the autoscaler and allow workers to wind down.
    await scaler.stop()

    # Collect all responses from the shared queue.
    responses = []
    while not scaler.responses.empty():
        resp = await scaler.responses.get()
        responses.append(resp)
        scaler.responses.task_done()

    print("All responses:")
    for r in responses:
        print(r)


if __name__ == "__main__":
    # Run the main entrypoint.
    asyncio.run(main())
