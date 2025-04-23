import asyncio
import logging
import os
import random
import time
import traceback
from typing import Dict, List, Optional, Set

import click
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Import the Morph Cloud client
from morphcloud.api import (Instance, InstanceStatus, MorphCloudClient,
                            SnapshotAPI)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("morph-load-balancer")


# Load balancer configuration
class LoadBalancerConfig(BaseModel):
    snapshot_id: str
    min_instances: int = 1
    max_instances: int = 10
    num_requests_per_instance: int = 10
    instance_timeout: int = 300  # seconds
    check_interval: int = 10  # seconds to wait between autoscaling checks
    http_service_name: str = "app"  # The name of the HTTP service exposed by instances
    http_port: int = 8000  # The port where the HTTP service is running
    worker_startup_timeout: int = 300  # Maximum time to wait for a worker to start
    request_timeout: int = 60  # Maximum time for a request to be processed

    def dict(self):
        """Convert to a dict for easier serialization"""
        return {
            "snapshot_id": self.snapshot_id,
            "min_instances": self.min_instances,
            "max_instances": self.max_instances,
            "num_requests_per_instance": self.num_requests_per_instance,
            "instance_timeout": self.instance_timeout,
            "check_interval": self.check_interval,
            "http_service_name": self.http_service_name,
            "http_port": self.http_port,
            "worker_startup_timeout": self.worker_startup_timeout,
            "request_timeout": self.request_timeout,
        }


class WorkerInstance:
    """Represents a worker instance in the pool"""

    def __init__(self, instance: Instance, service_url: str):
        self.instance = instance
        self.service_url = service_url
        self.request_count = 0
        self.active_requests = 0
        self.last_activity = time.time()
        self.is_ready = True
        self._request_lock = asyncio.Lock()  # Lock for request counter modifications

    def mark_active(self):
        """Mark this instance as having recent activity"""
        self.last_activity = time.time()

    async def proxy_request(self, request: Request) -> Response:
        """Proxy an incoming request to this worker instance"""
        async with self._request_lock:
            self.active_requests += 1
            self.request_count += 1
            self.mark_active()

        # Get the request method and URL
        method = request.method
        url = f"{self.service_url}{request.url.path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"

        # Get the request headers, excluding host
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}

        # Get the request body
        body = await request.body()

        try:
            # Create an async client for the request with explicit timeout and limits
            timeout = httpx.Timeout(60.0)  # Use a fixed timeout for now
            async with httpx.AsyncClient(timeout=timeout) as client:
                # Make the request to the worker
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                )

                # Create a FastAPI response from the httpx response
                return StreamingResponse(
                    content=response.aiter_bytes(),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                )
        except httpx.TimeoutException:
            logger.warning(f"Request to worker {self.instance.id} timed out")
            return Response(content="Worker request timed out", status_code=504)
        except Exception as e:
            logger.error(
                f"Error proxying request to {self.instance.id}: {traceback.format_exc()}"
            )
            return Response(content="Error communicating with worker", status_code=502)
        finally:
            # Ensure we always decrement active_requests and mark activity again
            # This is critical - we mark activity when the request completes
            # so idle detection works properly
            async with self._request_lock:
                self.active_requests -= 1
                self.mark_active()  # Mark active again when request completes


class LoadBalancer:
    def __init__(self, config: LoadBalancerConfig, morph_client: MorphCloudClient):
        self.config = config
        self.morph_client = morph_client
        self.workers: Dict[str, WorkerInstance] = {}
        self.pending_instances: Set[str] = set()
        self.app = FastAPI()
        self.setup_routes()
        self.total_requests = 0
        self.shutdown_event = asyncio.Event()
        self.snapshots_api = morph_client.snapshots
        self._workers_lock = asyncio.Lock()  # Lock for worker collection modifications
        self._pending_lock = asyncio.Lock()  # Lock for pending_instances modifications
        self._request_count_lock = asyncio.Lock()  # Lock for total_requests

        # Track scaling operations
        self.last_scale_up_time = time.time()

    def setup_routes(self):
        """Set up the FastAPI routes"""

        @self.app.get("/{path:path}")
        @self.app.post("/{path:path}")
        @self.app.put("/{path:path}")
        @self.app.delete("/{path:path}")
        @self.app.patch("/{path:path}")
        @self.app.head("/{path:path}")
        @self.app.options("/{path:path}")
        async def catch_all(request: Request, path: str):
            return await self.handle_request(request)

        @self.app.get("/lb/status")
        async def load_balancer_status():
            """Return status information about the load balancer"""
            active_workers = len(self.workers)
            pending_workers = len(self.pending_instances)

            worker_stats = []
            for worker_id, worker in self.workers.items():
                worker_stats.append(
                    {
                        "id": worker_id,
                        "request_count": worker.request_count,
                        "active_requests": worker.active_requests,
                        "idle_time": time.time() - worker.last_activity,
                        "url": worker.service_url,
                    }
                )

            return {
                "active_workers": active_workers,
                "pending_workers": pending_workers,
                "total_requests": self.total_requests,
                "last_scale_up": time.time() - self.last_scale_up_time,
                "config": self.config.dict(),
                "workers": worker_stats,
            }

    async def handle_request(self, request: Request):
        """Handle an incoming request by routing it to an appropriate worker"""
        async with self._request_count_lock:
            self.total_requests += 1

        # Use asyncio.wait_for to avoid waiting indefinitely for workers
        try:
            await asyncio.wait_for(self._wait_for_workers(), timeout=10.0)
        except asyncio.TimeoutError:
            return Response(
                content="Timed out waiting for workers to become available",
                status_code=503,
            )

        # Don't check scaling needs for every request - let the autoscaler handle scaling
        # This prevents request-triggered worker creation which can cause overprovisioning

        # Take a snapshot of available workers to avoid holding the lock during request processing
        async with self._workers_lock:
            available_workers = [w for w in self.workers.values() if w.is_ready]
            if not available_workers:
                return Response(content="All workers are busy", status_code=503)

            # Simple weighted selection - favor workers with fewer active requests
            worker_weights = [1.0 / (1 + w.active_requests) for w in available_workers]
            total_weight = sum(worker_weights)
            if total_weight == 0:  # Avoid division by zero
                normalized_weights = [
                    1.0 / len(available_workers) for _ in available_workers
                ]
            else:
                normalized_weights = [w / total_weight for w in worker_weights]

            selected_worker = random.choices(
                population=available_workers, weights=normalized_weights, k=1
            )[0]

        # Process the request outside any locks
        return await selected_worker.proxy_request(request)

    async def _wait_for_workers(self):
        """Wait until at least one worker is available"""
        while True:
            async with self._workers_lock:
                if self.workers:
                    return
            await asyncio.sleep(0.5)

    async def check_scaling_needs(self):
        """Check if we need to scale up or down based on the current load"""
        # Acquire the data needed under a lock, but do the computation outside
        async with self._workers_lock:
            workers_snapshot = list(self.workers.values())
            active_count = len(workers_snapshot)

        async with self._pending_lock:
            pending_count = len(self.pending_instances)

        total_count = active_count + pending_count

        # Calculate total and average active requests
        total_active_requests = sum(
            worker.active_requests for worker in workers_snapshot
        )
        avg_requests_per_worker = total_active_requests / max(active_count, 1)

        # Scale up if needed - only if both conditions are met:
        # 1. Average requests per worker exceeds threshold
        # 2. There's a meaningful number of total active requests (at least 1 per instance)
        if (
            avg_requests_per_worker >= self.config.num_requests_per_instance
            and total_count < self.config.max_instances
            and total_active_requests >= active_count
        ):  # Ensure at least one request per instance on average

            # Calculate how many new instances to add - scale more conservatively
            needed_instances = max(
                1, total_active_requests // (self.config.num_requests_per_instance * 2)
            )
            target_count = min(
                self.config.max_instances, total_count + needed_instances
            )
            to_add = target_count - total_count

            if to_add > 0:
                logger.info(
                    f"Scaling up: Adding {to_add} instances due to high load (avg {avg_requests_per_worker:.2f} req/worker)"
                )
                # Use a semaphore to limit concurrent instance creation
                # Allow up to half of the required instances, or at least 5
                sem = asyncio.Semaphore(max(5, min(to_add, to_add // 2)))

                async def add_with_semaphore():
                    async with sem:
                        await self.add_worker()

                # Create tasks with semaphore control
                for _ in range(to_add):
                    asyncio.create_task(add_with_semaphore())

                # Update our last scale-up time
                self.last_scale_up_time = time.time()

    async def add_worker(self):
        """Add a new worker instance to the pool"""
        instance = None
        instance_id = None

        try:
            # Start a new instance from the snapshot
            instance = await self.morph_client.instances.astart(self.config.snapshot_id)
            instance_id = instance.id

            # Use locks to safely update our collections
            async with self._pending_lock:
                self.pending_instances.add(instance_id)

            logger.info(
                f"Started new instance {instance_id}, waiting for it to be ready..."
            )

            # Use asyncio.wait_for to enforce a hard timeout
            try:
                await asyncio.wait_for(
                    instance.await_until_ready(),
                    timeout=self.config.worker_startup_timeout,
                )
            except asyncio.TimeoutError:
                logger.error(
                    f"Timeout waiting for instance {instance_id} to become ready (timeout: {self.config.worker_startup_timeout}s)"
                )
                raise

            # Wait briefly to ensure services are up
            await asyncio.sleep(5)

            # Refresh instance to get networking info
            await instance._refresh_async()

            # Find the HTTP service URL
            service_url = None
            for service in instance.networking.http_services:
                if service.name == self.config.http_service_name:
                    service_url = service.url
                    break

            if not service_url:
                # Expose the service if it's not already exposed
                try:
                    await instance.aexpose_http_service(
                        self.config.http_service_name, self.config.http_port
                    )
                    await instance._refresh_async()
                except Exception as e:
                    logger.error(f"Error exposing HTTP service on {instance_id}: {e}")
                    raise

                # Try again to find the service
                for service in instance.networking.http_services:
                    if service.name == self.config.http_service_name:
                        service_url = service.url
                        break

            if not service_url:
                logger.error(
                    f"Failed to find HTTP service {self.config.http_service_name} in instance {instance_id}"
                )
                raise ValueError(f"No HTTP service found for {instance_id}")

            # Create the worker
            worker = WorkerInstance(instance, service_url)

            # Update collections with proper locking
            async with self._workers_lock:
                self.workers[instance_id] = worker

            async with self._pending_lock:
                if instance_id in self.pending_instances:
                    self.pending_instances.remove(instance_id)

            logger.info(f"Added worker {instance_id} with URL {service_url}")

            # Update our last scale-up time
            self.last_scale_up_time = time.time()

        except Exception as e:
            logger.error(f"Error adding worker: {e}")
            # Clean up if needed
            if instance_id:
                async with self._pending_lock:
                    if instance_id in self.pending_instances:
                        self.pending_instances.remove(instance_id)

                # Try to stop the instance if it was created
                if instance:
                    try:
                        await instance.astop()
                        logger.info(f"Cleaned up failed instance {instance_id}")
                    except Exception as stop_error:
                        logger.error(
                            f"Error stopping failed instance {instance_id}: {stop_error}"
                        )
            # Re-raise to signal failure
            raise

    async def remove_worker(self, worker_id: str):
        """Remove a worker from the pool and stop its instance"""
        worker = None

        # Get the worker under a lock
        async with self._workers_lock:
            if worker_id in self.workers:
                worker = self.workers.pop(worker_id)
                logger.info(f"Worker {worker_id} removed from active pool")

        # If found, stop the instance (outside of the lock to prevent deadlocks)
        if worker:
            try:
                await worker.instance.astop()
                logger.info(f"Stopped instance {worker_id}")
            except Exception as e:
                logger.error(f"Error stopping instance {worker_id}: {e}")
        else:
            logger.warning(f"Attempted to remove non-existent worker: {worker_id}")

    async def autoscaler_task(self):
        """Background task to continuously check and adjust the worker pool"""
        logger.info("Starting autoscaler task")

        # Minimum interval between scale-up operations
        scale_up_cooldown = 30  # seconds

        while not self.shutdown_event.is_set():
            try:
                current_time = time.time()

                # Take snapshots of our current state with proper locking
                async with self._workers_lock:
                    workers_snapshot = dict(self.workers)
                    active_count = len(workers_snapshot)

                async with self._pending_lock:
                    pending_count = len(self.pending_instances)

                total_count = active_count + pending_count

                # Ensure minimum instances
                if total_count < self.config.min_instances:
                    to_add = self.config.min_instances - total_count
                    logger.info(
                        f"Scaling up to meet minimum: Adding {to_add} instances"
                    )

                    # Use a semaphore to prevent too many concurrent instance creations
                    sem = asyncio.Semaphore(max(5, min(to_add, to_add // 2)))

                    async def add_with_semaphore():
                        async with sem:
                            try:
                                await self.add_worker()
                            except Exception as e:
                                logger.error(f"Failed to add worker in autoscaler: {e}")

                    tasks = []
                    for _ in range(to_add):
                        tasks.append(asyncio.create_task(add_with_semaphore()))

                    # Don't wait for completion - let them run in the background
                    self.last_scale_up_time = current_time

                # Check for load-based scaling (only if we haven't scaled up recently)
                elapsed_since_last_scale = current_time - self.last_scale_up_time
                if elapsed_since_last_scale >= scale_up_cooldown:
                    # Calculate load metrics
                    total_active_requests = sum(
                        worker.active_requests for worker in workers_snapshot.values()
                    )
                    avg_requests_per_worker = total_active_requests / max(
                        active_count, 1
                    )

                    # Scale up if load exceeds threshold and we have meaningful traffic
                    if (
                        avg_requests_per_worker >= self.config.num_requests_per_instance
                        and total_count < self.config.max_instances
                        and total_active_requests >= active_count
                    ):

                        # Calculate how many new instances to add - scale conservatively
                        needed_instances = max(
                            1,
                            total_active_requests
                            // (self.config.num_requests_per_instance * 2),
                        )
                        target_count = min(
                            self.config.max_instances, total_count + needed_instances
                        )
                        to_add = target_count - total_count

                        if to_add > 0:
                            logger.info(
                                f"Scaling up due to load: Adding {to_add} instances (avg {avg_requests_per_worker:.2f} req/worker)"
                            )

                            # Use a semaphore to limit concurrent instance creation
                            sem = asyncio.Semaphore(max(5, min(to_add, to_add // 2)))

                            async def add_with_semaphore():
                                async with sem:
                                    try:
                                        await self.add_worker()
                                    except Exception as e:
                                        logger.error(
                                            f"Failed to add worker in autoscaler: {e}"
                                        )

                            for _ in range(to_add):
                                asyncio.create_task(add_with_semaphore())

                            # Update the timestamp to prevent rapid scaling
                            self.last_scale_up_time = current_time

                # Check for idle instances to remove
                now = time.time()
                idle_workers = []

                # Identify idle workers using our snapshot (no lock needed)
                for worker_id, worker in workers_snapshot.items():
                    idle_time = now - worker.last_activity

                    # Mark as idle if it's been inactive for too long
                    if idle_time > self.config.instance_timeout:
                        idle_workers.append(worker_id)

                # Only remove idle workers if we're above min_instances
                # And don't remove any if we just scaled up (give new instances time to distribute load)
                if (
                    active_count - len(idle_workers) >= self.config.min_instances
                    and now - self.last_scale_up_time > 60
                ):
                    for worker_id in idle_workers:
                        if worker_id in workers_snapshot:
                            logger.info(
                                f"Removing idle worker {worker_id} (inactive for {now - workers_snapshot[worker_id].last_activity:.1f}s)"
                            )
                            # Process removals one at a time to avoid overwhelming Morph API
                            await self.remove_worker(worker_id)
                            # Small sleep between removals
                            await asyncio.sleep(1)

                # Get updated counts for logging
                async with self._workers_lock:
                    active_count = len(self.workers)

                async with self._pending_lock:
                    pending_count = len(self.pending_instances)

                # Log current state
                logger.info(
                    f"Autoscaler status: {active_count} active workers, {pending_count} pending, {sum(w.active_requests for w in workers_snapshot.values())} active requests"
                )

            except Exception as e:
                logger.error(f"Error in autoscaler task: {e}", exc_info=True)

            # Wait before the next check
            try:
                # Make this cancellable in case of shutdown
                await asyncio.wait_for(
                    asyncio.shield(asyncio.sleep(self.config.check_interval)),
                    timeout=self.config.check_interval + 1,
                )
            except (asyncio.CancelledError, asyncio.TimeoutError):
                # Check if we should exit
                if self.shutdown_event.is_set():
                    break

    async def start(self):
        """Start the load balancer and its background tasks"""
        logger.info("Starting load balancer")

        # Create a specific task for the autoscaler that we can reference
        self.autoscaler_task_handle = asyncio.create_task(
            self.autoscaler_task(), name="autoscaler_task"
        )

        # We'll let the autoscaler handle starting our minimum instances
        # This avoids deadlock risks from starting too many instances simultaneously
        logger.info(
            f"Initial scaling to {self.config.min_instances} instances will be handled by the autoscaler"
        )

    async def shutdown(self):
        """Shutdown the load balancer and clean up resources"""
        logger.info("Shutting down load balancer")

        # Signal all background tasks to stop
        self.shutdown_event.set()

        # Cancel the autoscaler if it's running
        if (
            hasattr(self, "autoscaler_task_handle")
            and not self.autoscaler_task_handle.done()
        ):
            logger.info("Cancelling autoscaler task")
            self.autoscaler_task_handle.cancel()
            try:
                await self.autoscaler_task_handle
            except asyncio.CancelledError:
                pass

        # Get a snapshot of workers to shut down
        workers_to_stop = []
        async with self._workers_lock:
            workers_to_stop = list(self.workers.keys())

        # Stop all worker instances with a timeout to prevent hanging
        if workers_to_stop:
            logger.info(f"Stopping {len(workers_to_stop)} worker instances")

            shutdown_tasks = []
            for worker_id in workers_to_stop:
                # Create a task for each worker removal
                shutdown_tasks.append(
                    asyncio.create_task(
                        asyncio.wait_for(
                            self.remove_worker(worker_id),
                            timeout=30,  # 30 second timeout per worker
                        )
                    )
                )

            # Wait for all workers to be stopped, but with a maximum total time
            try:
                await asyncio.wait_for(
                    asyncio.gather(*shutdown_tasks, return_exceptions=True),
                    timeout=60,  # 60 second total timeout
                )
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for all workers to stop")

        logger.info("Load balancer shutdown complete")


async def run_server(
    load_balancer: LoadBalancer, host: str = "0.0.0.0", port: int = 8000
):
    """Run the FastAPI server"""
    # Create an event to signal cancellation
    should_exit = asyncio.Event()

    # Setup graceful shutdown handler
    def handle_signals():
        should_exit.set()

    # Configure the uvicorn server
    config = uvicorn.Config(
        app=load_balancer.app, host=host, port=port, log_level="info"
    )
    server = uvicorn.Server(config)

    # Override the default signal handlers to use our event
    server.install_signal_handlers = lambda: None

    # Start the load balancer
    await load_balancer.start()

    # Create a task for the server
    server_task = asyncio.create_task(server.serve())

    try:
        # Wait for either the server to exit or our signal
        await asyncio.wait(
            [server_task, asyncio.create_task(should_exit.wait())],
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        # Ensure proper cleanup
        logger.info("Initiating graceful shutdown")
        # First stop accepting new requests
        if not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass

        # Then do our cleanup
        await load_balancer.shutdown()


def start_load_balancer(config: LoadBalancerConfig, port: int = 8000):
    """Start the load balancer with the given configuration"""
    # Create Morph Cloud client
    api_key = os.environ.get("MORPH_API_KEY")
    base_url = os.environ.get("MORPH_BASE_URL")

    if not api_key:
        raise ValueError("MORPH_API_KEY environment variable is required")

    morph_client = MorphCloudClient(api_key=api_key, base_url=base_url)

    # Create and start the load balancer
    load_balancer = LoadBalancer(config, morph_client)

    # Setup an event loop policy that properly handles task cancellation
    asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())

    # Run the server with better exception handling
    try:
        asyncio.run(run_server(load_balancer, port=port))
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down")
    except Exception as e:
        logger.error(f"Error in main event loop: {e}", exc_info=True)


if __name__ == "__main__":
    import click

    @click.command(help="Morph Cloud Load Balancer and Autoscaler")
    @click.option(
        "--snapshot-id", required=True, help="Snapshot ID to use for worker instances"
    )
    @click.option(
        "--min-instances",
        type=int,
        default=1,
        help="Minimum number of instances to maintain",
    )
    @click.option(
        "--max-instances",
        type=int,
        default=10,
        help="Maximum number of instances allowed",
    )
    @click.option(
        "--requests-per-instance",
        type=int,
        default=10,
        help="Number of concurrent requests per instance before scaling up",
    )
    @click.option(
        "--instance-timeout",
        type=int,
        default=300,
        help="Time in seconds before an idle instance is removed",
    )
    @click.option(
        "--check-interval",
        type=int,
        default=10,
        help="Time in seconds between autoscaling checks",
    )
    @click.option(
        "--http-service-name",
        default="app",
        help="Name of the HTTP service exposed by worker instances",
    )
    @click.option(
        "--http-port",
        type=int,
        default=8000,
        help="Port where HTTP service is running on each worker",
    )
    @click.option(
        "--port", type=int, default=8000, help="Port to run the load balancer on"
    )
    @click.option(
        "--worker-startup-timeout",
        type=int,
        default=300,
        help="Maximum seconds to wait for a worker to start",
    )
    @click.option(
        "--request-timeout",
        type=int,
        default=60,
        help="Maximum seconds for a request to be processed",
    )
    def cli(
        snapshot_id,
        min_instances,
        max_instances,
        requests_per_instance,
        instance_timeout,
        check_interval,
        http_service_name,
        http_port,
        port,
        worker_startup_timeout,
        request_timeout,
    ):
        """Run the Morph Cloud Load Balancer"""
        config = LoadBalancerConfig(
            snapshot_id=snapshot_id,
            min_instances=min_instances,
            max_instances=max_instances,
            num_requests_per_instance=requests_per_instance,
            instance_timeout=instance_timeout,
            check_interval=check_interval,
            http_service_name=http_service_name,
            http_port=http_port,
            worker_startup_timeout=worker_startup_timeout,
            request_timeout=request_timeout,
        )

        click.echo(f"Starting load balancer with config: {config}")
        start_load_balancer(config, port=port)

    cli()
