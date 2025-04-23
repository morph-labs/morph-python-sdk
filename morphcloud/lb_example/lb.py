import asyncio
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from morphcloud.api import ApiError, InstanceStatus, MorphCloudClient


# ------------------------------------------------------------------------------
# DATA MODELS
# ------------------------------------------------------------------------------
class PayloadRequest(BaseModel):
    # Define the structure of the incoming payload.
    data: dict


class EphemeralResponse(BaseModel):
    message: str
    output: str


class HealthResponse(BaseModel):
    status: str


# ------------------------------------------------------------------------------
# CONFIGURATION & GLOBALS
# ------------------------------------------------------------------------------
API_KEY = os.environ.get("MORPH_API_KEY", "YOUR_MORPH_API_KEY")
BASE_URL = os.environ.get("MORPH_BASE_URL", "https://cloud.morph.so/api")
SNAPSHOT_ID = "snapshot_d44ylz4a"  # Fixed snapshot to rehydrate for each request.
MAX_CONCURRENT_INSTANCES = 5  # Maximum concurrent ephemeral instances.

# Global Morph client and asyncio semaphore for limiting concurrency.
morph_client = MorphCloudClient(api_key=API_KEY, base_url=BASE_URL)
instance_semaphore = asyncio.Semaphore(MAX_CONCURRENT_INSTANCES)


# ------------------------------------------------------------------------------
# GENERIC FORWARDING HANDLER (HOOKS FOR OVERRIDING)
# ------------------------------------------------------------------------------
class BaseForwarder:
    async def get_service_url(self, instance) -> str:
        """
        Hook to obtain the designated HTTP service URL.
        Since we assume the HTTP service is already exposed on the snapshot,
        we simply read the service URL from instance.networking.http_services.
        Override this method if your service naming or lookup differs.
        """
        # Optionally, refresh instance data here if needed:
        # await instance._refresh_async()
        for service in instance.networking.http_services:
            if service.name == "hello-world":
                return service.url
        raise Exception("HTTP service 'app' not found in instance networking.")

    async def forward_payload(self, service_url: str, payload: dict) -> str:
        """
        Hook to forward the payload to the designated HTTP service.
        Default: issues an async POST with the JSON payload.
        Override this method for custom forwarding or error handling.
        """
        async with httpx.AsyncClient() as client:
            response = await client.post(service_url, json=payload)
            response.raise_for_status()
            return response.text

    async def handle(self, payload: dict) -> str:
        """
        Implements the complete lifecycle:
          1. Spin up an ephemeral instance from the fixed snapshot.
          2. Wait until it is ready.
          3. Look up the pre-exposed HTTP service URL.
          4. Forward the incoming payload to that service.
          5. Return the service's output.
          6. Always stop the instance.
        """
        try:
            instance = await morph_client.instances.astart(SNAPSHOT_ID)
        except ApiError as e:
            raise Exception(
                f"Failed to start instance from snapshot {SNAPSHOT_ID}: {e}"
            )

        try:
            # Wait asynchronously until the instance is ready (timeout after 300s)
            await instance.await_until_ready(timeout=300)
            if instance.status != InstanceStatus.READY:
                raise Exception(
                    f"Instance {instance.id} is not ready (status={instance.status})"
                )
            service_url = await self.get_service_url(instance)
            result = await self.forward_payload(service_url, payload)
            return result
        finally:
            try:
                await instance.astop()
            except Exception as stop_err:
                logging.warning(f"Failed to stop instance {instance.id}: {stop_err}")


# ------------------------------------------------------------------------------
# FASTAPI APPLICATION & ENDPOINTS
# ------------------------------------------------------------------------------
app = FastAPI()


@app.get("/healthz", response_model=HealthResponse)
async def healthz():
    """Health check endpoint."""
    return HealthResponse(status="OK")


@app.post("/process", response_model=EphemeralResponse)
async def process_endpoint(request: PayloadRequest):
    """
    Process endpoint that accepts a JSON payload, then forwards it to the
    pre-exposed HTTP service on an ephemeral Morph instance.

    The endpoint:
      1. Acquires an asyncio semaphore slot to limit concurrency.
      2. Spins up an ephemeral instance from the fixed snapshot.
      3. Looks up the HTTP service URL (assuming it's already exposed).
      4. Forwards the payload to that service.
      5. Returns the output from the service.

    Errors during instance lifecycle or payload forwarding are caught and
    result in an appropriate HTTP error response.
    """
    try:
        async with instance_semaphore:
            forwarder = BaseForwarder()  # Override this class for custom behavior.
            output = await forwarder.handle(request.data)
            return EphemeralResponse(
                message="Payload forwarded successfully", output=output
            )
    except Exception as e:
        error_message = str(e).lower()
        # Return 503 if errors seem related to resource constraints.
        if "resource" in error_message:
            raise HTTPException(status_code=503, detail=f"Resource limit reached: {e}")
        else:
            raise HTTPException(
                status_code=500, detail=f"Error processing request: {e}"
            )


# ------------------------------------------------------------------------------
# ENTRY POINT FOR RUNNING THE APPLICATION
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    # Read port from LB_PORT environment variable; default to 8080 if not set.
    port = int(os.environ.get("LB_PORT", "8080"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
