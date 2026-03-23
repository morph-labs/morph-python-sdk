from __future__ import annotations

import os

import pytest
import pytest_asyncio

from morphcloud.api import MorphCloudClient


def _env_flag(name: str) -> bool:
    value = os.environ.get(name, "")
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """
    Integration tests are opt-in.

    Running this suite can be slow and requires a valid Morph API key. To run:
      MORPH_RUN_INTEGRATION_TESTS=1 pytest tests/integration
    """

    if _env_flag("MORPH_RUN_INTEGRATION_TESTS"):
        return

    skip_marker = pytest.mark.skip(
        reason="Integration tests are opt-in; set MORPH_RUN_INTEGRATION_TESTS=1"
    )
    for item in items:
        if item.nodeid.startswith("tests/integration/"):
            item.add_marker(skip_marker)


@pytest.fixture
def api_key() -> str:
    key = os.environ.get("MORPH_API_KEY")
    if not key:
        pytest.skip("MORPH_API_KEY environment variable must be set for integration tests")
    return key


@pytest.fixture
def base_url() -> str | None:
    return os.environ.get("MORPH_BASE_URL") or None


@pytest_asyncio.fixture
async def client(api_key: str, base_url: str | None) -> MorphCloudClient:
    return MorphCloudClient(api_key=api_key, base_url=base_url)


@pytest_asyncio.fixture
async def base_image(client: MorphCloudClient):
    images = await client.images.alist()
    if not images:
        pytest.skip("No images available for integration tests")
    return next((img for img in images if "ubuntu" in img.id.lower()), images[0])
