import asyncio

from morphcloud._http_transport import ShardedAsyncTransport, ShardedTransport
from morphcloud.api import MorphCloudClient
from morphcloud.devbox.client import AsyncDevboxClient, DevboxClient


def _make_client(monkeypatch, shards=None):
    monkeypatch.setenv("MORPH_API_KEY", "test-key")
    if shards is None:
        monkeypatch.delenv("MORPH_HTTP_TRANSPORT_SHARDS", raising=False)
    else:
        monkeypatch.setenv("MORPH_HTTP_TRANSPORT_SHARDS", str(shards))
    monkeypatch.setattr(MorphCloudClient, "_load_sdk_plugins", lambda self: None)
    return MorphCloudClient(base_url="https://cloud.morph.so/api")


def _make_devbox_clients(monkeypatch, shards=None):
    monkeypatch.setenv("MORPH_API_KEY", "test-key")
    if shards is None:
        monkeypatch.delenv("MORPH_HTTP_TRANSPORT_SHARDS", raising=False)
    else:
        monkeypatch.setenv("MORPH_HTTP_TRANSPORT_SHARDS", str(shards))
    return (
        DevboxClient(base_url="https://devbox.svc.cloud.morph.so", token="test-key"),
        AsyncDevboxClient(
            base_url="https://devbox.svc.cloud.morph.so", token="test-key"
        ),
    )


def test_client_uses_sharded_transports_by_default(monkeypatch):
    client = _make_client(monkeypatch)
    try:
        assert isinstance(client._http_client._transport, ShardedTransport)
        assert isinstance(client._async_http_client._transport, ShardedAsyncTransport)
        assert len(client._http_client._transport._transports) == 16
        assert len(client._async_http_client._transport._transports) == 16
    finally:
        client._http_client.close()
        asyncio.run(client._async_http_client.aclose())


def test_transport_shards_can_be_disabled(monkeypatch):
    client = _make_client(monkeypatch, shards=1)
    try:
        assert not isinstance(client._http_client._transport, ShardedTransport)
        assert not isinstance(client._async_http_client._transport, ShardedAsyncTransport)
    finally:
        client._http_client.close()
        asyncio.run(client._async_http_client.aclose())


def test_devbox_clients_use_sharded_transports_by_default(monkeypatch):
    client, async_client = _make_devbox_clients(monkeypatch)
    try:
        assert isinstance(
            client._client_wrapper.httpx_client.httpx_client._transport,
            ShardedTransport,
        )
        assert isinstance(
            async_client._client_wrapper.httpx_client.httpx_client._transport,
            ShardedAsyncTransport,
        )
        assert (
            len(client._client_wrapper.httpx_client.httpx_client._transport._transports)
            == 16
        )
        assert (
            len(
                async_client._client_wrapper.httpx_client.httpx_client._transport._transports
            )
            == 16
        )
    finally:
        client._client_wrapper.httpx_client.httpx_client.close()
        asyncio.run(async_client._client_wrapper.httpx_client.httpx_client.aclose())


def test_devbox_transport_shards_can_be_disabled(monkeypatch):
    client, async_client = _make_devbox_clients(monkeypatch, shards=1)
    try:
        assert not isinstance(
            client._client_wrapper.httpx_client.httpx_client._transport,
            ShardedTransport,
        )
        assert not isinstance(
            async_client._client_wrapper.httpx_client.httpx_client._transport,
            ShardedAsyncTransport,
        )
    finally:
        client._client_wrapper.httpx_client.httpx_client.close()
        asyncio.run(async_client._client_wrapper.httpx_client.httpx_client.aclose())
