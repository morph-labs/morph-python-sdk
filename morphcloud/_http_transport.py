from __future__ import annotations

import asyncio
import itertools
import os
import typing

import httpx


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except Exception:
        return default


class ShardedTransport(httpx.BaseTransport):
    def __init__(self, transports: typing.Sequence[httpx.HTTPTransport]) -> None:
        self._transports = list(transports)
        self._counter = itertools.count()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transports[next(self._counter) % len(self._transports)]
        return transport.handle_request(request)

    def close(self) -> None:
        for transport in self._transports:
            transport.close()


class ShardedAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, transports: typing.Sequence[httpx.AsyncHTTPTransport]) -> None:
        self._transports = list(transports)
        self._counter = itertools.count()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transports[next(self._counter) % len(self._transports)]
        return await transport.handle_async_request(request)

    async def aclose(self) -> None:
        await asyncio.gather(*(transport.aclose() for transport in self._transports))


def _new_limits() -> httpx.Limits:
    max_connections = _env_int("MORPH_HTTP_MAX_CONNECTIONS", 100)
    max_keepalive_connections = _env_int(
        "MORPH_HTTP_MAX_KEEPALIVE_CONNECTIONS",
        max_connections,
    )
    keepalive_expiry = _env_float("MORPH_HTTP_KEEPALIVE_EXPIRY", 60.0)
    return httpx.Limits(
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive_connections,
        keepalive_expiry=keepalive_expiry,
    )


def build_http_transport() -> httpx.BaseTransport:
    # Spread requests across independent httpcore pools to avoid contention
    # in a single transport under high concurrency. Set to 1 to disable.
    transport_shards = max(_env_int("MORPH_HTTP_TRANSPORT_SHARDS", 32), 1)
    if transport_shards == 1:
        return httpx.HTTPTransport(limits=_new_limits())
    return ShardedTransport(
        [httpx.HTTPTransport(limits=_new_limits()) for _ in range(transport_shards)]
    )


def build_async_http_transport() -> httpx.AsyncBaseTransport:
    transport_shards = max(_env_int("MORPH_HTTP_TRANSPORT_SHARDS", 32), 1)
    if transport_shards == 1:
        return httpx.AsyncHTTPTransport(limits=_new_limits())
    return ShardedAsyncTransport(
        [
            httpx.AsyncHTTPTransport(limits=_new_limits())
            for _ in range(transport_shards)
        ]
    )
