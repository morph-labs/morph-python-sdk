import types

import pytest

from morphcloud.api import Instance, Snapshot, SnapshotAPI


class StubResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class StubHTTPClient:
    def __init__(self, payload):
        self.payload = payload
        self.post_calls = []

    def post(self, url, params=None, json=None):
        self.post_calls.append(
            {
                "url": url,
                "params": params,
                "json": json,
            }
        )
        return StubResponse(self.payload)


class StubAsyncHTTPClient:
    def __init__(self, payload):
        self.payload = payload
        self.post_calls = []

    async def post(self, url, params=None, json=None):
        self.post_calls.append(
            {
                "url": url,
                "params": params,
                "json": json,
            }
        )
        return StubResponse(self.payload)


class StubSnapshotAPI:
    def __init__(self, http_payload, refresh_payload):
        self._http_client = StubHTTPClient(http_payload)
        self._async_http_client = StubAsyncHTTPClient(http_payload)
        self._client = types.SimpleNamespace(
            _http_client=self._http_client,
            _async_http_client=self._async_http_client,
        )
        self._refresh_payload = refresh_payload

    def get(self, snapshot_id):
        assert snapshot_id == self._refresh_payload["id"]
        return Snapshot.model_validate(self._refresh_payload)._set_api(self)

    async def aget(self, snapshot_id):
        assert snapshot_id == self._refresh_payload["id"]
        return Snapshot.model_validate(self._refresh_payload)._set_api(self)


def _snapshot_payload(*, ttl_seconds=None, ttl_expire_at=None):
    payload = {
        "id": "snapshot_123",
        "object": "snapshot",
        "created": 1,
        "status": "ready",
        "spec": {"vcpus": 1, "memory": 512, "disk_size": 1024},
        "refs": {"image_id": "morphvm-minimal"},
        "metadata": {},
    }
    if ttl_seconds is not None or ttl_expire_at is not None:
        payload["ttl"] = {
            "ttl_seconds": ttl_seconds,
            "ttl_expire_at": ttl_expire_at,
        }
    return payload


def _instance_payload():
    return {
        "id": "instance_123",
        "object": "instance",
        "created": 1,
        "status": "ready",
        "spec": {"vcpus": 1, "memory": 512, "disk_size": 1024},
        "refs": {
            "snapshot_id": "snapshot_base",
            "image_id": "morphvm-minimal",
        },
        "networking": {"internal_ip": None, "http_services": []},
        "metadata": {},
    }


def test_snapshot_model_parses_ttl():
    snapshot = Snapshot.model_validate(
        _snapshot_payload(ttl_seconds=60, ttl_expire_at=120)
    )

    assert snapshot.ttl.ttl_seconds == 60
    assert snapshot.ttl.ttl_expire_at == 120


def test_snapshot_create_sends_ttl_seconds():
    http_client = StubHTTPClient(_snapshot_payload(ttl_seconds=60, ttl_expire_at=120))
    client = types.SimpleNamespace(_http_client=http_client)

    snapshot = SnapshotAPI(client).create(
        image_id="morphvm-minimal",
        vcpus=1,
        memory=512,
        disk_size=1024,
        ttl_seconds=60,
    )

    assert http_client.post_calls == [
        {
            "url": "/snapshot",
            "params": None,
            "json": {
                "image_id": "morphvm-minimal",
                "vcpus": 1,
                "memory": 512,
                "disk_size": 1024,
                "ttl_seconds": 60,
            },
        }
    ]
    assert snapshot.ttl.ttl_seconds == 60


@pytest.mark.parametrize("ttl_seconds", [0, -5])
def test_snapshot_create_rejects_non_positive_ttl(ttl_seconds):
    http_client = StubHTTPClient(_snapshot_payload())
    client = types.SimpleNamespace(_http_client=http_client)

    with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
        SnapshotAPI(client).create(
            image_id="morphvm-minimal",
            vcpus=1,
            memory=512,
            disk_size=1024,
            ttl_seconds=ttl_seconds,
        )

    assert http_client.post_calls == []


def test_instance_snapshot_sends_ttl_seconds():
    http_client = StubHTTPClient(_snapshot_payload(ttl_seconds=45, ttl_expire_at=90))
    client = types.SimpleNamespace(
        _http_client=http_client,
        snapshots=types.SimpleNamespace(),
    )
    instance = Instance.model_validate(_instance_payload())._set_api(
        types.SimpleNamespace(_client=client)
    )

    snapshot = instance.snapshot(
        digest="digest-1",
        metadata={"env": "test"},
        ttl_seconds=45,
    )

    assert http_client.post_calls == [
        {
            "url": "/instance/instance_123/snapshot",
            "params": {"digest": "digest-1"},
            "json": {
                "metadata": {"env": "test"},
                "ttl_seconds": 45,
            },
        }
    ]
    assert snapshot.ttl.ttl_seconds == 45


@pytest.mark.parametrize("ttl_seconds", [0, -1])
def test_instance_snapshot_rejects_non_positive_ttl(ttl_seconds):
    http_client = StubHTTPClient(_snapshot_payload())
    client = types.SimpleNamespace(
        _http_client=http_client,
        snapshots=types.SimpleNamespace(),
    )
    instance = Instance.model_validate(_instance_payload())._set_api(
        types.SimpleNamespace(_client=client)
    )

    with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
        instance.snapshot(ttl_seconds=ttl_seconds)

    assert http_client.post_calls == []


def test_snapshot_set_ttl_can_clear_snapshot_ttl():
    api = StubSnapshotAPI(
        http_payload=_snapshot_payload(ttl_seconds=60, ttl_expire_at=120),
        refresh_payload=_snapshot_payload(ttl_seconds=None, ttl_expire_at=None),
    )
    snapshot = Snapshot.model_validate(
        _snapshot_payload(ttl_seconds=60, ttl_expire_at=120)
    )._set_api(api)

    snapshot.set_ttl(None)

    assert api._http_client.post_calls == [
        {
            "url": "/snapshot/snapshot_123/ttl",
            "params": None,
            "json": {"ttl_seconds": None},
        }
    ]
    assert snapshot.ttl.ttl_seconds is None
    assert snapshot.ttl.ttl_expire_at is None


@pytest.mark.parametrize("ttl_seconds", [0, -2])
def test_snapshot_set_ttl_rejects_non_positive_values(ttl_seconds):
    api = StubSnapshotAPI(
        http_payload=_snapshot_payload(),
        refresh_payload=_snapshot_payload(),
    )
    snapshot = Snapshot.model_validate(_snapshot_payload())._set_api(api)

    with pytest.raises(ValueError, match="ttl_seconds must be greater than zero"):
        snapshot.set_ttl(ttl_seconds)

    assert api._http_client.post_calls == []


@pytest.mark.asyncio
async def test_snapshot_aset_ttl_updates_snapshot():
    api = StubSnapshotAPI(
        http_payload=_snapshot_payload(ttl_seconds=120, ttl_expire_at=240),
        refresh_payload=_snapshot_payload(ttl_seconds=120, ttl_expire_at=240),
    )
    snapshot = Snapshot.model_validate(_snapshot_payload())._set_api(api)

    await snapshot.aset_ttl(120)

    assert api._async_http_client.post_calls == [
        {
            "url": "/snapshot/snapshot_123/ttl",
            "params": None,
            "json": {"ttl_seconds": 120},
        }
    ]
    assert snapshot.ttl.ttl_seconds == 120
    assert snapshot.ttl.ttl_expire_at == 240
