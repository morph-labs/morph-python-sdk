import morphcloud.api as api


def test_snapshot_parses_ttl_fields():
    snap = api.Snapshot.model_validate(
        {
            "id": "snapshot_1",
            "object": "snapshot",
            "created": 1,
            "status": "ready",
            "spec": {"vcpus": 1, "memory": 256, "disk_size": 1024},
            "refs": {"image_id": "morphvm-minimal"},
            "metadata": {},
            "ttl": {"ttl_seconds": 60, "ttl_expire_at": 2000},
        }
    )
    assert snap.ttl.ttl_seconds == 60
    assert snap.ttl.ttl_expire_at == 2000


def test_snapshot_allows_no_ttl():
    snap = api.Snapshot.model_validate(
        {
            "id": "snapshot_1",
            "object": "snapshot",
            "created": 1,
            "status": "ready",
            "spec": {"vcpus": 1, "memory": 256, "disk_size": 1024},
            "refs": {"image_id": "morphvm-minimal"},
            "metadata": {},
            "ttl": {"ttl_seconds": None},
        }
    )
    assert snap.ttl.ttl_seconds is None
    assert snap.ttl.ttl_expire_at is None

