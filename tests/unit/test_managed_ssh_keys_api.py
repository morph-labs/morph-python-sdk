import json

import httpx
import pytest

from morphcloud.api import (
    ApiClient,
    ApiError,
    AsyncApiClient,
    ManagedSSHKey,
    ManagedSSHKeyError,
    ManagedSSHKeyPatchRequest,
    ManagedSSHKeyStatus,
    MorphCloudClient,
)

KEY = {
    "object": "user_ssh_key",
    "id": "usk_123",
    "name": "Work laptop",
    "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest test@example",
    "fingerprint": "SHA256:AbCdEf",
    "algorithm": "ssh-ed25519",
    "created": 1_700_000_000,
    "updated": 1_700_000_001,
    "expires": 1_800_000_000,
    "last_used": None,
    "revoked": None,
    "status": "active",
    "migrated_from_legacy": False,
    "migration_warning": False,
}


def _client(handler):
    client = MorphCloudClient(
        api_key="test-key", base_url="https://api.example.test/api"
    )
    client._http_client.close()
    client._http_client = ApiClient(
        base_url=client.base_url, transport=httpx.MockTransport(handler)
    )
    client._async_http_client = AsyncApiClient(
        base_url=client.base_url, transport=httpx.MockTransport(handler)
    )
    return client


def _json_request(request):
    return json.loads(request.content.decode()) if request.content else None


def test_managed_ssh_key_models_cover_lifecycle_and_structured_error():
    key = ManagedSSHKey.model_validate(KEY)
    assert key.id == "usk_123"
    assert key.status is ManagedSSHKeyStatus.ACTIVE
    assert key.expires == 1_800_000_000
    assert key.last_used is None
    assert key.revoked is None
    assert key.migrated_from_legacy is False
    assert key.migration_warning is False

    error = ManagedSSHKeyError.model_validate(
        {"detail": "that key is already registered", "error_code": "duplicate_ssh_key"}
    )
    assert error.error_code == "duplicate_ssh_key"


def test_patch_model_requires_a_change_and_preserves_explicit_null():
    with pytest.raises(ValueError, match="at least one"):
        ManagedSSHKeyPatchRequest()

    patch = ManagedSSHKeyPatchRequest(expires=None)
    assert patch.model_dump(exclude_unset=True) == {"expires": None}


def test_sync_managed_ssh_key_contract_and_legacy_aliases():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, _json_request(request)))
        path = request.url.path
        if request.method == "GET" and path == "/api/user/ssh-keys":
            return httpx.Response(200, json={"object": "list", "data": [KEY]})
        if request.method == "GET" and path == "/api/user/ssh-keys/usk_123":
            return httpx.Response(200, json=KEY)
        if request.method == "POST" and path == "/api/user/ssh-keys":
            return httpx.Response(201, json=KEY)
        if request.method == "PATCH" and path == "/api/user/ssh-keys/usk_123":
            body = _json_request(request)
            return httpx.Response(200, json={**KEY, **body, "updated": 1_700_000_002})
        if request.method == "DELETE" and path == "/api/user/ssh-keys/usk_123":
            return httpx.Response(204)
        if request.method == "GET" and path == "/api/user/ssh-key":
            return httpx.Response(
                200, json={"public_key": KEY["public_key"], "created": 1}
            )
        if request.method == "PUT" and path == "/api/user/ssh-key":
            return httpx.Response(200, json={**_json_request(request), "created": 2})
        raise AssertionError(f"unexpected request: {request.method} {path}")

    client = _client(handler)
    assert [key.id for key in client.user.list_ssh_keys()] == ["usk_123"]
    assert client.user.get_managed_ssh_key("usk_123").name == "Work laptop"
    assert (
        client.user.add_ssh_key(
            name="Work laptop", public_key=KEY["public_key"], expires=1_800_000_000
        ).id
        == "usk_123"
    )
    assert client.user.edit_ssh_key("usk_123", name="Office").name == "Office"
    assert client.user.edit_ssh_key("usk_123", clear_expiry=True).expires is None
    assert client.user.revoke_ssh_key("usk_123") is None
    assert client.user.get_ssh_key().public_key == KEY["public_key"]
    assert client.user.set_ssh_key(KEY["public_key"]).created == 2
    assert client.user.update_ssh_key(KEY["public_key"]).created == 2

    assert seen == [
        ("GET", "/api/user/ssh-keys", None),
        ("GET", "/api/user/ssh-keys/usk_123", None),
        (
            "POST",
            "/api/user/ssh-keys",
            {
                "name": "Work laptop",
                "public_key": KEY["public_key"],
                "expires": 1_800_000_000,
            },
        ),
        ("PATCH", "/api/user/ssh-keys/usk_123", {"name": "Office"}),
        ("PATCH", "/api/user/ssh-keys/usk_123", {"expires": None}),
        ("DELETE", "/api/user/ssh-keys/usk_123", None),
        ("GET", "/api/user/ssh-key", None),
        ("PUT", "/api/user/ssh-key", {"public_key": KEY["public_key"]}),
        ("PUT", "/api/user/ssh-key", {"public_key": KEY["public_key"]}),
    ]


@pytest.mark.asyncio
async def test_async_managed_ssh_key_contract_and_legacy_aliases():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path, _json_request(request)))
        path = request.url.path
        if request.method == "GET" and path == "/api/user/ssh-keys":
            return httpx.Response(200, json={"object": "list", "data": [KEY]})
        if request.method == "GET" and path == "/api/user/ssh-keys/usk_123":
            return httpx.Response(200, json=KEY)
        if request.method == "POST" and path == "/api/user/ssh-keys":
            return httpx.Response(201, json=KEY)
        if request.method == "PATCH" and path == "/api/user/ssh-keys/usk_123":
            return httpx.Response(200, json={**KEY, **_json_request(request)})
        if request.method == "DELETE" and path == "/api/user/ssh-keys/usk_123":
            return httpx.Response(204)
        if request.method == "GET" and path == "/api/user/ssh-key":
            return httpx.Response(
                200, json={"public_key": KEY["public_key"], "created": 1}
            )
        if request.method == "PUT" and path == "/api/user/ssh-key":
            return httpx.Response(200, json={**_json_request(request), "created": 2})
        raise AssertionError(f"unexpected request: {request.method} {path}")

    client = _client(handler)
    assert [key.id for key in await client.user.alist_ssh_keys()] == ["usk_123"]
    assert (await client.user.aget_managed_ssh_key("usk_123")).id == "usk_123"
    assert (
        await client.user.aadd_ssh_key(name="Work laptop", public_key=KEY["public_key"])
    ).id == "usk_123"
    assert (await client.user.aedit_ssh_key("usk_123", name="Office")).name == "Office"
    assert (
        await client.user.aedit_ssh_key("usk_123", clear_expiry=True)
    ).expires is None
    assert await client.user.arevoke_ssh_key("usk_123") is None
    assert (await client.user.aget_ssh_key()).created == 1
    assert (await client.user.aset_ssh_key(KEY["public_key"])).created == 2
    assert (await client.user.aupdate_ssh_key(KEY["public_key"])).created == 2

    assert seen[2] == (
        "POST",
        "/api/user/ssh-keys",
        {"name": "Work laptop", "public_key": KEY["public_key"]},
    )
    assert seen[3] == (
        "PATCH",
        "/api/user/ssh-keys/usk_123",
        {"name": "Office"},
    )
    assert seen[4] == (
        "PATCH",
        "/api/user/ssh-keys/usk_123",
        {"expires": None},
    )


def test_structured_api_error_is_available_without_losing_response_body():
    def handler(request):
        return httpx.Response(
            409,
            json={
                "detail": "that key is already registered",
                "error_code": "duplicate_ssh_key",
            },
        )

    client = _client(handler)
    with pytest.raises(ApiError) as exc_info:
        client.user.add_ssh_key(name="duplicate", public_key=KEY["public_key"])

    error = exc_info.value
    assert error.status_code == 409
    assert error.error_code == "duplicate_ssh_key"
    assert error.detail == "that key is already registered"
    assert error.as_managed_ssh_key_error() == ManagedSSHKeyError(
        detail="that key is already registered", error_code="duplicate_ssh_key"
    )
    assert "duplicate_ssh_key" in error.response_body


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({}, "at least one"),
        (
            {"expires": 1_800_000_000, "clear_expiry": True},
            "expires and clear_expiry cannot be used together",
        ),
    ],
)
def test_edit_rejects_ambiguous_or_empty_updates(kwargs, message):
    client = _client(lambda request: pytest.fail("request must not be sent"))
    with pytest.raises(ValueError, match=message):
        client.user.edit_ssh_key("usk_123", **kwargs)
