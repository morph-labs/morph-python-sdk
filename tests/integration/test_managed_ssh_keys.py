"""Stage/production contract tests for user-managed SSH public keys.

Run only after the plural runtime API is deployed in the selected environment:

    MORPH_RUN_INTEGRATION_TESTS=1 MORPH_TARGET=stage MORPH_API_HOST=stage.morph.so \
    MORPH_BASE_URL=https://stage.morph.so/api MORPH_API_KEY=... \
    pytest -q tests/integration/test_managed_ssh_keys.py

or:

    MORPH_RUN_INTEGRATION_TESTS=1 MORPH_TARGET=prod MORPH_API_HOST=cloud.morph.so \
    MORPH_BASE_URL=https://cloud.morph.so/api MORPH_API_KEY=... \
    pytest -q tests/integration/test_managed_ssh_keys.py

Only these exact environment tuples are accepted; there is no target fallback.
The tests add unique generated public keys and always target those stable IDs for
cleanup. They never read or replace the legacy singular/default key.
"""

import os
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio

_MANAGED_KEY_CONTRACTS = frozenset(
    {
        ("stage", "stage.morph.so", "https://stage.morph.so/api"),
        ("prod", "cloud.morph.so", "https://cloud.morph.so/api"),
    }
)


@pytest.fixture(autouse=True)
def managed_key_target() -> str:
    contract = (
        os.environ.get("MORPH_TARGET"),
        os.environ.get("MORPH_API_HOST"),
        os.environ.get("MORPH_BASE_URL"),
    )
    assert contract in _MANAGED_KEY_CONTRACTS
    return contract[0]


def _generated_public_key(comment: str) -> str:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return f"{public_key.decode('ascii')} {comment}"


async def test_managed_ssh_key_lifecycle_sync(client, managed_key_target: str):
    suffix = uuid.uuid4().hex[:12]
    original_name = f"SDK {managed_key_target} e2e sync {suffix}"
    edited_name = f"SDK {managed_key_target} e2e sync edited {suffix}"
    public_key = _generated_public_key(
        f"morph-sdk-{managed_key_target}-e2e-sync-{suffix}"
    )
    created = None

    try:
        created = client.user.add_ssh_key(name=original_name, public_key=public_key)
        assert created.name == original_name
        assert created.public_key == public_key
        assert created.algorithm == "ssh-ed25519"
        assert created.fingerprint.startswith("SHA256:")
        assert created.status.value == "active"

        listed = client.user.list_ssh_keys()
        assert any(item.id == created.id for item in listed)
        fetched = client.user.get_managed_ssh_key(created.id)
        assert fetched == created

        expires = int(time.time()) + 3600
        edited = client.user.edit_ssh_key(created.id, name=edited_name, expires=expires)
        assert edited.id == created.id
        assert edited.name == edited_name
        assert edited.expires == expires
        assert edited.public_key == public_key
    finally:
        cleanup_ids = {
            item.id
            for item in client.user.list_ssh_keys()
            if item.name in {original_name, edited_name} and item.revoked is None
        }
        if created is not None and created.revoked is None:
            cleanup_ids.add(created.id)
        for key_id in cleanup_ids:
            client.user.revoke_ssh_key(key_id)

    revoked = client.user.get_managed_ssh_key(created.id)
    assert revoked.status.value == "revoked"
    assert revoked.revoked is not None


async def test_managed_ssh_key_lifecycle_async(client, managed_key_target: str):
    suffix = uuid.uuid4().hex[:12]
    original_name = f"SDK {managed_key_target} e2e async {suffix}"
    edited_name = f"SDK {managed_key_target} e2e async edited {suffix}"
    public_key = _generated_public_key(
        f"morph-sdk-{managed_key_target}-e2e-async-{suffix}"
    )
    created = None

    try:
        created = await client.user.aadd_ssh_key(
            name=original_name, public_key=public_key
        )
        assert created.name == original_name
        assert created.public_key == public_key
        assert created.algorithm == "ssh-ed25519"
        assert created.fingerprint.startswith("SHA256:")
        assert created.status.value == "active"

        listed = await client.user.alist_ssh_keys()
        assert any(item.id == created.id for item in listed)
        fetched = await client.user.aget_managed_ssh_key(created.id)
        assert fetched == created

        edited = await client.user.aedit_ssh_key(
            created.id, name=edited_name, clear_expiry=True
        )
        assert edited.id == created.id
        assert edited.name == edited_name
        assert edited.expires is None
        assert edited.public_key == public_key
    finally:
        cleanup_ids = {
            item.id
            for item in await client.user.alist_ssh_keys()
            if item.name in {original_name, edited_name} and item.revoked is None
        }
        if created is not None and created.revoked is None:
            cleanup_ids.add(created.id)
        for key_id in cleanup_ids:
            await client.user.arevoke_ssh_key(key_id)

    revoked = await client.user.aget_managed_ssh_key(created.id)
    assert revoked.status.value == "revoked"
    assert revoked.revoked is not None
