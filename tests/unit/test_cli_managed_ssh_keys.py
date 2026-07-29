import json
import types

import pytest
from click.testing import CliRunner

from morphcloud.api import ManagedSSHKey, UserSSHKey

PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest cli@example"
KEY = ManagedSSHKey(
    id="usk_cli",
    name="Work laptop",
    public_key=PUBLIC_KEY,
    fingerprint="SHA256:CliTest",
    algorithm="ssh-ed25519",
    created=1_700_000_000,
    updated=1_700_000_001,
    expires=None,
    last_used=None,
    revoked=None,
    status="active",
)


def _install_noop_spinner(monkeypatch):
    import morphcloud.cli as cli_mod

    class NoopSpinner:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(cli_mod, "Spinner", NoopSpinner)


def _invoke(monkeypatch, user, argv, *, input=None):
    import morphcloud.cli as cli_mod

    _install_noop_spinner(monkeypatch)
    monkeypatch.setattr(cli_mod, "get_client", lambda: types.SimpleNamespace(user=user))
    return CliRunner().invoke(cli_mod.cli, ["user", "ssh-key", *argv], input=input)


@pytest.mark.parametrize("command", ["list", "get", "add", "edit", "revoke", "set"])
def test_managed_ssh_key_commands_are_documented(command):
    import morphcloud.cli as cli_mod

    result = CliRunner().invoke(cli_mod.cli, ["user", "ssh-key", command, "--help"])
    assert result.exit_code == 0, result.output


def test_list_outputs_typed_json(monkeypatch):
    user = types.SimpleNamespace(list_ssh_keys=lambda: [KEY])
    result = _invoke(monkeypatch, user, ["list", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload[0]["id"] == "usk_cli"
    assert payload[0]["status"] == "active"


def test_list_outputs_auditable_columns(monkeypatch):
    user = types.SimpleNamespace(list_ssh_keys=lambda: [KEY])
    result = _invoke(monkeypatch, user, ["list"])
    assert result.exit_code == 0, result.output
    assert "Fingerprint" in result.output
    assert "SHA256:CliTest" in result.output
    assert "Work laptop" in result.output


def test_get_with_id_uses_plural_endpoint_method(monkeypatch):
    calls = []
    user = types.SimpleNamespace(
        get_managed_ssh_key=lambda key_id: calls.append(key_id) or KEY
    )
    result = _invoke(monkeypatch, user, ["get", "usk_cli", "--json"])
    assert result.exit_code == 0, result.output
    assert calls == ["usk_cli"]
    assert json.loads(result.output)["fingerprint"] == "SHA256:CliTest"


def test_get_without_id_retains_legacy_behavior(monkeypatch):
    user = types.SimpleNamespace(
        get_ssh_key=lambda: UserSSHKey(public_key=PUBLIC_KEY, created=1)
    )
    result = _invoke(monkeypatch, user, ["get", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"public_key": PUBLIC_KEY, "created": 1}


def test_add_accepts_public_key_text_and_iso_expiry(monkeypatch):
    calls = []

    def add_ssh_key(**kwargs):
        calls.append(kwargs)
        return KEY

    result = _invoke(
        monkeypatch,
        types.SimpleNamespace(add_ssh_key=add_ssh_key),
        [
            "add",
            "--name",
            "Work laptop",
            "--public-key",
            PUBLIC_KEY,
            "--expires",
            "2030-01-01T00:00:00Z",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "name": "Work laptop",
            "public_key": PUBLIC_KEY,
            "expires": 1_893_456_000,
        }
    ]


def test_add_reads_exactly_one_public_key_from_pub_file(monkeypatch, tmp_path):
    pub_file = tmp_path / "id_ed25519.pub"
    pub_file.write_text(f"{PUBLIC_KEY}\n", encoding="utf-8")
    calls = []
    user = types.SimpleNamespace(
        add_ssh_key=lambda **kwargs: calls.append(kwargs) or KEY
    )
    result = _invoke(
        monkeypatch,
        user,
        ["add", "--name", "Work laptop", "--public-key-file", str(pub_file)],
    )
    assert result.exit_code == 0, result.output
    assert calls[0]["public_key"] == PUBLIC_KEY


@pytest.mark.parametrize(
    "argv, expected",
    [
        (
            ["--public-key", PUBLIC_KEY, "--public-key-file", "id.pub"],
            "either --public-key or --public-key-file",
        ),
        (
            ["--public-key", "-----BEGIN PRIVATE KEY-----"],
            "Private keys are not accepted",
        ),
        (
            ["--public-key", f"{PUBLIC_KEY}\n{PUBLIC_KEY}"],
            "exactly one SSH public key",
        ),
    ],
)
def test_add_rejects_ambiguous_or_private_input(monkeypatch, tmp_path, argv, expected):
    pub_file = tmp_path / "id.pub"
    pub_file.write_text(PUBLIC_KEY, encoding="utf-8")
    argv = [str(pub_file) if item == "id.pub" else item for item in argv]
    result = _invoke(
        monkeypatch,
        types.SimpleNamespace(),
        ["add", "--name", "Unsafe", *argv],
    )
    assert result.exit_code != 0
    assert expected in result.output


def test_add_refuses_non_pub_file(monkeypatch, tmp_path):
    private_file = tmp_path / "id_ed25519"
    private_file.write_text("not a public file", encoding="utf-8")
    result = _invoke(
        monkeypatch,
        types.SimpleNamespace(),
        ["add", "--name", "Unsafe", "--public-key-file", str(private_file)],
    )
    assert result.exit_code != 0
    assert "public .pub file" in result.output


@pytest.mark.parametrize(
    "argv, expected",
    [
        (
            ["--name", "Office"],
            {"name": "Office", "expires": None, "clear_expiry": False},
        ),
        (["--clear-expiry"], {"name": None, "expires": None, "clear_expiry": True}),
        (
            ["--expires", "1800000000"],
            {"name": None, "expires": 1_800_000_000, "clear_expiry": False},
        ),
    ],
)
def test_edit_sends_only_deliberate_metadata_change(monkeypatch, argv, expected):
    calls = []

    def edit_ssh_key(key_id, **kwargs):
        calls.append((key_id, kwargs))
        return KEY

    result = _invoke(
        monkeypatch,
        types.SimpleNamespace(edit_ssh_key=edit_ssh_key),
        ["edit", "usk_cli", *argv],
    )
    assert result.exit_code == 0, result.output
    assert calls == [("usk_cli", expected)]


def test_edit_rejects_empty_or_conflicting_change(monkeypatch):
    result = _invoke(monkeypatch, types.SimpleNamespace(), ["edit", "usk_cli"])
    assert result.exit_code != 0
    assert "Provide at least one" in result.output

    result = _invoke(
        monkeypatch,
        types.SimpleNamespace(),
        ["edit", "usk_cli", "--expires", "1800000000", "--clear-expiry"],
    )
    assert result.exit_code != 0
    assert "either --expires or --clear-expiry" in result.output


def test_revoke_requires_confirmation_and_targets_one_id(monkeypatch):
    calls = []
    user = types.SimpleNamespace(revoke_ssh_key=lambda key_id: calls.append(key_id))
    result = _invoke(monkeypatch, user, ["revoke", "usk_cli"], input="n\n")
    assert result.exit_code != 0
    assert calls == []

    result = _invoke(monkeypatch, user, ["revoke", "usk_cli", "--yes"])
    assert result.exit_code == 0, result.output
    assert calls == ["usk_cli"]


def test_set_retains_legacy_singular_alias(monkeypatch):
    calls = []
    user = types.SimpleNamespace(
        set_ssh_key=lambda public_key: (
            calls.append(public_key) or UserSSHKey(public_key=public_key, created=1)
        )
    )
    result = _invoke(monkeypatch, user, ["set", "--public-key", PUBLIC_KEY, "--json"])
    assert result.exit_code == 0, result.output
    assert calls == [PUBLIC_KEY]
