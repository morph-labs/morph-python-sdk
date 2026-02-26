import morphcloud.api as api


def test_default_chain_snapshot_ttl_seconds_uses_fallback(monkeypatch):
    monkeypatch.delenv(api.CHAIN_SNAPSHOT_TTL_ENV_VAR, raising=False)
    api.default_chain_snapshot_ttl_seconds.cache_clear()
    assert api.default_chain_snapshot_ttl_seconds() == api.DEFAULT_CHAIN_SNAPSHOT_TTL_SECONDS


def test_default_chain_snapshot_ttl_seconds_env_override(monkeypatch):
    monkeypatch.setenv(api.CHAIN_SNAPSHOT_TTL_ENV_VAR, "123")
    api.default_chain_snapshot_ttl_seconds.cache_clear()
    assert api.default_chain_snapshot_ttl_seconds() == 123


def test_default_chain_snapshot_ttl_seconds_env_invalid(monkeypatch):
    monkeypatch.setenv(api.CHAIN_SNAPSHOT_TTL_ENV_VAR, "not-an-int")
    api.default_chain_snapshot_ttl_seconds.cache_clear()
    assert api.default_chain_snapshot_ttl_seconds() == api.DEFAULT_CHAIN_SNAPSHOT_TTL_SECONDS

