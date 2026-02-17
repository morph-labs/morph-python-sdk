import toml
from click.testing import CliRunner

import morphcloud.config as config


def test_resolve_settings_derives_from_api_host():
    cfg = {
        "version": 1,
        "profiles": {
            "stage": {
                "api_host": "stage.morph.so",
                "api_key": "k",
            }
        },
    }

    settings = config.resolve_settings(profile="stage", env={}, config=cfg)
    assert settings.base_url == "https://stage.morph.so/api"
    assert settings.ssh_hostname == "ssh.stage.morph.so"
    assert settings.service_base_url == "https://service.svc.stage.morph.so"
    assert settings.admin_base_url == "https://admin.svc.stage.morph.so"
    assert settings.db_base_url == "https://db.svc.stage.morph.so"


def test_env_overrides_profile():
    cfg = {
        "version": 1,
        "profiles": {
            "stage": {
                "base_url": "https://stage.morph.so/api",
            }
        },
    }
    env = {"MORPH_BASE_URL": "https://override.morph.so/api"}

    settings = config.resolve_settings(profile="stage", env=env, config=cfg)
    assert settings.base_url == "https://override.morph.so/api"


def test_profile_cli_set_use_and_env(tmp_path, monkeypatch):
    import morphcloud.cli as cli_mod

    cfg_path = tmp_path / "config.toml"
    monkeypatch.setenv("MORPH_CONFIG_PATH", str(cfg_path))

    runner = CliRunner()
    result = runner.invoke(
        cli_mod.cli,
        [
            "profile",
            "set",
            "stage",
            "--api-host",
            "stage.morph.so",
            "--api-key",
            "key-123",
        ],
    )
    assert result.exit_code == 0, result.output

    result = runner.invoke(cli_mod.cli, ["profile", "use", "stage"])
    assert result.exit_code == 0, result.output

    result = runner.invoke(cli_mod.cli, ["profile", "current"])
    assert result.exit_code == 0, result.output
    assert "stage" in result.output

    result = runner.invoke(cli_mod.cli, ["profile", "env", "stage", "--no-api-key"])
    assert result.exit_code == 0, result.output
    assert "MORPH_BASE_URL" in result.output
    assert "MORPH_API_KEY" not in result.output

    # Ensure config persisted
    cfg = toml.loads(cfg_path.read_text())
    assert cfg.get("active_profile") == "stage"
