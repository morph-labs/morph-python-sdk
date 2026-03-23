import pathlib

import pytest


def test_load_local_template_spec_fetches_shared_alias_yaml(monkeypatch, tmp_path):
    import morphcloud.devbox.template_local_runner as local_runner_mod

    calls = []
    monkeypatch.chdir(tmp_path)

    def fake_fetch(alias: str) -> str:
        calls.append(alias)
        return (
            "name: OpenGauss\n"
            "steps:\n"
            "  - title: Echo\n"
            "    run: printf 'remote alias\\n'\n"
        )

    monkeypatch.setattr(
        local_runner_mod,
        "_fetch_morph_new_template_yaml",
        fake_fetch,
    )

    spec = local_runner_mod.load_local_template_spec("opengauss")
    try:
        assert calls == ["opengauss"]
        assert spec.display_path == "https://morph.new/opengauss/yaml"
        assert spec.working_directory == pathlib.Path(tmp_path).resolve()
        assert spec.target.template_id == "https://morph.new/opengauss/yaml"
        assert spec.target.name == "OpenGauss"
        assert spec.steps[0].command == "printf 'remote alias\\n'"
        assert spec.path.is_file()
    finally:
        if spec.cleanup is not None:
            spec.cleanup()

    assert not spec.path.exists()


def test_load_local_template_spec_prefers_alias_over_same_named_directory(
    monkeypatch, tmp_path
):
    import morphcloud.devbox.template_local_runner as local_runner_mod

    calls = []
    monkeypatch.chdir(tmp_path)
    (tmp_path / "opengauss").mkdir()

    def fake_fetch(alias: str) -> str:
        calls.append(alias)
        return (
            "name: OpenGauss\n"
            "steps:\n"
            "  - title: Echo\n"
            "    run: printf 'remote alias directory collision\\n'\n"
        )

    monkeypatch.setattr(
        local_runner_mod,
        "_fetch_morph_new_template_yaml",
        fake_fetch,
    )

    spec = local_runner_mod.load_local_template_spec("opengauss")
    try:
        assert calls == ["opengauss"]
        assert spec.display_path == "https://morph.new/opengauss/yaml"
        assert spec.target.name == "OpenGauss"
        assert (
            spec.steps[0].command
            == "printf 'remote alias directory collision\\n'"
        )
    finally:
        if spec.cleanup is not None:
            spec.cleanup()


def test_load_local_template_spec_reports_alias_fetch_failure(monkeypatch, tmp_path):
    import morphcloud.devbox.template_local_runner as local_runner_mod

    monkeypatch.chdir(tmp_path)

    def fake_fetch(alias: str) -> str:
        raise local_runner_mod.TemplateRunnerError("404 Not Found")

    monkeypatch.setattr(
        local_runner_mod,
        "_fetch_morph_new_template_yaml",
        fake_fetch,
    )

    with pytest.raises(local_runner_mod.TemplateRunnerError) as exc_info:
        local_runner_mod.load_local_template_spec("opengauss")

    assert "Template YAML file does not exist:" in str(exc_info.value)
    assert "https://morph.new/opengauss/yaml" in str(exc_info.value)
    assert "404 Not Found" in str(exc_info.value)


def test_load_local_template_spec_uses_explicit_local_yaml_path(monkeypatch, tmp_path):
    import morphcloud.devbox.template_local_runner as local_runner_mod

    monkeypatch.chdir(tmp_path)
    yaml_path = tmp_path / "opengauss.yaml"
    yaml_path.write_text(
        "name: Local OpenGauss\nsteps:\n  - title: Echo\n    run: printf 'local file\\n'\n",
        encoding="utf-8",
    )

    spec = local_runner_mod.load_local_template_spec("./opengauss.yaml")

    assert spec.display_path == str(yaml_path.resolve())
    assert spec.target.template_id == str(yaml_path.resolve())
    assert spec.target.name == "Local OpenGauss"
    assert spec.steps[0].command == "printf 'local file\\n'"
