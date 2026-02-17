from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

import toml

DEFAULT_API_HOST = "cloud.morph.so"
DEFAULT_BASE_URL = "https://cloud.morph.so/api"
DEFAULT_SSH_HOSTNAME = "ssh.cloud.morph.so"
DEFAULT_SSH_PORT = 22
DEFAULT_SERVICE_BASE_URL = "https://service.svc.cloud.morph.so"
DEFAULT_ADMIN_BASE_URL = "https://admin.svc.cloud.morph.so"
DEFAULT_DB_BASE_URL = "https://db.svc.cloud.morph.so"


@dataclass(frozen=True)
class ResolvedSettings:
    profile: Optional[str]
    api_key: Optional[str]
    base_url: str
    ssh_hostname: str
    ssh_port: int
    api_host: str
    service_base_url: str
    admin_base_url: str
    db_base_url: str

    def as_env(self, *, include_api_key: bool = True) -> Dict[str, str]:
        env: Dict[str, str] = {
            "MORPH_BASE_URL": self.base_url,
            "MORPH_API_HOST": self.api_host,
            "MORPH_SSH_HOSTNAME": self.ssh_hostname,
            "MORPH_SSH_PORT": str(self.ssh_port),
            "MORPH_SERVICE_BASE_URL": self.service_base_url,
            "MORPH_ADMIN_BASE_URL": self.admin_base_url,
            "MORPH_DB_BASE_URL": self.db_base_url,
        }
        if include_api_key and self.api_key:
            env["MORPH_API_KEY"] = self.api_key
        return env


def _clean(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    return value


def _coalesce(*values: Any) -> Any:
    for value in values:
        value = _clean(value)
        if value is not None:
            return value
    return None


def _parse_int(value: Any) -> Optional[int]:
    value = _clean(value)
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _api_host_from_base_url(base_url: Optional[str]) -> Optional[str]:
    if not base_url:
        return None
    candidate = str(base_url).strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"https://{candidate.lstrip('/')}"
    try:
        parsed = urlparse(candidate)
    except Exception:
        return None
    return parsed.hostname


def _config_paths() -> list[pathlib.Path]:
    env_path = _clean(os.getenv("MORPH_CONFIG_PATH"))
    if env_path:
        return [pathlib.Path(os.path.expanduser(env_path))]

    xdg_root = _clean(os.getenv("XDG_CONFIG_HOME")) or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    primary = pathlib.Path(xdg_root) / "morphcloud" / "config.toml"
    fallback = pathlib.Path(os.path.expanduser("~")) / ".morphcloud" / "config.toml"
    return [primary, fallback]


def get_config_path() -> pathlib.Path:
    for path in _config_paths():
        if path.exists():
            return path
    return _config_paths()[0]


def load_config(path: Optional[pathlib.Path] = None) -> Dict[str, Any]:
    paths = [path] if path else _config_paths()
    for candidate in paths:
        if candidate is None:
            continue
        candidate = pathlib.Path(candidate)
        if not candidate.exists():
            continue
        try:
            data = toml.load(candidate)
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def save_config(config: Mapping[str, Any], path: Optional[pathlib.Path] = None) -> pathlib.Path:
    target = pathlib.Path(path or get_config_path())
    target.parent.mkdir(parents=True, exist_ok=True)
    rendered = toml.dumps(dict(config))
    target.write_text(rendered, encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except Exception:
        pass
    return target


def resolve_profile(name: Optional[str], config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    config = config or load_config()
    profiles = config.get("profiles", {}) if isinstance(config, dict) else {}
    if not name:
        return {}
    profile = profiles.get(name, {}) if isinstance(profiles, dict) else {}
    return profile if isinstance(profile, dict) else {}


def resolve_settings(
    *,
    profile: Optional[str] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    env: Optional[Mapping[str, str]] = None,
    config: Optional[Mapping[str, Any]] = None,
) -> ResolvedSettings:
    overrides = overrides or {}
    env = env or os.environ
    config = config or load_config()

    active_profile = None
    if isinstance(config, dict):
        active_profile = _clean(config.get("active_profile"))

    profile_name = _coalesce(profile, env.get("MORPH_PROFILE"), active_profile)
    profile_data = resolve_profile(profile_name, config)

    api_key = _coalesce(
        overrides.get("api_key"),
        env.get("MORPH_API_KEY"),
        profile_data.get("api_key"),
    )
    api_host = _coalesce(
        overrides.get("api_host"),
        env.get("MORPH_API_HOST"),
        profile_data.get("api_host"),
    )
    base_url = _coalesce(
        overrides.get("base_url"),
        env.get("MORPH_BASE_URL"),
        profile_data.get("base_url"),
    )
    ssh_hostname = _coalesce(
        overrides.get("ssh_hostname"),
        env.get("MORPH_SSH_HOSTNAME"),
        profile_data.get("ssh_hostname"),
    )
    ssh_port = _coalesce(
        _parse_int(overrides.get("ssh_port")),
        _parse_int(env.get("MORPH_SSH_PORT")),
        _parse_int(profile_data.get("ssh_port")),
    )
    service_base_url = _coalesce(
        overrides.get("service_base_url"),
        env.get("MORPH_SERVICE_BASE_URL"),
        profile_data.get("service_base_url"),
    )
    admin_base_url = _coalesce(
        overrides.get("admin_base_url"),
        env.get("MORPH_ADMIN_BASE_URL"),
        profile_data.get("admin_base_url"),
    )
    db_base_url = _coalesce(
        overrides.get("db_base_url"),
        env.get("MORPH_DB_BASE_URL"),
        profile_data.get("db_base_url"),
    )

    if not api_host:
        api_host = _api_host_from_base_url(base_url)

    if api_host:
        if not base_url:
            base_url = f"https://{api_host}/api"
        if not ssh_hostname:
            ssh_hostname = f"ssh.{api_host}"
        if not service_base_url:
            service_base_url = f"https://service.svc.{api_host}"
        if not admin_base_url:
            admin_base_url = f"https://admin.svc.{api_host}"
        if not db_base_url:
            db_base_url = f"https://db.svc.{api_host}"

    base_url = base_url or DEFAULT_BASE_URL
    ssh_hostname = ssh_hostname or DEFAULT_SSH_HOSTNAME
    ssh_port = ssh_port or DEFAULT_SSH_PORT
    service_base_url = service_base_url or DEFAULT_SERVICE_BASE_URL
    admin_base_url = admin_base_url or DEFAULT_ADMIN_BASE_URL
    db_base_url = db_base_url or DEFAULT_DB_BASE_URL

    if not api_host:
        api_host = _api_host_from_base_url(base_url) or DEFAULT_API_HOST

    return ResolvedSettings(
        profile=profile_name,
        api_key=api_key,
        base_url=base_url,
        ssh_hostname=ssh_hostname,
        ssh_port=int(ssh_port),
        api_host=api_host,
        service_base_url=service_base_url,
        admin_base_url=admin_base_url,
        db_base_url=db_base_url,
    )


__all__ = [
    "ResolvedSettings",
    "load_config",
    "save_config",
    "get_config_path",
    "resolve_profile",
    "resolve_settings",
]
