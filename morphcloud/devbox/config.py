from __future__ import annotations

import typing as _t

from morphcloud.config import ResolvedSettings, resolve_settings


def resolve_devbox_settings(*, profile: _t.Optional[str] = None) -> ResolvedSettings:
    """
    Resolve settings relevant to devbox operations.

    This is a thin wrapper around `morphcloud.config.resolve_settings` to keep
    devbox-related configuration in one place without mutating process env.
    """

    return resolve_settings(profile=profile)


def get_devbox_base_url(*, profile: _t.Optional[str] = None) -> str:
    return resolve_devbox_settings(profile=profile).devbox_base_url


def get_ssh_hostname(*, profile: _t.Optional[str] = None) -> str:
    return resolve_devbox_settings(profile=profile).ssh_hostname


def get_ssh_port(*, profile: _t.Optional[str] = None) -> int:
    return resolve_devbox_settings(profile=profile).ssh_port
