from __future__ import annotations

import re
import typing as _t
from dataclasses import dataclass

from morphcloud.devbox.gen.types.tmux_install_response import TmuxInstallResponse
from morphcloud.devbox.gen.types.tmux_new_session_response import TmuxNewSessionResponse
from morphcloud.devbox.gen.types.tmux_session import TmuxSession


def sh_quote(value: str) -> str:
    """Best-effort POSIX shell quoting using single quotes."""

    return "'" + value.replace("'", "'\\''") + "'"


def sanitize_tmux_session_name(value: str) -> str:
    """
    Sanitize a tmux session name to a conservative character set.

    Matches frontend-v2 behavior (replace disallowed chars with underscores).
    """

    trimmed = (value or "").strip()
    if not trimmed:
        return ""
    return re.sub(r"[^A-Za-z0-9_-]", "_", trimmed)


def build_tmux_attach_command(
    session_name: str, initial_command: str | None = None
) -> str:
    """
    Build an attach-or-create command for tmux.

    Mirrors frontend-v2's `buildTmuxAttachCommand`:
    - No initial command: `tmux new-session -A -s '<session>'`
    - With initial command: `tmux new-session -A -s '<session>' '<cmd>'`
    """

    session = (session_name or "").strip()
    if not session:
        return ""

    command = (initial_command or "").strip()
    if not command:
        return f"tmux new-session -A -s {sh_quote(session)}"
    return f"tmux new-session -A -s {sh_quote(session)} {sh_quote(command)}"


def _parse_optional_bool_header(
    headers: _t.Mapping[str, str], name: str
) -> bool | None:
    for key, value in (headers or {}).items():
        if key.lower() != name.lower():
            continue
        raw = (value or "").strip().lower()
        if raw in {"true", "1", "yes"}:
            return True
        if raw in {"false", "0", "no"}:
            return False
        return None
    return None


@dataclass(frozen=True)
class TerminalListResult:
    sessions: list[TmuxSession]
    tmux_installed: bool | None = None

    def model_dump(self) -> dict[str, _t.Any]:
        def _dump(obj: _t.Any) -> _t.Any:
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            if hasattr(obj, "dict"):
                return obj.dict()
            return obj

        return {
            "tmux_installed": self.tmux_installed,
            "sessions": [_dump(s) for s in self.sessions],
        }


@dataclass(frozen=True)
class TerminalStartResult:
    session: TmuxSession
    install: TmuxInstallResponse | None = None

    def model_dump(self) -> dict[str, _t.Any]:
        def _dump(obj: _t.Any) -> _t.Any:
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            if hasattr(obj, "dict"):
                return obj.dict()
            return obj

        return {
            "install": _dump(self.install) if self.install is not None else None,
            "session": _dump(self.session),
        }


class DevboxTerminals:
    """First-class devbox "terminals" (tmux sessions) for the sync devbox client."""

    def __init__(self, devbox_client: _t.Any):
        self._client = devbox_client

    def list(self, devbox_id: str, *, socket: str | None = None) -> TerminalListResult:
        response = self._client.tmux.with_raw_response.list_tmux_sessions(
            devbox_id, socket=socket
        )
        try:
            tmux_installed = _parse_optional_bool_header(
                getattr(response, "headers", {}) or {}, "x-tmux-installed"
            )
            sessions = list(getattr(getattr(response, "data", None), "data", []) or [])
            return TerminalListResult(sessions=sessions, tmux_installed=tmux_installed)
        finally:
            try:
                response.close()
            except Exception:
                pass

    def start(
        self,
        devbox_id: str,
        *,
        name: str,
        ensure_tmux: bool = True,
        detached: bool = True,
    ) -> TerminalStartResult:
        install: TmuxInstallResponse | None = None
        if ensure_tmux:
            install = self._client.tmux.tmux_install(devbox_id)

        result: TmuxNewSessionResponse = self._client.tmux.tmux_new_session(
            devbox_id, name=name, detached=detached
        )
        return TerminalStartResult(session=result.session, install=install)


class AsyncDevboxTerminals:
    """First-class devbox "terminals" (tmux sessions) for the async devbox client."""

    def __init__(self, devbox_client: _t.Any):
        self._client = devbox_client

    async def list(
        self, devbox_id: str, *, socket: str | None = None
    ) -> TerminalListResult:
        response = await self._client.tmux.with_raw_response.list_tmux_sessions(
            devbox_id, socket=socket
        )
        try:
            tmux_installed = _parse_optional_bool_header(
                getattr(response, "headers", {}) or {}, "x-tmux-installed"
            )
            sessions = list(getattr(getattr(response, "data", None), "data", []) or [])
            return TerminalListResult(sessions=sessions, tmux_installed=tmux_installed)
        finally:
            try:
                await response.close()
            except Exception:
                pass

    async def start(
        self,
        devbox_id: str,
        *,
        name: str,
        ensure_tmux: bool = True,
        detached: bool = True,
    ) -> TerminalStartResult:
        install: TmuxInstallResponse | None = None
        if ensure_tmux:
            install = await self._client.tmux.tmux_install(devbox_id)

        result: TmuxNewSessionResponse = await self._client.tmux.tmux_new_session(
            devbox_id, name=name, detached=detached
        )
        return TerminalStartResult(session=result.session, install=install)
