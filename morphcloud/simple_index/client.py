from __future__ import annotations

import mimetypes
import re
import typing
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from morphcloud._http_transport import build_http_transport
from morphcloud.api import ApiError

if typing.TYPE_CHECKING:
    from morphcloud.api import MorphCloudClient


BASIC_USERNAME = "__token__"


@dataclass(frozen=True)
class PluginCatalogEntry:
    name: str
    package_name: str | None = None
    version_spec: str | None = None
    artifact_url: str | None = None
    enabled: bool = True
    entry_point: str | None = None
    command_name: str | None = None
    visibility: str | None = None
    organization_id: str | None = None
    source: str | None = None
    manifest: dict[str, typing.Any] | None = None

    @classmethod
    def from_payload(
        cls, payload: typing.Mapping[str, typing.Any]
    ) -> "PluginCatalogEntry":
        manifest = dict(payload)
        return cls(
            name=str(payload.get("name") or ""),
            package_name=_clean_optional(
                payload.get("package_name") or payload.get("package")
            ),
            version_spec=_clean_optional(payload.get("version_spec")),
            artifact_url=_clean_optional(payload.get("artifact_url")),
            enabled=bool(payload.get("enabled", True)),
            entry_point=_clean_optional(payload.get("entry_point")),
            command_name=_clean_optional(payload.get("command_name")),
            visibility=_clean_optional(
                payload.get("visibility") or payload.get("scope")
            ),
            organization_id=_clean_optional(payload.get("organization_id")),
            source=_clean_optional(payload.get("source")),
            manifest=manifest,
        )

    @property
    def install_requirement(self) -> str | None:
        if not self.package_name:
            return None
        return f"{self.package_name}{self.version_spec or ''}"

    @property
    def install_target(self) -> str | None:
        return self.artifact_url or self.install_requirement

    def to_dict(self) -> dict[str, typing.Any]:
        data = dict(self.manifest or {})
        data.update(
            {
                "name": self.name,
                "package_name": self.package_name,
                "version_spec": self.version_spec,
                "artifact_url": self.artifact_url,
                "enabled": self.enabled,
                "entry_point": self.entry_point,
                "command_name": self.command_name,
                "visibility": self.visibility,
                "organization_id": self.organization_id,
                "source": self.source,
            }
        )
        return {key: value for key, value in data.items() if value is not None}


class SimpleIndexClient:
    def __init__(
        self,
        client: "MorphCloudClient",
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._client = client
        self.api_key = api_key or client.api_key
        self.base_url = str(base_url or client.simple_index_base_url or "").rstrip("/")
        self._http_client = http_client or httpx.Client(
            timeout=None,
            transport=build_http_transport(),
        )

    def list_plugins(self) -> list[PluginCatalogEntry]:
        payload = self._request_json("GET", "/api/v1/plugins")
        data = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(data, list):
            return []
        return [
            PluginCatalogEntry.from_payload(item)
            for item in data
            if isinstance(item, dict)
        ]

    def get_plugin(self, name: str) -> PluginCatalogEntry:
        normalized = _normalize_name(name)
        try:
            payload = self._request_json(
                "GET", f"/api/v1/plugins/{quote(normalized, safe='')}"
            )
        except ApiError as exc:
            if exc.status_code != 404:
                raise
        else:
            return PluginCatalogEntry.from_payload(payload)

        for item in self.list_plugins():
            if item.name == normalized:
                return item
        raise KeyError(normalized)

    def upsert_plugin(
        self,
        name: str,
        manifest: typing.Mapping[str, typing.Any],
        *,
        visibility: str | None = None,
        organization_id: str | None = None,
    ) -> PluginCatalogEntry:
        query = _scope_query(visibility=visibility, organization_id=organization_id)
        payload = self._request_json(
            "PUT",
            f"/api/v1/plugins/{quote(_normalize_name(name), safe='')}{query}",
            json=dict(manifest),
        )
        return PluginCatalogEntry.from_payload(payload)

    def disable_plugin(
        self,
        name: str,
        *,
        visibility: str | None = None,
        organization_id: str | None = None,
    ) -> PluginCatalogEntry:
        query = _scope_query(visibility=visibility, organization_id=organization_id)
        payload = self._request_json(
            "POST",
            f"/api/v1/plugins/{quote(_normalize_name(name), safe='')}/disable{query}",
            json={},
        )
        return PluginCatalogEntry.from_payload(payload)

    def delete_plugin(
        self,
        name: str,
        *,
        visibility: str | None = None,
        organization_id: str | None = None,
    ) -> None:
        query = _scope_query(visibility=visibility, organization_id=organization_id)
        self._request(
            "DELETE",
            f"/api/v1/plugins/{quote(_normalize_name(name), safe='')}{query}",
        )

    def list_packages(self) -> dict[str, typing.Any]:
        return self._request_json("GET", "/api/v1/packages")

    def upload_package(
        self,
        wheel: str | Path,
        *,
        project: str | None = None,
        allow_overwrite: bool = False,
        visibility: str | None = None,
        organization_id: str | None = None,
    ) -> dict[str, typing.Any]:
        wheel_path = Path(wheel)
        if not wheel_path.is_file():
            raise FileNotFoundError(str(wheel_path))
        query = _package_upload_query(
            project=project,
            allow_overwrite=allow_overwrite,
            visibility=visibility,
            organization_id=organization_id,
        )
        content_type = (
            mimetypes.guess_type(wheel_path.name)[0] or "application/octet-stream"
        )
        return self._request_json(
            "POST",
            f"/api/v1/packages{query}",
            content=wheel_path.read_bytes(),
            headers={
                "Content-Type": content_type,
                "X-Filename": wheel_path.name,
            },
        )

    def yank_package(
        self,
        project: str,
        filename: str,
        *,
        reason: str | None = None,
        visibility: str | None = None,
        organization_id: str | None = None,
    ) -> dict[str, typing.Any]:
        query = _scope_query(visibility=visibility, organization_id=organization_id)
        return self._request_json(
            "POST",
            f"/api/v1/packages/{quote(project, safe='')}/{quote(filename, safe='')}/yank{query}",
            json={"reason": reason or ""},
        )

    def delete_package(
        self,
        project: str,
        filename: str,
        *,
        visibility: str | None = None,
        organization_id: str | None = None,
    ) -> None:
        query = _scope_query(visibility=visibility, organization_id=organization_id)
        self._request(
            "DELETE",
            f"/api/v1/packages/{quote(project, safe='')}/{quote(filename, safe='')}{query}",
        )

    def authenticated_simple_index_url(self) -> str:
        if not self.api_key:
            raise ValueError(
                "MORPH_API_KEY is required for authenticated package index URLs"
            )
        parsed = urlsplit(f"{self.base_url}/simple/")
        username = quote(BASIC_USERNAME, safe="")
        password = quote(self.api_key, safe="")
        netloc = f"{username}:{password}@{parsed.netloc}"
        return urlunsplit(
            (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
        )

    def redacted_simple_index_url(self) -> str:
        parsed = urlsplit(f"{self.base_url}/simple/")
        netloc = parsed.netloc
        return urlunsplit(
            (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
        )

    def _request_json(
        self, method: str, path: str, **kwargs: typing.Any
    ) -> dict[str, typing.Any]:
        response = self._request(method, path, **kwargs)
        try:
            data = response.json()
        except ValueError as exc:
            raise ApiError(
                f"Invalid JSON response for {response.url}",
                response.status_code,
                response.text,
            ) from exc
        if not isinstance(data, dict):
            raise ApiError(
                f"Unexpected response shape for {response.url}",
                response.status_code,
                response.text,
            )
        return data

    def _request(self, method: str, path: str, **kwargs: typing.Any) -> httpx.Response:
        if not self.base_url:
            raise ValueError("simple-index base URL is not configured")
        if not self.api_key:
            raise ValueError("MORPH_API_KEY is required for simple-index requests")
        url = f"{self.base_url}{path}"
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("Accept", "application/json")
        headers["Authorization"] = f"Bearer {self.api_key}"
        response = self._http_client.request(
            method,
            url,
            headers=headers,
            **kwargs,
        )
        if response.is_error:
            raise ApiError(
                f"HTTP Error {response.status_code} for url '{response.url}'",
                response.status_code,
                _redact_text(response.text, [self.api_key]),
            )
        return response


def _normalize_name(name: str) -> str:
    normalized = str(name or "").strip()
    if not normalized:
        raise ValueError("plugin name is required")
    return normalized


def _scope_query(*, visibility: str | None, organization_id: str | None) -> str:
    visibility = _clean_optional(visibility)
    organization_id = _clean_optional(organization_id)
    visibility, organization_id = _validate_scope_options(
        visibility=visibility,
        organization_id=organization_id,
    )
    pairs = []
    if visibility:
        pairs.append(("visibility", visibility))
    if organization_id:
        pairs.append(("organization_id", organization_id))
    if not pairs:
        return ""
    return "?" + "&".join(
        f"{quote(str(key), safe='')}={quote(str(value), safe='')}"
        for key, value in pairs
    )


def _package_upload_query(
    *,
    project: str | None,
    allow_overwrite: bool,
    visibility: str | None,
    organization_id: str | None,
) -> str:
    visibility = _clean_optional(visibility)
    organization_id = _clean_optional(organization_id)
    visibility, organization_id = _validate_scope_options(
        visibility=visibility,
        organization_id=organization_id,
    )
    pairs: list[tuple[str, str]] = []
    project = _clean_optional(project)
    if project:
        pairs.append(("project", project))
    if allow_overwrite:
        pairs.append(("allow_overwrite", "true"))
    if visibility:
        pairs.append(("visibility", visibility))
    if organization_id:
        pairs.append(("organization_id", organization_id))
    if not pairs:
        return ""
    return "?" + "&".join(
        f"{quote(str(key), safe='')}={quote(str(value), safe='')}"
        for key, value in pairs
    )


def _clean_optional(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _redact_text(value: str, secrets: list[str | None]) -> str:
    rendered = _redact_urls_in_text(value)
    for secret in secrets:
        if secret:
            rendered = rendered.replace(secret, "<redacted>")
    return rendered


_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _redact_urls_in_text(value: str) -> str:
    return _URL_RE.sub(lambda match: _redact_url(match.group(0)), value)


def _redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if "://" not in value or not (
        "@" in parsed.netloc or parsed.query or parsed.fragment
    ):
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    netloc = f"<redacted>@{host}" if "@" in parsed.netloc else host
    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            "<redacted>" if parsed.query else "",
            "<redacted>" if parsed.fragment else "",
        )
    )


def _validate_scope_options(
    *, visibility: str | None, organization_id: str | None
) -> tuple[str | None, str | None]:
    if visibility is None and organization_id:
        visibility = "org"
    if visibility is not None and visibility not in {"global", "org"}:
        raise ValueError("visibility must be global or org")
    if visibility == "org" and not organization_id:
        raise ValueError("organization_id is required when visibility is org")
    if visibility == "global" and organization_id:
        raise ValueError("organization_id cannot be used when visibility is global")
    return visibility, organization_id
