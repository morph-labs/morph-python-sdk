from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import typing
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, quote, unquote, urlsplit

import httpx
from pydantic import BaseModel, Field

from morphcloud._http_transport import build_http_transport
from morphcloud.api import ApiError, MorphCloudClient

DEFAULT_VOLUMES_REGION = "us-east-1"
DEFAULT_VOLUMES_SERVICE = "s3"
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


class VolumeBucket(BaseModel):
    name: str
    created_at: str | None = None


class VolumePrefix(BaseModel):
    name: str
    prefix: str


class VolumeObject(BaseModel):
    key: str
    name: str
    size: int = 0
    last_modified: str | None = None
    etag: str | None = None
    storage_class: str | None = None
    content_type: str | None = None


class VolumeListing(BaseModel):
    bucket: str
    prefix: str = ""
    prefixes: list[VolumePrefix] = Field(default_factory=list)
    objects: list[VolumeObject] = Field(default_factory=list)
    is_truncated: bool = False
    next_continuation_token: str | None = None
    key_count: int = 0


def validate_bucket_name(name: str) -> None:
    normalized = str(name or "").strip()
    if not normalized:
        raise ValueError("Bucket name is required.")
    if (
        not _BUCKET_NAME_RE.fullmatch(normalized)
        or ".." in normalized
        or ".-" in normalized
        or "-." in normalized
    ):
        raise ValueError(
            "Bucket names must be 3-63 characters using lower-case letters, numbers, dots, and hyphens."
        )


def _normalize_bucket(name: str) -> str:
    normalized = str(name or "").strip()
    validate_bucket_name(normalized)
    return normalized


def _normalize_key(key: str | None) -> str:
    return str(key or "").strip().lstrip("/")


def _normalize_prefix(prefix: str | None) -> str:
    normalized = _normalize_key(prefix)
    if not normalized:
        return ""
    return normalized if normalized.endswith("/") else f"{normalized}/"


def _basename(value: str) -> str:
    parts = [part for part in str(value or "").rstrip("/").split("/") if part]
    return parts[-1] if parts else str(value or "")


def _encode_rfc3986(value: str) -> str:
    return quote(value, safe="-_.~")


def _timestamp_parts(now: dt.datetime | None = None) -> tuple[str, str]:
    current = now or dt.datetime.now(dt.timezone.utc)
    iso = current.strftime("%Y%m%dT%H%M%SZ")
    return iso, iso[:8]


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hmac_sha256(key: bytes | str, value: str) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def _build_signing_key(api_key: str, date_stamp: str) -> bytes:
    date_key = _hmac_sha256(f"AWS4{api_key}", date_stamp)
    region_key = _hmac_sha256(date_key, DEFAULT_VOLUMES_REGION)
    service_key = _hmac_sha256(region_key, DEFAULT_VOLUMES_SERVICE)
    return _hmac_sha256(service_key, "aws4_request")


def _canonicalize_uri(path: str) -> str:
    if not path or path == "/":
        return "/"
    return "/".join(_encode_rfc3986(unquote(segment)) for segment in path.split("/"))


def _canonicalize_query(query: str) -> str:
    pairs = [
        (_encode_rfc3986(key), _encode_rfc3986(value))
        for key, value in parse_qsl(query, keep_blank_values=True)
    ]
    pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(f"{key}={value}" for key, value in pairs)


def _first_text(element: ET.Element, tag_name: str) -> str | None:
    node = element.find(f".//{{*}}{tag_name}")
    if node is None or node.text is None:
        return None
    text = node.text.strip()
    return text or None


def _first_bool(element: ET.Element, tag_name: str) -> bool:
    return (_first_text(element, tag_name) or "").strip().lower() == "true"


def _sort_by_name(items: list[typing.Any]) -> list[typing.Any]:
    return sorted(items, key=lambda item: str(getattr(item, "name", "")).casefold())


def _parse_xml(xml: str) -> ET.Element:
    try:
        return ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError("Failed to parse volumes XML response.") from exc


def _parse_error_body(body: str) -> str:
    cleaned = body.strip()
    if not cleaned:
        return "Unknown error"

    try:
        payload = json.loads(cleaned)
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        for key in ("detail", "error", "message"):
            value = payload.get(key)
            if value:
                return str(value)

    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return cleaned

    code = _first_text(root, "Code")
    message = _first_text(root, "Message")
    if code and message:
        return f"{code}: {message}"
    return message or code or cleaned or "Unknown error"


class VolumesClient:
    def __init__(self, client: MorphCloudClient):
        self._client = client
        self.base_url = str(client.volumes_base_url or "").rstrip("/")
        transport = build_http_transport()
        self._http_client = httpx.Client(
            timeout=None,
            transport=transport,
        )

    def _compose_url(
        self,
        *,
        bucket: str | None = None,
        key: str | None = None,
        query: typing.Mapping[str, typing.Any] | None = None,
    ) -> str:
        path_segments: list[str] = []
        if bucket:
            path_segments.append(_normalize_bucket(bucket))
        if key:
            path_segments.extend(
                segment for segment in _normalize_key(key).split("/") if segment
            )

        if path_segments:
            path = "/" + "/".join(_encode_rfc3986(segment) for segment in path_segments)
        else:
            path = "/"

        query_pairs: list[tuple[str, str]] = []
        for raw_key, raw_value in dict(query or {}).items():
            if raw_value is None:
                continue
            query_pairs.append(
                (_encode_rfc3986(str(raw_key)), _encode_rfc3986(str(raw_value)))
            )
        query_pairs.sort(key=lambda item: (item[0], item[1]))
        query_string = "&".join(f"{key}={value}" for key, value in query_pairs)
        if query_string:
            return f"{self.base_url}{path}?{query_string}"
        return f"{self.base_url}{path}"

    def _signed_headers(
        self,
        method: str,
        url: str,
        *,
        accept: str | None = None,
        content_type: str | None = None,
        payload_hash: str = UNSIGNED_PAYLOAD,
    ) -> dict[str, str]:
        parsed = urlsplit(url)
        amz_date, date_stamp = _timestamp_parts()
        canonical_headers = (
            f"host:{parsed.netloc}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = "\n".join(
            [
                method.upper(),
                _canonicalize_uri(parsed.path),
                _canonicalize_query(parsed.query),
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )
        credential_scope = f"{date_stamp}/{DEFAULT_VOLUMES_REGION}/{DEFAULT_VOLUMES_SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                credential_scope,
                _sha256_hex(canonical_request),
            ]
        )
        signature = hmac.new(
            _build_signing_key(self._client.api_key, date_stamp),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        authorization = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self._client.api_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
        headers = {
            "Authorization": authorization,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if accept:
            headers["Accept"] = accept
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _request(
        self,
        method: str,
        url: str,
        *,
        accept: str | None = None,
        content_type: str | None = None,
        data: bytes | None = None,
    ) -> httpx.Response:
        response = self._http_client.request(
            method=method.upper(),
            url=url,
            headers=self._signed_headers(
                method,
                url,
                accept=accept,
                content_type=content_type,
            ),
            content=data,
        )
        if response.is_error:
            raise ApiError(
                f"Volumes request failed for url '{response.url}'",
                response.status_code,
                _parse_error_body(response.text),
            )
        return response

    def list_buckets(self) -> list[VolumeBucket]:
        response = self._request(
            "GET",
            self._compose_url(),
            accept="application/xml, text/xml;q=0.9, */*;q=0.8",
        )
        root = _parse_xml(response.text)
        buckets = [
            VolumeBucket(
                name=_first_text(bucket_node, "Name") or "",
                created_at=_first_text(bucket_node, "CreationDate"),
            )
            for bucket_node in root.findall(".//{*}Bucket")
        ]
        buckets = [bucket for bucket in buckets if bucket.name]
        return _sort_by_name(buckets)

    def create_bucket(self, bucket: str) -> VolumeBucket:
        normalized_bucket = _normalize_bucket(bucket)
        self._request(
            "PUT",
            self._compose_url(bucket=normalized_bucket),
        )
        return VolumeBucket(
            name=normalized_bucket,
            created_at=None,
        )

    def delete_bucket(self, bucket: str) -> None:
        normalized_bucket = _normalize_bucket(bucket)
        self._request(
            "DELETE",
            self._compose_url(bucket=normalized_bucket),
            accept="application/xml, text/xml;q=0.9, */*;q=0.8",
        )

    def head_object(self, bucket: str, key: str) -> VolumeObject | None:
        normalized_bucket = _normalize_bucket(bucket)
        normalized_key = _normalize_key(key)
        if not normalized_key:
            raise ValueError("Object key is required.")

        try:
            response = self._request(
                "HEAD",
                self._compose_url(bucket=normalized_bucket, key=normalized_key),
                accept="*/*",
            )
        except ApiError as exc:
            if exc.status_code == 404:
                return None
            raise

        size_header = response.headers.get("content-length")
        try:
            size = int(size_header or "0")
        except ValueError:
            size = 0

        return VolumeObject(
            key=normalized_key,
            name=_basename(normalized_key),
            size=size,
            last_modified=response.headers.get("last-modified"),
            etag=response.headers.get("etag"),
            storage_class=response.headers.get("x-amz-storage-class"),
            content_type=response.headers.get("content-type"),
        )

    def get_object(self, bucket: str, key: str) -> bytes:
        normalized_bucket = _normalize_bucket(bucket)
        normalized_key = _normalize_key(key)
        if not normalized_key:
            raise ValueError("Object key is required.")
        response = self._request(
            "GET",
            self._compose_url(bucket=normalized_bucket, key=normalized_key),
            accept="*/*",
        )
        return response.content

    def put_object(
        self,
        bucket: str,
        key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> VolumeObject:
        normalized_bucket = _normalize_bucket(bucket)
        normalized_key = _normalize_key(key)
        if not normalized_key:
            raise ValueError("Object key is required.")
        self._request(
            "PUT",
            self._compose_url(bucket=normalized_bucket, key=normalized_key),
            accept="application/xml, text/xml;q=0.9, */*;q=0.8",
            content_type=content_type,
            data=data,
        )
        return VolumeObject(
            key=normalized_key,
            name=_basename(normalized_key),
            size=len(data),
            content_type=content_type,
        )

    def delete_object(self, bucket: str, key: str) -> None:
        normalized_bucket = _normalize_bucket(bucket)
        normalized_key = _normalize_key(key)
        if not normalized_key:
            raise ValueError("Object key is required.")
        self._request(
            "DELETE",
            self._compose_url(bucket=normalized_bucket, key=normalized_key),
            accept="application/xml, text/xml;q=0.9, */*;q=0.8",
        )

    def list_all_objects(
        self,
        bucket: str,
        *,
        prefix: str | None = None,
        max_keys: int = 1000,
    ) -> list[VolumeObject]:
        normalized_bucket = _normalize_bucket(bucket)
        normalized_prefix = _normalize_key(prefix)
        continuation_token: str | None = None
        objects: list[VolumeObject] = []

        while True:
            query: dict[str, typing.Any] = {
                "list-type": "2",
                "max-keys": str(max(1, min(int(max_keys), 1000))),
            }
            if normalized_prefix:
                query["prefix"] = normalized_prefix
            if continuation_token:
                query["continuation-token"] = continuation_token

            response = self._request(
                "GET",
                self._compose_url(bucket=normalized_bucket, query=query),
                accept="application/xml, text/xml;q=0.9, */*;q=0.8",
            )
            root = _parse_xml(response.text)

            for node in root.findall(".//{*}Contents"):
                key = _first_text(node, "Key")
                if not key:
                    continue

                try:
                    size = int(_first_text(node, "Size") or "0")
                except ValueError:
                    size = 0

                if key == normalized_prefix:
                    continue
                if key.endswith("/") and size == 0:
                    continue

                objects.append(
                    VolumeObject(
                        key=key,
                        name=_basename(key),
                        size=size,
                        last_modified=_first_text(node, "LastModified"),
                        etag=_first_text(node, "ETag"),
                        storage_class=_first_text(node, "StorageClass"),
                    )
                )

            is_truncated = _first_bool(root, "IsTruncated")
            continuation_token = _first_text(root, "NextContinuationToken")
            if not is_truncated or not continuation_token:
                break

        return sorted(objects, key=lambda item: item.key.casefold())

    def list_directory(
        self, bucket: str, *, prefix: str | None = None
    ) -> VolumeListing:
        normalized_bucket = _normalize_bucket(bucket)
        normalized_prefix = _normalize_prefix(prefix)
        all_objects = self.list_all_objects(
            normalized_bucket,
            prefix=normalized_prefix,
        )

        prefix_map: dict[str, VolumePrefix] = {}
        direct_objects: list[VolumeObject] = []

        for obj in all_objects:
            relative_key = obj.key
            if normalized_prefix and relative_key.startswith(normalized_prefix):
                relative_key = relative_key[len(normalized_prefix) :]
            relative_key = relative_key.lstrip("/")
            if not relative_key:
                continue

            separator_index = relative_key.find("/")
            if separator_index >= 0:
                name = relative_key[:separator_index]
                child_prefix = f"{normalized_prefix}{name}/"
                prefix_map.setdefault(
                    child_prefix,
                    VolumePrefix(name=name, prefix=child_prefix),
                )
                continue

            direct_objects.append(obj.model_copy(update={"name": relative_key}))

        prefixes = _sort_by_name(list(prefix_map.values()))
        objects = _sort_by_name(direct_objects)
        return VolumeListing(
            bucket=normalized_bucket,
            prefix=normalized_prefix,
            prefixes=prefixes,
            objects=objects,
            is_truncated=False,
            next_continuation_token=None,
            key_count=len(prefixes) + len(objects),
        )
