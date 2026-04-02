import types

import pytest

from morphcloud.api import ApiError
from morphcloud.volumes.client import VolumesClient


class StubResponse:
    def __init__(
        self,
        *,
        status_code=200,
        json_data=None,
        text="",
        content=b"",
        headers=None,
        url="https://volumes.svc.stage.morph.so/",
    ):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.content = content or text.encode("utf-8")
        self.headers = headers or {}
        self.url = url

    @property
    def is_error(self):
        return self.status_code >= 400

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON payload configured")
        return self._json_data


class StubHTTPClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, content=None, json=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "content": content,
                "json": json,
            }
        )
        if not self.responses:
            raise AssertionError("No stub responses left")
        return self.responses.pop(0)


def _build_client(
    *,
    s3_responses=(),
    json_responses=(),
    volumes_service_api_key="morph_service_key",
):
    morph_client = types.SimpleNamespace(
        api_key="morph_test_key",
        base_url="https://cloud.morph.so/api",
        service_base_url="https://service.svc.stage.morph.so",
        volumes_base_url="https://volumes.svc.stage.morph.so",
        volumes_service_api_key=volumes_service_api_key,
    )
    client = VolumesClient(morph_client)
    client._http_client = StubHTTPClient(s3_responses)
    client._json_client = StubHTTPClient(json_responses)
    return client


def test_list_buckets_parses_xml():
    client = _build_client(s3_responses=[StubResponse(text="""
            <ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Buckets>
                <Bucket>
                  <Name>beta</Name>
                  <CreationDate>2026-04-02T00:00:00Z</CreationDate>
                </Bucket>
                <Bucket>
                  <Name>alpha</Name>
                  <CreationDate>2026-04-01T00:00:00Z</CreationDate>
                </Bucket>
              </Buckets>
            </ListAllMyBucketsResult>
            """)])

    buckets = client.list_buckets()

    assert [bucket.name for bucket in buckets] == ["alpha", "beta"]
    assert buckets[0].created_at == "2026-04-01T00:00:00Z"


def test_create_bucket_uses_service_api_and_active_org():
    client = _build_client(
        json_responses=[
            StubResponse(
                json_data={
                    "organization_id": "organization_demo",
                    "organization": {"id": "organization_demo"},
                },
                url="https://cloud.morph.so/api/orgs/active",
            ),
            StubResponse(
                json_data={
                    "volume": {
                        "name": "demo",
                        "created_at": "2026-04-06T00:00:00Z",
                    }
                },
                url="https://service.svc.stage.morph.so/service/volume",
            ),
        ]
    )

    bucket = client.create_bucket("demo")

    assert bucket.name == "demo"
    assert bucket.created_at == "2026-04-06T00:00:00Z"
    assert client._json_client.calls[0]["method"] == "GET"
    assert client._json_client.calls[0]["url"].endswith("/orgs/active")
    assert client._json_client.calls[0]["headers"]["Authorization"] == (
        "Bearer morph_test_key"
    )
    assert client._json_client.calls[1]["method"] == "POST"
    assert client._json_client.calls[1]["url"].endswith("/service/volume")
    assert client._json_client.calls[1]["headers"]["Authorization"] == (
        "Bearer morph_service_key"
    )
    assert client._json_client.calls[1]["headers"]["X-Morph-Organization-ID"] == (
        "organization_demo"
    )
    assert client._json_client.calls[1]["json"] == {"name": "demo"}


def test_create_bucket_requires_service_api_key():
    client = _build_client(volumes_service_api_key="")

    with pytest.raises(ValueError) as excinfo:
        client.create_bucket("demo")

    assert "MORPH_VOLUMES_SERVICE_API_KEY" in str(excinfo.value)


def test_list_directory_derives_prefixes_from_flat_listing():
    client = _build_client(s3_responses=[StubResponse(text="""
            <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <IsTruncated>false</IsTruncated>
              <Contents>
                <Key>assets/logo.svg</Key>
                <LastModified>2026-04-02T00:00:00Z</LastModified>
                <ETag>"etag-1"</ETag>
                <Size>11</Size>
                <StorageClass>STANDARD</StorageClass>
              </Contents>
              <Contents>
                <Key>assets/icons/app.svg</Key>
                <LastModified>2026-04-02T00:00:01Z</LastModified>
                <ETag>"etag-2"</ETag>
                <Size>12</Size>
                <StorageClass>STANDARD</StorageClass>
              </Contents>
              <Contents>
                <Key>readme.txt</Key>
                <LastModified>2026-04-02T00:00:02Z</LastModified>
                <ETag>"etag-3"</ETag>
                <Size>13</Size>
                <StorageClass>STANDARD</StorageClass>
              </Contents>
            </ListBucketResult>
            """)])

    listing = client.list_directory("demo")

    assert [prefix.name for prefix in listing.prefixes] == ["assets"]
    assert [obj.name for obj in listing.objects] == ["readme.txt"]
    assert listing.objects[0].key == "readme.txt"


def test_head_object_returns_none_on_404():
    client = _build_client(
        s3_responses=[
            StubResponse(
                status_code=404,
                text=(
                    "<Error><Code>NoSuchKey</Code>"
                    "<Message>The specified key does not exist.</Message></Error>"
                ),
                url="https://volumes.svc.stage.morph.so/demo/missing.txt",
            )
        ]
    )

    assert client.head_object("demo", "missing.txt") is None


def test_delete_bucket_raises_api_error_with_readable_message():
    client = _build_client(
        s3_responses=[
            StubResponse(
                status_code=409,
                text=(
                    "<Error><Code>BucketNotEmpty</Code>"
                    "<Message>The bucket you tried to delete is not empty.</Message></Error>"
                ),
                url="https://volumes.svc.stage.morph.so/demo",
            )
        ]
    )

    with pytest.raises(ApiError) as excinfo:
        client.delete_bucket("demo")

    assert excinfo.value.status_code == 409
    assert "BucketNotEmpty" in excinfo.value.response_body
