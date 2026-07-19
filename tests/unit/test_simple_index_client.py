import json
import types

import httpx
import pytest

from morphcloud.api import ApiError
from morphcloud.simple_index.client import SimpleIndexClient


def _sdk_client(api_key="secret", base_url="https://simple-index.example.test"):
    return types.SimpleNamespace(
        api_key=api_key,
        simple_index_base_url=base_url,
    )


def test_simple_index_client_lists_plugins_with_bearer_auth():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "object": "list",
                "data": [
                    {
                        "name": "intro",
                        "package_name": "morphcloud-intro",
                        "version_spec": "==1.2.3",
                        "entry_point": "morphcloud_intro:register_cli",
                        "command_name": "intro",
                        "visibility": "org",
                        "organization_id": "org_1",
                        "source": "org:org_1",
                    }
                ],
            },
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    entries = client.list_plugins()

    assert len(entries) == 1
    assert entries[0].name == "intro"
    assert entries[0].install_requirement == "morphcloud-intro==1.2.3"
    assert entries[0].to_dict()["source"] == "org:org_1"
    assert seen[0].headers["authorization"] == "Bearer secret"


def test_simple_index_client_supports_legacy_package_field():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/api/v1/plugins/demo":
            return httpx.Response(404, text="not found")
        return httpx.Response(
            200,
            json={"data": [{"name": "demo", "package": "morphcloud-demo"}]},
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    entry = client.get_plugin("demo")

    assert entry.package_name == "morphcloud-demo"
    assert entry.install_requirement == "morphcloud-demo"
    assert [request.url.path for request in requests] == [
        "/api/v1/plugins/demo",
        "/api/v1/plugins",
    ]


def test_simple_index_client_get_plugin_uses_direct_show_endpoint():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "name": "intro",
                "package_name": "morphcloud-intro",
                "version_spec": "==1.2.3",
                "visibility": "org",
                "organization_id": "org_1",
            },
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    entry = client.get_plugin("intro")

    assert entry.name == "intro"
    assert entry.install_requirement == "morphcloud-intro==1.2.3"
    assert entry.visibility == "org"
    assert [request.url.path for request in seen] == ["/api/v1/plugins/intro"]


def test_simple_index_client_supports_artifact_url_install_target():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/api/v1/plugins/demo":
            return httpx.Response(404, text="not found")
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "name": "demo",
                        "artifact_url": "https://artifacts.example.test/demo.whl",
                    }
                ]
            },
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    entry = client.get_plugin("demo")

    assert entry.package_name is None
    assert entry.artifact_url == "https://artifacts.example.test/demo.whl"
    assert entry.install_requirement is None
    assert entry.install_target == "https://artifacts.example.test/demo.whl"
    assert entry.to_dict()["artifact_url"] == "https://artifacts.example.test/demo.whl"
    assert [request.url.path for request in requests] == [
        "/api/v1/plugins/demo",
        "/api/v1/plugins",
    ]


def test_simple_index_client_authenticated_index_url_redacts_secret():
    client = SimpleIndexClient(_sdk_client(api_key="key/with spaces"))

    authenticated = client.authenticated_simple_index_url()
    redacted = client.redacted_simple_index_url()

    assert authenticated == (
        "https://__token__:key%2Fwith%20spaces@simple-index.example.test/simple/"
    )
    assert redacted == "https://simple-index.example.test/simple/"
    assert "key/with spaces" not in redacted


def test_simple_index_client_scope_mutations_add_query_parameters():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "name": "intro",
                "package_name": "morphcloud-intro",
                "version": "1.0.0",
            },
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    client.upsert_plugin(
        "intro",
        {"name": "intro", "package_name": "morphcloud-intro", "version": "1.0.0"},
        visibility="org",
        organization_id="org_1",
    )
    client.disable_plugin("intro", visibility="global")
    client.delete_plugin("intro", visibility="org", organization_id="org_1")
    client.disable_plugin("intro", organization_id="org_2")

    assert requests[0].method == "PUT"
    assert requests[0].url.path == "/api/v1/plugins/intro"
    assert requests[0].url.query == b"visibility=org&organization_id=org_1"
    assert requests[1].method == "POST"
    assert requests[1].url.path == "/api/v1/plugins/intro/disable"
    assert requests[1].url.query == b"visibility=global"
    assert requests[2].method == "DELETE"
    assert requests[2].url.query == b"visibility=org&organization_id=org_1"
    assert requests[3].method == "POST"
    assert requests[3].url.query == b"visibility=org&organization_id=org_2"


def test_simple_index_client_rejects_invalid_scope_options():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"name": "intro"})

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(ValueError, match="organization_id is required"):
        client.upsert_plugin(
            "intro",
            {"name": "intro", "package_name": "morphcloud-intro"},
            visibility="org",
        )

    with pytest.raises(ValueError, match="cannot be used"):
        client.delete_plugin(
            "intro",
            visibility="global",
            organization_id="org_1",
        )

    assert requests == []


def test_simple_index_client_uploads_package_wheel_with_scope(tmp_path):
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel-bytes")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            201,
            json={
                "project": "morphcloud-demo",
                "filename": wheel.name,
                "visibility": "org",
                "organization_id": "org_1",
            },
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    payload = client.upload_package(
        wheel,
        project="morphcloud-demo",
        allow_overwrite=True,
        visibility="org",
        organization_id="org_1",
    )

    assert payload["filename"] == wheel.name
    assert payload["visibility"] == "org"
    assert requests[0].method == "POST"
    assert requests[0].url.path == "/api/v1/packages"
    assert requests[0].url.query == (
        b"project=morphcloud-demo&allow_overwrite=true&"
        b"visibility=org&organization_id=org_1"
    )
    assert requests[0].headers["content-type"] == "application/octet-stream"
    assert requests[0].headers["x-filename"] == wheel.name
    assert requests[0].content == b"wheel-bytes"


def test_simple_index_client_manages_package_lifecycle():
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(
            200,
            json={
                "project": "morphcloud-demo",
                "filename": "morphcloud_demo-1.2.3-py3-none-any.whl",
                "yanked": True,
                "yank_reason": "bad build",
            },
        )

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    payload = client.yank_package(
        "morphcloud-demo",
        "morphcloud_demo-1.2.3-py3-none-any.whl",
        reason="bad build",
        visibility="org",
        organization_id="org_1",
    )
    client.delete_package(
        "morphcloud-demo",
        "morphcloud_demo-1.2.3-py3-none-any.whl",
        visibility="global",
    )

    assert payload["yank_reason"] == "bad build"
    assert requests[0].method == "POST"
    assert (
        requests[0].url.path
        == "/api/v1/packages/morphcloud-demo/morphcloud_demo-1.2.3-py3-none-any.whl/yank"
    )
    assert requests[0].url.query == b"visibility=org&organization_id=org_1"
    assert json.loads(requests[0].content) == {"reason": "bad build"}
    assert requests[1].method == "DELETE"
    assert (
        requests[1].url.path
        == "/api/v1/packages/morphcloud-demo/morphcloud_demo-1.2.3-py3-none-any.whl"
    )
    assert requests[1].url.query == b"visibility=global"


def test_simple_index_client_package_mutations_reject_invalid_scope(tmp_path):
    wheel = tmp_path / "morphcloud_demo-1.2.3-py3-none-any.whl"
    wheel.write_bytes(b"wheel-bytes")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={})

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(ValueError, match="organization_id is required"):
        client.upload_package(wheel, visibility="org")

    with pytest.raises(ValueError, match="cannot be used"):
        client.yank_package(
            "morphcloud-demo",
            "morphcloud_demo-1.2.3-py3-none-any.whl",
            visibility="global",
            organization_id="org_1",
        )

    assert requests == []


def test_simple_index_client_raises_api_error_on_error_response():
    def handler(request):
        return httpx.Response(403, text="forbidden")

    client = SimpleIndexClient(
        _sdk_client(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(ApiError) as excinfo:
        client.list_packages()

    assert excinfo.value.status_code == 403
    assert "forbidden" in excinfo.value.response_body


def test_simple_index_client_redacts_error_response_secrets():
    def handler(request):
        del request
        return httpx.Response(
            403,
            text=(
                "bad api-secret "
                "https://artifacts.example.test/demo.whl?token=url-secret"
            ),
        )

    client = SimpleIndexClient(
        _sdk_client(api_key="api-secret"),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(ApiError) as excinfo:
        client.list_packages()

    message = str(excinfo.value)
    assert "api-secret" not in message
    assert "url-secret" not in message
    assert "<redacted>" in message
