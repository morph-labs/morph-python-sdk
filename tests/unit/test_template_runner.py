import json
import types

import httpx
import pytest

from morphcloud.devbox.client import DevboxClient
from morphcloud.devbox.template_runner import (
    BaseTemplatePresenter,
    PlainTemplatePresenter,
    SKIP_OPTIONAL_SECRET_TOKEN,
    SecretPromptState,
    SecretSubmission,
    TemplateRunOptions,
    TemplateRunState,
    TemplateRunnerError,
    TemplateTarget,
    TemplateWorkflowRunner,
    TemplateWorkflowTransport,
    USE_SAVED_SECRET_TOKEN,
)


class _StubPresenter(BaseTemplatePresenter):
    def __init__(self, submission: SecretSubmission | None = None):
        super().__init__(interactive=False)
        self.submission = submission
        self.events: list[str] = []

    def select_target(self, owned_templates, search_fn):
        raise AssertionError("select_target should not be called in these tests")

    def update(self, state, event=None):
        if event is not None:
            self.events.append(event.event_type)

    def prompt_for_secret(self, prompt, state):
        return self.submission


class _EventStream(httpx.SyncByteStream):
    def __init__(self, state):
        self._state = state

    def __iter__(self):
        yield (
            b'data: {"type":"awaiting_input","index":0,"secretName":"TOKEN",'
            b'"hasSaved":false,"optional":false,"defaultAction":"wait","runId":"run-1"}\n\n'
        )
        assert self._state["secret_submitted"] is True
        yield (
            b'data: {"type":"completed","instanceId":"devbox_123","instance":{"id":"devbox_123"}}\n\n'
        )


class _ByteStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __iter__(self):
        yield from self._chunks


def _json_response(status_code: int, payload, headers=None):
    return httpx.Response(
        status_code,
        json=payload,
        headers=headers,
    )


def _target(template_id: str = "tpl_123") -> TemplateTarget:
    return TemplateTarget(
        template_id=template_id,
        name="Template",
        description=None,
        status="ready",
        step_count=1,
        cached_step_count=0,
    )


def test_template_runner_resolves_alias_and_uses_instant_start_anonymously():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.headers["authorization"] == "Bearer service-key"
        if request.url.path == "/api/aliases/demo":
            return _json_response(
                200,
                {"alias": "demo", "template_id": "tpl_shared"},
            )
        if request.url.path == "/api/templates/shared/tpl_shared":
            return _json_response(
                200,
                {
                    "id": "tpl_shared",
                    "name": "Shared Template",
                    "status": "ready",
                    "step_count": 1,
                    "cached_step_count": 1,
                    "steps": [{"index": 0, "type": "command", "command": "echo hi"}],
                    "is_shared": True,
                },
            )
        if request.url.path == "/api/templates/tpl_shared/instant-devbox/availability":
            return _json_response(
                200,
                {"template_id": "tpl_shared", "available": True},
            )
        if request.url.path == "/api/templates/tpl_shared/instant-devbox":
            return _json_response(
                200,
                {
                    "id": "devbox_123",
                    "status": "ready",
                    "networking": {
                        "http_services": [
                            {
                                "name": "web",
                                "port": 3000,
                                "url": "https://web.example",
                            }
                        ]
                    },
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="service-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(None, devbox_client, anonymous=True)
    )

    result = runner.run(
        "demo",
        options=TemplateRunOptions(),
        presenter=_StubPresenter(),
    )

    assert result.status == "completed"
    assert result.mode == "instant"
    assert result.devbox_id == "devbox_123"
    assert result.exposed_services == (
        {
            "name": "web",
            "port": 3000,
            "url": "https://web.example",
            "auth_mode": None,
        },
    )
    assert requests == [
        ("GET", "/api/aliases/demo"),
        ("GET", "/api/templates/shared/tpl_shared"),
        ("GET", "/api/templates/tpl_shared/instant-devbox/availability"),
        ("POST", "/api/templates/tpl_shared/instant-devbox"),
    ]


def test_template_runner_submits_secret_with_shared_http_session():
    state = {"secret_submitted": False}
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path, request.headers.get("cookie")))
        if request.url.path == "/api/templates/shared/tpl_shared":
            return _json_response(
                200,
                {
                    "id": "tpl_shared",
                    "name": "Shared Template",
                    "status": "draft",
                    "step_count": 1,
                    "cached_step_count": 0,
                    "steps": [
                        {
                            "index": 0,
                            "type": "exportSecret",
                            "title": "Provide TOKEN",
                            "export_secret": {"name": "TOKEN"},
                        }
                    ],
                    "is_shared": True,
                },
            )
        if request.url.path == "/api/templates/tpl_shared/cache":
            return _json_response(
                202,
                {"run_id": "run-1"},
                headers={"set-cookie": "worker=alpha; Path=/"},
            )
        if request.url.path == "/api/templates/tpl_shared/events":
            assert request.headers.get("cookie") == "worker=alpha"
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_EventStream(state),
            )
        if request.url.path == "/api/templates/tpl_shared/cache/run-1/secrets":
            assert request.headers.get("cookie") == "worker=alpha"
            assert json.loads(request.content.decode("utf-8")) == {"TOKEN": "abc123"}
            state["secret_submitted"] = True
            return _json_response(200, {"ok": True})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="service-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(None, devbox_client, anonymous=True)
    )

    result = runner.run(
        "tpl_shared",
        options=TemplateRunOptions(force=True),
        presenter=_StubPresenter(SecretSubmission("abc123", False)),
    )

    assert result.status == "completed"
    assert result.mode == "build"
    assert result.devbox_id == "devbox_123"
    assert state["secret_submitted"] is True
    assert requests == [
        ("GET", "/api/templates/shared/tpl_shared", None),
        ("POST", "/api/templates/tpl_shared/cache", None),
        ("GET", "/api/templates/tpl_shared/events", "worker=alpha"),
        ("POST", "/api/templates/tpl_shared/cache/run-1/secrets", "worker=alpha"),
    ]


def test_template_runner_reconnects_and_skips_replayed_events():
    state = {"event_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/templates/tpl_owned":
            return _json_response(
                200,
                {
                    "id": "tpl_owned",
                    "name": "Owned Template",
                    "status": "draft",
                    "step_count": 1,
                    "cached_step_count": 0,
                    "steps": [{"index": 0, "type": "command", "command": "echo hi"}],
                },
            )
        if request.url.path == "/api/templates/tpl_owned/cache":
            return _json_response(
                202,
                {"run_id": "run-1"},
                headers={"set-cookie": "worker=alpha; Path=/"},
            )
        if request.url.path == "/api/templates/tpl_owned/events":
            state["event_calls"] += 1
            assert request.headers.get("cookie") == "worker=alpha"
            if state["event_calls"] == 1:
                chunks = [
                    b'data: {"type":"started"}\n\n',
                    b'data: {"type":"step_started","index":0}\n\n',
                    b'data: {"type":"output","index":0,"content":"hello\\n"}\n\n',
                ]
            else:
                chunks = [
                    b'data: {"type":"started"}\n\n',
                    b'data: {"type":"step_started","index":0}\n\n',
                    b'data: {"type":"output","index":0,"content":"hello\\n"}\n\n',
                    b'data: {"type":"cache","index":0}\n\n',
                    b'data: {"type":"step_completed","index":0}\n\n',
                    b'data: {"type":"completed","instanceId":"devbox_123","instance":{"id":"devbox_123"}}\n\n',
                ]
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_ByteStream(chunks),
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="user-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(types.SimpleNamespace(user=None), devbox_client)
    )
    presenter = _StubPresenter()

    result = runner.run(
        "tpl_owned",
        options=TemplateRunOptions(force=True),
        presenter=presenter,
    )

    assert result.status == "completed"
    assert result.devbox_id == "devbox_123"
    assert state["event_calls"] == 2
    assert presenter.events == [
        "started",
        "step_started",
        "output",
        "cache",
        "step_completed",
        "completed",
    ]


def test_template_runner_reconnects_after_divergent_replay_without_duplicate_steps():
    state = {"event_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/templates/tpl_owned":
            return _json_response(
                200,
                {
                    "id": "tpl_owned",
                    "name": "Owned Template",
                    "status": "draft",
                    "step_count": 2,
                    "cached_step_count": 0,
                    "steps": [
                        {"index": 0, "type": "command", "command": "echo first"},
                        {"index": 1, "type": "command", "command": "echo second"},
                    ],
                },
            )
        if request.url.path == "/api/templates/tpl_owned/cache":
            return _json_response(
                202,
                {"run_id": "run-1"},
                headers={"set-cookie": "worker=alpha; Path=/"},
            )
        if request.url.path == "/api/templates/tpl_owned/events":
            state["event_calls"] += 1
            assert request.headers.get("cookie") == "worker=alpha"
            if state["event_calls"] == 1:
                chunks = [
                    b'data: {"type":"started"}\n\n',
                    b'data: {"type":"step_started","index":0}\n\n',
                    b'data: {"type":"output","index":0,"content":"first\\n"}\n\n',
                    b'data: {"type":"step_completed","index":0}\n\n',
                    b'data: {"type":"step_started","index":1}\n\n',
                    b'data: {"type":"output","index":1,"content":"second\\n"}\n\n',
                ]
            else:
                chunks = [
                    b'data: {"type":"started"}\n\n',
                    b'data: {"type":"step_started","index":0}\n\n',
                    b'data: {"type":"cache","index":0}\n\n',
                    b'data: {"type":"step_completed","index":0}\n\n',
                    b'data: {"type":"step_started","index":1}\n\n',
                    b'data: {"type":"output","index":1,"content":"second\\n"}\n\n',
                    b'data: {"type":"step_completed","index":1}\n\n',
                    b'data: {"type":"completed","instanceId":"devbox_123","instance":{"id":"devbox_123"}}\n\n',
                ]
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_ByteStream(chunks),
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="user-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(types.SimpleNamespace(user=None), devbox_client)
    )
    presenter = _StubPresenter()

    result = runner.run(
        "tpl_owned",
        options=TemplateRunOptions(force=True),
        presenter=presenter,
    )

    assert result.status == "completed"
    assert result.devbox_id == "devbox_123"
    assert state["event_calls"] == 2
    assert presenter.events == [
        "started",
        "step_started",
        "output",
        "step_completed",
        "step_started",
        "output",
        "step_completed",
        "completed",
    ]


def test_template_runner_save_and_submit_secret_authenticated():
    state = {"secret_submitted": False, "saved": []}

    def create_secret(*, name, value):
        state["saved"].append((name, value))

    client_wrapper = types.SimpleNamespace(
        user=types.SimpleNamespace(create_secret=create_secret)
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/templates/tpl_owned":
            return _json_response(
                200,
                {
                    "id": "tpl_owned",
                    "name": "Owned Template",
                    "status": "draft",
                    "step_count": 1,
                    "cached_step_count": 0,
                    "steps": [
                        {
                            "index": 0,
                            "type": "exportSecret",
                            "title": "Provide TOKEN",
                            "export_secret": {"name": "TOKEN"},
                        }
                    ],
                },
            )
        if request.url.path == "/api/templates/tpl_owned/cache":
            return _json_response(202, {"run_id": "run-1"})
        if request.url.path == "/api/templates/tpl_owned/events":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_EventStream(state),
            )
        if request.url.path == "/api/templates/tpl_owned/cache/run-1/secrets":
            assert json.loads(request.content.decode("utf-8")) == {"TOKEN": "abc123"}
            state["secret_submitted"] = True
            return _json_response(200, {"ok": True})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="user-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(client_wrapper, devbox_client)
    )

    result = runner.run(
        "tpl_owned",
        options=TemplateRunOptions(force=True),
        presenter=_StubPresenter(SecretSubmission("abc123", True)),
    )

    assert result.status == "completed"
    assert state["secret_submitted"] is True
    assert state["saved"] == [("TOKEN", "abc123")]
    assert "Saved TOKEN to your Morph secrets." in result.warnings


def test_template_runner_submits_saved_secret_token_authenticated():
    state = {"secret_submitted": False}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/templates/tpl_owned":
            return _json_response(
                200,
                {
                    "id": "tpl_owned",
                    "name": "Owned Template",
                    "status": "draft",
                    "step_count": 1,
                    "cached_step_count": 0,
                    "steps": [
                        {
                            "index": 0,
                            "type": "exportSecret",
                            "title": "Provide TOKEN",
                            "export_secret": {"name": "TOKEN"},
                        }
                    ],
                },
            )
        if request.url.path == "/api/templates/tpl_owned/cache":
            return _json_response(202, {"run_id": "run-1"})
        if request.url.path == "/api/templates/tpl_owned/events":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_ByteStream(
                    [
                        b'data: {"type":"awaiting_input","index":0,"secretName":"TOKEN","hasSaved":true,"optional":false,"defaultAction":"wait","runId":"run-1"}\n\n',
                        b'data: {"type":"completed","instanceId":"devbox_123","instance":{"id":"devbox_123"}}\n\n',
                    ]
                ),
            )
        if request.url.path == "/api/templates/tpl_owned/cache/run-1/secrets":
            assert json.loads(request.content.decode("utf-8")) == {
                "TOKEN": USE_SAVED_SECRET_TOKEN
            }
            state["secret_submitted"] = True
            return _json_response(200, {"ok": True})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="user-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(types.SimpleNamespace(user=None), devbox_client)
    )

    result = runner.run(
        "tpl_owned",
        options=TemplateRunOptions(force=True),
        presenter=_StubPresenter(SecretSubmission(USE_SAVED_SECRET_TOKEN, False)),
    )

    assert result.status == "completed"
    assert state["secret_submitted"] is True


def test_template_runner_rejects_saved_secret_token_anonymously():
    devbox_client = DevboxClient(
        token="service-key",
        base_url="https://devbox.example",
        httpx_client=httpx.Client(transport=httpx.MockTransport(lambda request: _json_response(500, {"detail": "unexpected"}))),
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(None, devbox_client, anonymous=True)
    )

    with pytest.raises(
        TemplateRunnerError,
        match="Saved secrets are unavailable for anonymous template runs",
    ):
        runner.run(
            "tpl_shared",
            options=TemplateRunOptions(
                force=True,
                runtime_secrets={"TOKEN": USE_SAVED_SECRET_TOKEN},
            ),
            presenter=_StubPresenter(),
        )


@pytest.mark.parametrize(
    ("event_payload", "expected_status", "expected_error"),
    [
        (b'data: {"type":"cancelled","message":"operator cancelled"}\n\n', "cancelled", "operator cancelled"),
        (
            b'data: {"type":"error","message":"workflow failed","details":"boom"}\n\n',
            "error",
            "workflow failed: boom",
        ),
    ],
)
def test_template_runner_returns_terminal_failure_states(
    event_payload, expected_status, expected_error
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/templates/tpl_owned":
            return _json_response(
                200,
                {
                    "id": "tpl_owned",
                    "name": "Owned Template",
                    "status": "draft",
                    "step_count": 1,
                    "cached_step_count": 0,
                },
            )
        if request.url.path == "/api/templates/tpl_owned/cache":
            return _json_response(202, {"run_id": "run-1"})
        if request.url.path == "/api/templates/tpl_owned/events":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_ByteStream([event_payload]),
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="user-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    runner = TemplateWorkflowRunner(
        TemplateWorkflowTransport(types.SimpleNamespace(user=None), devbox_client)
    )

    result = runner.run(
        "tpl_owned",
        options=TemplateRunOptions(force=True),
        presenter=_StubPresenter(),
    )

    assert result.status == expected_status
    assert result.error == expected_error


def test_plain_presenter_autoskips_optional_secret_noninteractive():
    presenter = PlainTemplatePresenter(interactive=False)

    submission = presenter.prompt_for_secret(
        SecretPromptState(
            step_index=0,
            secret_name="TOKEN",
            optional=True,
            default_action="skip",
            countdown_seconds=30,
        ),
        TemplateRunState(target=_target()),
    )

    assert submission == SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)


def test_build_presenter_uses_prompt_toolkit_when_interactive(monkeypatch):
    import morphcloud.devbox.template_runner as runner_mod

    class _TTY:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(runner_mod.click, "get_text_stream", lambda name: _TTY())

    presenter = runner_mod.build_presenter(plain=False, json_output=False)

    assert isinstance(presenter, runner_mod.PromptToolkitTemplatePresenter)


def test_build_presenter_uses_plain_when_plain_flag_set(monkeypatch):
    import morphcloud.devbox.template_runner as runner_mod

    class _TTY:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(runner_mod.click, "get_text_stream", lambda name: _TTY())

    presenter = runner_mod.build_presenter(plain=True, json_output=False)

    assert isinstance(presenter, runner_mod.PlainTemplatePresenter)


def test_transport_resolve_target_reports_unresolved_alias():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/aliases/missing":
            return _json_response(404, {"detail": "Alias not found"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    devbox_client = DevboxClient(
        token="service-key",
        base_url="https://devbox.example",
        httpx_client=client,
    )
    transport = TemplateWorkflowTransport(None, devbox_client, anonymous=True)

    with pytest.raises(TemplateRunnerError, match="Alias not found"):
        transport.resolve_target("missing")
