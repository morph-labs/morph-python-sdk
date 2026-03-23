"""Template workflow runner transport, controller, and terminal presenters."""

from __future__ import annotations

import dataclasses
import json
import re
import time
import typing as t
import urllib.parse

import click

USE_SAVED_SECRET_TOKEN = "__USE_SAVED__"
SKIP_OPTIONAL_SECRET_TOKEN = "__SKIP__"
_TEMPLATE_ID_RE = re.compile(r"^tpl[_-]")
_MAX_OUTPUT_LINES = 200
_MAX_STREAM_RECONNECTS = 2
_RECONNECT_BACKOFF_SECONDS = 1.0
_PROMPT_TOOLKIT_REFRESH_SECONDS = 0.5


class TemplateRunnerError(RuntimeError):
    """Raised when the template runner cannot continue."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclasses.dataclass(frozen=True)
class TemplateStepSummary:
    """User-facing step metadata for rendering build progress."""

    index: int
    step_type: str
    title: str | None = None
    command: str | None = None
    session_name: str | None = None
    secret_name: str | None = None
    service_name: str | None = None
    service_port: int | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, t.Any]) -> "TemplateStepSummary":
        http_service = payload.get("http_service")
        export_secret = payload.get("export_secret")
        tmux_session = payload.get("tmux_session")
        return cls(
            index=_coerce_int(payload.get("index"), default=0),
            step_type=_coerce_str(payload.get("type"), default="command"),
            title=_coerce_optional_str(payload.get("title")),
            command=_coerce_optional_str(payload.get("command")),
            session_name=_coerce_optional_str(_get_mapping_value(tmux_session, "name")),
            secret_name=_coerce_optional_str(_get_mapping_value(export_secret, "name")),
            service_name=_coerce_optional_str(_get_mapping_value(http_service, "name")),
            service_port=_coerce_optional_int(_get_mapping_value(http_service, "port")),
        )

    @property
    def label(self) -> str:
        if self.title:
            return self.title
        if self.step_type == "exportSecret" and self.secret_name:
            return f"exportSecret {self.secret_name}"
        if self.step_type == "exposeHttpService" and self.service_name:
            if self.service_port is not None:
                return f"Expose {self.service_name}:{self.service_port}"
            return f"Expose {self.service_name}"
        if self.step_type == "tmuxSession" and self.session_name:
            return f"tmux {self.session_name}"
        if self.command:
            return _truncate_line(self.command, 48)
        return self.step_type


@dataclasses.dataclass(frozen=True)
class TemplateTarget:
    """Resolved template target for build or instant-start flows."""

    template_id: str
    name: str
    description: str | None
    status: str
    step_count: int
    cached_step_count: int
    final_snapshot_id: str | None = None
    run_id: str | None = None
    alias: str | None = None
    is_shared: bool = False
    steps: tuple[TemplateStepSummary, ...] = ()

    @classmethod
    def from_payload(
        cls,
        payload: dict[str, t.Any],
        *,
        alias: str | None = None,
        is_shared: bool = False,
    ) -> "TemplateTarget":
        steps_payload = payload.get("steps")
        steps = ()
        if isinstance(steps_payload, list):
            steps = tuple(
                TemplateStepSummary.from_payload(step)
                for step in steps_payload
                if isinstance(step, dict)
            )
        return cls(
            template_id=_require_str(payload.get("id"), name="template id"),
            name=_coerce_str(payload.get("name"), default="Unnamed Template"),
            description=_coerce_optional_str(payload.get("description")),
            status=_coerce_str(payload.get("status"), default="unknown"),
            step_count=_coerce_int(payload.get("step_count"), default=len(steps)),
            cached_step_count=_coerce_int(payload.get("cached_step_count"), default=0),
            final_snapshot_id=_coerce_optional_str(payload.get("final_snapshot_id")),
            run_id=_coerce_optional_str(payload.get("run_id")),
            alias=alias or _coerce_optional_str(payload.get("alias")),
            is_shared=bool(
                payload.get("is_shared") if "is_shared" in payload else is_shared
            ),
            steps=steps,
        )

    def step_label(self, index: int) -> str:
        for step in self.steps:
            if step.index == index:
                return step.label
        return f"Step {index}"

    def as_dict(self) -> dict[str, t.Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "step_count": self.step_count,
            "cached_step_count": self.cached_step_count,
            "final_snapshot_id": self.final_snapshot_id,
            "run_id": self.run_id,
            "alias": self.alias,
            "is_shared": self.is_shared,
            "steps": [dataclasses.asdict(step) for step in self.steps],
        }


@dataclasses.dataclass(frozen=True)
class AliasSearchResult:
    """Typed alias-search result returned by the devbox service."""

    alias: str
    template_id: str
    description: str | None = None
    step_count: int | None = None
    match_count: int | None = None
    tags: tuple[str, ...] = ()
    steps_preview: tuple[str, ...] = ()

    @classmethod
    def from_payload(cls, payload: dict[str, t.Any]) -> "AliasSearchResult":
        raw_tags = payload.get("tags")
        raw_preview = payload.get("steps_preview")
        tags = ()
        if isinstance(raw_tags, list):
            tags = tuple(str(item) for item in raw_tags if item is not None)
        preview = ()
        if isinstance(raw_preview, list):
            values: list[str] = []
            for item in raw_preview:
                if isinstance(item, dict):
                    title = _coerce_optional_str(item.get("title"))
                    step_type = _coerce_optional_str(item.get("type"))
                    values.append(title or step_type or "step")
            preview = tuple(values)
        return cls(
            alias=_require_str(payload.get("alias"), name="alias"),
            template_id=_require_str(
                payload.get("template_id") or payload.get("templateId"),
                name="template_id",
            ),
            description=_coerce_optional_str(payload.get("description")),
            step_count=_coerce_optional_int(payload.get("step_count")),
            match_count=_coerce_optional_int(payload.get("match_count")),
            tags=tags,
            steps_preview=preview,
        )


@dataclasses.dataclass(frozen=True)
class TemplateRunOptions:
    """Typed build/run request options for the template workflow path."""

    workflow_context: dict[str, str] = dataclasses.field(default_factory=dict)
    runtime_secrets: dict[str, str] = dataclasses.field(default_factory=dict)
    force: bool = False
    attach_run_id: str | None = None
    base_devbox_id: str | None = None
    base_snapshot_id: str | None = None
    handoff_ttl_seconds: int | None = None
    handoff_ttl_action: str | None = None

    def to_cache_request(self) -> dict[str, t.Any] | None:
        body: dict[str, t.Any] = {}
        if self.runtime_secrets:
            body["runtime_secrets"] = dict(self.runtime_secrets)
        if self.workflow_context:
            body["workflow_context"] = dict(self.workflow_context)
        if self.force:
            body["force"] = True
        if self.base_devbox_id:
            body["base_devbox_id"] = self.base_devbox_id
        if self.base_snapshot_id:
            body["base_snapshot_id"] = self.base_snapshot_id
        if self.handoff_ttl_seconds is not None:
            body["handoff_ttl_seconds"] = int(self.handoff_ttl_seconds)
        if self.handoff_ttl_action:
            body["handoff_ttl_action"] = self.handoff_ttl_action
        return body or None

    @property
    def requires_build(self) -> bool:
        return any(
            [
                self.force,
                bool(self.attach_run_id),
                bool(self.workflow_context),
                bool(self.runtime_secrets),
                bool(self.base_devbox_id),
                bool(self.base_snapshot_id),
            ]
        )


@dataclasses.dataclass(frozen=True)
class SecretPromptState:
    """Normalized secret prompt emitted by the SSE workflow stream."""

    step_index: int
    secret_name: str
    has_saved: bool = False
    optional: bool = False
    default_action: str | None = None
    deadline_at_ms: int | None = None
    countdown_seconds: int | None = None
    run_id: str | None = None

    def as_dict(self) -> dict[str, t.Any]:
        return {
            "step_index": self.step_index,
            "secret_name": self.secret_name,
            "has_saved": self.has_saved,
            "optional": self.optional,
            "default_action": self.default_action,
            "deadline_at_ms": self.deadline_at_ms,
            "countdown_seconds": self.countdown_seconds,
            "run_id": self.run_id,
        }


@dataclasses.dataclass(frozen=True)
class SecretSubmission:
    """Decision returned by the presenter when a secret prompt appears."""

    value: str
    save_to_account: bool = False


@dataclasses.dataclass(frozen=True)
class InstantStartAvailability:
    """Typed response for instant-start availability."""

    template_id: str
    available: bool
    reason: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, t.Any]) -> "InstantStartAvailability":
        return cls(
            template_id=_require_str(
                payload.get("template_id") or payload.get("templateId"),
                name="template_id",
            ),
            available=bool(payload.get("available")),
            reason=_coerce_optional_str(payload.get("reason")),
        )

    def as_dict(self) -> dict[str, t.Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class TemplateRunEvent:
    """Normalized SSE event payload."""

    event_type: str
    payload: dict[str, t.Any]
    step_index: int | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, t.Any]) -> "TemplateRunEvent":
        event_type = _coerce_str(
            payload.get("type") or payload.get("status"), default="event"
        )
        normalized = dict(payload)
        if event_type == "awaiting_input":
            normalized["secretName"] = _coerce_str(
                payload.get("secretName") or payload.get("secret_name"),
                default="",
            )
            normalized["hasSaved"] = _coerce_bool(
                (
                    payload.get("hasSaved")
                    if "hasSaved" in payload
                    else payload.get("has_saved")
                ),
                default=False,
            )
            normalized["optional"] = _coerce_bool(
                (
                    payload.get("optional")
                    if "optional" in payload
                    else payload.get("isOptional")
                ),
                default=False,
            )
            default_action = payload.get("defaultAction")
            if default_action not in {"wait", "skip"}:
                default_action = payload.get("default_action")
            normalized["defaultAction"] = (
                default_action if default_action in {"wait", "skip"} else None
            )
            normalized["deadlineAt"] = _coerce_optional_int(
                payload.get("deadlineAt")
                if "deadlineAt" in payload
                else payload.get("deadline_at")
            )
            normalized["countdownSeconds"] = _coerce_optional_int(
                payload.get("countdownSeconds")
                if "countdownSeconds" in payload
                else payload.get("countdown_seconds")
            )
            normalized["runId"] = _coerce_optional_str(
                payload.get("runId") or payload.get("run_id")
            )
        return cls(
            event_type=event_type,
            payload=normalized,
            step_index=_coerce_optional_int(normalized.get("index")),
        )


@dataclasses.dataclass
class TemplateRunState:
    """Mutable workflow state shared between the controller and presenters."""

    target: TemplateTarget
    status: str = "pending"
    mode: str = "build"
    run_id: str | None = None
    current_step_index: int | None = None
    last_message: str | None = None
    waiting_for_secret: SecretPromptState | None = None
    completed_devbox_id: str | None = None
    completed_devbox: dict[str, t.Any] | None = None
    exposed_services: list[dict[str, t.Any]] = dataclasses.field(default_factory=list)
    step_statuses: dict[int, str] = dataclasses.field(default_factory=dict)
    output_by_step: dict[int, list[str]] = dataclasses.field(default_factory=dict)
    recent_output: list[str] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    error_message: str | None = None
    instant_availability: InstantStartAvailability | None = None
    started_at: float = dataclasses.field(default_factory=time.time)
    finished_at: float | None = None
    event_count: int = 0

    def append_output(self, step_index: int, content: str) -> None:
        chunks = self.output_by_step.setdefault(step_index, [])
        chunks.append(content)
        self.recent_output.extend(content.splitlines() or [content])
        if len(self.recent_output) > _MAX_OUTPUT_LINES:
            self.recent_output = self.recent_output[-_MAX_OUTPUT_LINES:]

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)


@dataclasses.dataclass(frozen=True)
class TemplateRunResult:
    """Final structured result for CLI output or scripting."""

    status: str
    mode: str
    target: TemplateTarget
    run_id: str | None = None
    devbox_id: str | None = None
    devbox: dict[str, t.Any] | None = None
    awaiting_input: SecretPromptState | None = None
    availability: InstantStartAvailability | None = None
    exposed_services: tuple[dict[str, t.Any], ...] = ()
    warnings: tuple[str, ...] = ()
    error: str | None = None

    @classmethod
    def from_state(cls, state: TemplateRunState) -> "TemplateRunResult":
        return cls(
            status=state.status,
            mode=state.mode,
            target=state.target,
            run_id=state.run_id,
            devbox_id=state.completed_devbox_id,
            devbox=state.completed_devbox,
            awaiting_input=state.waiting_for_secret,
            availability=state.instant_availability,
            exposed_services=tuple(dict(item) for item in state.exposed_services),
            warnings=tuple(state.warnings),
            error=state.error_message,
        )

    def exit_code(self) -> int:
        if self.status == "completed":
            return 0
        if self.status == "awaiting_input":
            return 2
        if self.status == "cancelled":
            return 1
        if self.status == "error":
            return 1
        return 0

    def as_dict(self) -> dict[str, t.Any]:
        return {
            "status": self.status,
            "mode": self.mode,
            "target": self.target.as_dict(),
            "run_id": self.run_id,
            "devbox_id": self.devbox_id,
            "devbox": self.devbox,
            "awaiting_input": (
                self.awaiting_input.as_dict()
                if self.awaiting_input is not None
                else None
            ),
            "availability": (
                self.availability.as_dict() if self.availability is not None else None
            ),
            "exposed_services": [dict(item) for item in self.exposed_services],
            "warnings": list(self.warnings),
            "error": self.error,
        }


class TemplateWorkflowTransport:
    """Typed transport wrapper around the template workflow endpoints."""

    def __init__(self, client: t.Any, devbox_client: t.Any, *, anonymous: bool = False):
        self._client = client
        self._devbox_client = devbox_client
        self._anonymous = anonymous
        self._wrapper = devbox_client._client_wrapper
        self._http = self._wrapper.httpx_client
        self._raw_http = self._http.httpx_client

    @property
    def is_anonymous(self) -> bool:
        return self._anonymous

    def list_templates(self) -> list[TemplateTarget]:
        if self._anonymous:
            return []
        response = self._request("GET", "api/templates")
        payload = self._json_body(response, fallback="Failed to list templates.")
        items = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            return []
        return [
            TemplateTarget.from_payload(item)
            for item in items
            if isinstance(item, dict)
        ]

    def get_template_detail(self, template_id: str) -> TemplateTarget:
        response = self._request("GET", f"api/templates/{_quote(template_id)}")
        payload = self._json_body(
            response, fallback=f"Failed to fetch template {template_id}."
        )
        if not isinstance(payload, dict):
            raise TemplateRunnerError(
                f"Template detail response for {template_id} was not an object."
            )
        return TemplateTarget.from_payload(payload)

    def get_shared_template_detail(
        self, template_id: str, *, alias: str | None = None
    ) -> TemplateTarget:
        response = self._request("GET", f"api/templates/shared/{_quote(template_id)}")
        payload = self._json_body(
            response,
            fallback=f"Failed to fetch shared template detail for {template_id}.",
        )
        if not isinstance(payload, dict):
            raise TemplateRunnerError(
                f"Shared template detail response for {template_id} was not an object."
            )
        return TemplateTarget.from_payload(payload, alias=alias, is_shared=True)

    def get_alias(self, alias: str) -> dict[str, t.Any]:
        response = self._request("GET", f"api/aliases/{_quote(alias)}")
        payload = self._json_body(
            response, fallback=f"Failed to resolve alias '{alias}'."
        )
        if not isinstance(payload, dict):
            raise TemplateRunnerError(
                f"Alias response for '{alias}' was not an object."
            )
        return payload

    def search_aliases(self, query: str, *, limit: int = 10) -> list[AliasSearchResult]:
        response = self._request(
            "GET",
            "api/aliases/search",
            params={
                "q": query,
                "limit": limit,
                "match": "any",
                "include_steps": "true",
                "steps_limit": 5,
            },
        )
        payload = self._json_body(
            response, fallback=f"Failed to search aliases for '{query}'."
        )
        items = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            return []
        return [
            AliasSearchResult.from_payload(item)
            for item in items
            if isinstance(item, dict)
        ]

    def resolve_target(self, target: str) -> TemplateTarget:
        candidate = target.strip()
        if not candidate:
            raise TemplateRunnerError("Template target cannot be empty.")
        if _looks_like_template_id(candidate):
            if self._anonymous:
                return self.get_shared_template_detail(candidate)
            try:
                return self.get_template_detail(candidate)
            except TemplateRunnerError as exc:
                if exc.status_code not in {403, 404}:
                    raise
                return self.get_shared_template_detail(candidate)

        alias_payload = self.get_alias(candidate)
        template_id = _coerce_optional_str(
            alias_payload.get("template_id") or alias_payload.get("templateId")
        )
        if not template_id:
            raise TemplateRunnerError(
                f"Alias '{candidate}' did not resolve to a template id."
            )
        return self.get_shared_template_detail(template_id, alias=candidate)

    def start_cache_run(self, template_id: str, options: TemplateRunOptions) -> str:
        response = self._request(
            "POST",
            f"api/templates/{_quote(template_id)}/cache",
            json_body=options.to_cache_request(),
        )
        if response.status_code == 409:
            target = self.resolve_target(template_id)
            if target.run_id:
                return target.run_id
            raise TemplateRunnerError(
                f"Template {template_id} is already building, but the active run id is unavailable.",
                status_code=response.status_code,
            )
        payload = self._json_body(
            response, fallback=f"Failed to start cache run for template {template_id}."
        )
        run_id = None
        if isinstance(payload, dict):
            run_id = _coerce_optional_str(payload.get("run_id") or payload.get("runId"))
        if not run_id:
            raise TemplateRunnerError(
                f"Cache run for template {template_id} did not return a run id."
            )
        return run_id

    def submit_secret(
        self, template_id: str, run_id: str, value_by_name: dict[str, str]
    ) -> None:
        response = self._request(
            "POST",
            f"api/templates/{_quote(template_id)}/cache/{_quote(run_id)}/secrets",
            json_body=value_by_name,
        )
        if response.status_code >= 400:
            raise self._response_error(
                response,
                fallback=f"Failed to submit secrets for run {run_id}.",
            )

    def check_instant_start_availability(
        self, template_id: str
    ) -> InstantStartAvailability:
        response = self._request(
            "GET",
            f"api/templates/{_quote(template_id)}/instant-devbox/availability",
        )
        payload = self._json_body(
            response,
            fallback=f"Failed to check instant-start availability for {template_id}.",
        )
        if not isinstance(payload, dict):
            raise TemplateRunnerError(
                f"Instant-start availability response for {template_id} was not an object."
            )
        return InstantStartAvailability.from_payload(payload)

    def start_instant_devbox(
        self, template_id: str, options: TemplateRunOptions
    ) -> dict[str, t.Any]:
        payload: dict[str, t.Any] = {}
        if options.handoff_ttl_seconds is not None:
            payload["handoff_ttl_seconds"] = int(options.handoff_ttl_seconds)
        if options.handoff_ttl_action:
            payload["handoff_ttl_action"] = options.handoff_ttl_action
        response = self._request(
            "POST",
            f"api/templates/{_quote(template_id)}/instant-devbox",
            json_body=payload or None,
        )
        body = self._json_body(
            response, fallback=f"Failed to start instant devbox for {template_id}."
        )
        if not isinstance(body, dict):
            raise TemplateRunnerError(
                f"Instant devbox response for {template_id} was not an object."
            )
        return body

    def save_secret(self, name: str, value: str) -> None:
        if self._client is None:
            raise TemplateRunnerError(
                "Saving secrets is unavailable for anonymous template runs."
            )
        self._client.user.create_secret(name=name, value=value)

    def stream_events(
        self,
        template_id: str,
        *,
        run_id: str,
        force: bool = False,
    ) -> t.Iterator[TemplateRunEvent]:
        path = f"api/templates/{_quote(template_id)}/events"
        params: dict[str, t.Any] = {"run_id": run_id}
        if force:
            params["force"] = "true"
        url = urllib.parse.urljoin(f"{self._wrapper.get_base_url()}/", path)
        headers = {
            **self._wrapper.get_headers(),
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        with self._raw_http.stream(
            "GET",
            url,
            headers=headers,
            params=params,
            timeout=None,
        ) as response:
            if response.status_code >= 400:
                raise self._response_error(
                    response,
                    fallback=f"Failed to stream events for run {run_id}.",
                )
            yield from self._iter_sse_events(response)

    def _iter_sse_events(self, response: t.Any) -> t.Iterator[TemplateRunEvent]:
        data_lines: list[str] = []
        for raw_line in response.iter_lines():
            line = raw_line if isinstance(raw_line, str) else raw_line.decode("utf-8")
            if not line:
                if data_lines:
                    joined = "\n".join(data_lines)
                    data_lines = []
                    try:
                        payload = json.loads(joined)
                    except json.JSONDecodeError as exc:
                        raise TemplateRunnerError(
                            f"Received malformed SSE payload: {joined}"
                        ) from exc
                    if isinstance(payload, dict):
                        yield TemplateRunEvent.from_payload(payload)
                continue
            if line.startswith(":"):
                continue
            field, _, value = line.partition(":")
            if field == "data":
                data_lines.append(value.lstrip())

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, t.Any] | None = None,
        json_body: dict[str, t.Any] | None = None,
    ) -> t.Any:
        return self._http.request(
            path,
            method=method,
            params=params,
            json=json_body,
        )

    def _json_body(
        self, response: t.Any, *, fallback: str
    ) -> dict[str, t.Any] | list[t.Any] | None:
        if response.status_code >= 400:
            raise self._response_error(response, fallback=fallback)
        try:
            return response.json()
        except ValueError as exc:
            raise TemplateRunnerError(fallback) from exc

    def _response_error(self, response: t.Any, *, fallback: str) -> TemplateRunnerError:
        message = fallback
        try:
            payload = response.json()
        except Exception:
            payload = response.text or ""
        detail = _extract_error_detail(payload)
        if detail:
            message = detail
        return TemplateRunnerError(message, status_code=response.status_code)


class TemplateWorkflowRunner:
    """Controller that drives the template workflow through a presenter."""

    def __init__(self, transport: TemplateWorkflowTransport):
        self.transport = transport

    def list_owned_templates(self) -> list[TemplateTarget]:
        return self.transport.list_templates()

    def search_aliases(self, query: str, *, limit: int = 10) -> list[AliasSearchResult]:
        return self.transport.search_aliases(query, limit=limit)

    def resolve_target(self, target: str) -> TemplateTarget:
        return self.transport.resolve_target(target)

    def run(
        self,
        target: str | None,
        *,
        options: TemplateRunOptions,
        presenter: "BaseTemplatePresenter",
    ) -> TemplateRunResult:
        if self.transport.is_anonymous:
            saved_secret_names = sorted(
                name
                for name, value in options.runtime_secrets.items()
                if value == USE_SAVED_SECRET_TOKEN
            )
            if saved_secret_names:
                joined = ", ".join(saved_secret_names)
                raise TemplateRunnerError(
                    "Saved secrets are unavailable for anonymous template runs: "
                    f"{joined}."
                )
        selected = target or presenter.select_target(
            self.list_owned_templates(),
            self.search_aliases,
        )
        resolved = self.resolve_target(selected)
        state = TemplateRunState(target=resolved)
        presenter.start(state)

        try:
            if options.attach_run_id:
                state.run_id = options.attach_run_id
                state.status = "running"
                state.last_message = f"Attached to run {state.run_id}."
                presenter.update(state)
            elif self._should_attempt_instant_start(options):
                availability = self.transport.check_instant_start_availability(
                    resolved.template_id
                )
                state.instant_availability = availability
                state.last_message = self._availability_message(availability)
                presenter.update(state)
                if availability.available:
                    devbox = self.transport.start_instant_devbox(
                        resolved.template_id, options
                    )
                    state.mode = "instant"
                    state.status = "completed"
                    state.finished_at = time.time()
                    state.completed_devbox = devbox
                    state.completed_devbox_id = _resolve_completed_devbox_id(devbox)
                    state.exposed_services = _extract_http_services(devbox)
                    if state.completed_devbox_id:
                        state.last_message = (
                            f"Devbox {state.completed_devbox_id} is ready."
                        )
                    else:
                        state.last_message = "Instant devbox is ready."
                    presenter.finish(state)
                    return TemplateRunResult.from_state(state)

            if state.status != "completed":
                state.mode = "build"
                if not state.run_id:
                    state.run_id = self.transport.start_cache_run(
                        resolved.template_id, options
                    )
                    state.status = "running"
                    state.last_message = f"Started run {state.run_id}."
                    presenter.update(state)
                self._run_build_loop(state, options, presenter)
            presenter.finish(state)
            return TemplateRunResult.from_state(state)
        finally:
            presenter.close()

    def _run_build_loop(
        self,
        state: TemplateRunState,
        options: TemplateRunOptions,
        presenter: "BaseTemplatePresenter",
    ) -> None:
        if not state.run_id:
            raise TemplateRunnerError("Build run id is required to stream events.")
        event_history: list[str] = []
        reconnect_attempt = 0

        while True:
            replay_cursor: int | None = 0 if event_history else None
            semantic_replay = False
            replay_output_cursors: dict[int, int] = {}
            saw_new_event = False
            try:
                for event in self.transport.stream_events(
                    state.target.template_id,
                    run_id=state.run_id,
                    force=options.force,
                ):
                    event_key = _event_history_key(event)
                    if replay_cursor is not None:
                        if replay_cursor < len(event_history):
                            if event_history[replay_cursor] == event_key:
                                replay_cursor += 1
                                continue
                            semantic_replay = True
                        replay_cursor = None

                    if semantic_replay and self._should_skip_replayed_event(
                        state,
                        event,
                        replay_output_cursors=replay_output_cursors,
                    ):
                        continue

                    saw_new_event = True
                    reconnect_attempt = 0
                    event_history.append(event_key)
                    self._apply_event(state, event)
                    presenter.update(state, event)
                    if state.waiting_for_secret is not None:
                        submission = presenter.prompt_for_secret(
                            state.waiting_for_secret, state
                        )
                        if submission is None:
                            return
                        if (
                            submission.value == USE_SAVED_SECRET_TOKEN
                            and self.transport.is_anonymous
                        ):
                            raise TemplateRunnerError(
                                "Saved secrets are unavailable for anonymous template runs."
                            )
                        if (
                            submission.value
                            not in {
                                USE_SAVED_SECRET_TOKEN,
                                SKIP_OPTIONAL_SECRET_TOKEN,
                            }
                            and submission.save_to_account
                        ):
                            try:
                                self.transport.save_secret(
                                    state.waiting_for_secret.secret_name,
                                    submission.value,
                                )
                                state.warnings.append(
                                    f"Saved {state.waiting_for_secret.secret_name} to your Morph secrets."
                                )
                            except Exception as exc:
                                state.warnings.append(
                                    f"Failed to save {state.waiting_for_secret.secret_name}: {exc}"
                                )
                        self.transport.submit_secret(
                            state.target.template_id,
                            state.run_id,
                            {state.waiting_for_secret.secret_name: submission.value},
                        )
                        state.status = "running"
                        state.last_message = f"Submitted {state.waiting_for_secret.secret_name}; waiting for build to resume."
                        state.waiting_for_secret = None
                        presenter.update(state)
                    if state.status in {"completed", "cancelled", "error"}:
                        return
            except Exception as exc:
                if reconnect_attempt >= _MAX_STREAM_RECONNECTS:
                    raise TemplateRunnerError(
                        "Template event stream failed after reconnect attempts: "
                        f"{exc}"
                    ) from exc
                reconnect_attempt += 1
                self._notify_reconnect(
                    state,
                    presenter,
                    attempt=reconnect_attempt,
                    reason=str(exc) or "stream error",
                )
                continue

            if state.status in {"completed", "cancelled", "error", "awaiting_input"}:
                return

            if reconnect_attempt >= _MAX_STREAM_RECONNECTS:
                state.status = "error"
                state.error_message = "Template event stream ended before the workflow reached a terminal state."
                state.last_message = state.error_message
                presenter.update(state)
                return

            reconnect_attempt += 1
            reason = (
                "event stream closed before completion"
                if saw_new_event
                else "event stream closed without new events"
            )
            self._notify_reconnect(
                state,
                presenter,
                attempt=reconnect_attempt,
                reason=reason,
            )

    def _should_skip_replayed_event(
        self,
        state: TemplateRunState,
        event: TemplateRunEvent,
        *,
        replay_output_cursors: dict[int, int],
    ) -> bool:
        step_index = event.step_index
        if step_index is None:
            return False

        step_status = state.step_statuses.get(step_index)
        event_type = event.event_type

        if event_type == "step_started":
            return step_status is not None

        if event_type == "output":
            if step_status in {"cached", "completed", "failed"}:
                return True
            if step_status != "executing":
                return False
            content = _coerce_str(event.payload.get("content"), default="")
            prior_chunks = state.output_by_step.get(step_index) or []
            cursor = replay_output_cursors.get(step_index, 0)
            if cursor < len(prior_chunks) and prior_chunks[cursor] == content:
                replay_output_cursors[step_index] = cursor + 1
                return True
            return False

        if event_type == "cache":
            return step_status in {"cached", "completed", "failed"}

        if event_type in {"step_completed", "awaiting_input"}:
            return step_status in {"completed", "failed"}

        return False

    def _apply_event(self, state: TemplateRunState, event: TemplateRunEvent) -> None:
        state.event_count += 1
        payload = event.payload
        event_type = event.event_type
        service = _extract_single_http_service(payload)
        if service is not None:
            _merge_exposed_service(state.exposed_services, service)

        if event_type == "started":
            state.status = "running"
            state.last_message = _coerce_optional_str(payload.get("message")) or (
                f"Workflow started with {payload.get('totalSteps') or state.target.step_count} steps."
            )
            return

        if event_type == "base_selected":
            state.status = "running"
            state.last_message = (
                _coerce_optional_str(payload.get("message"))
                or "Base snapshot selected."
            )
            return

        if event_type == "step_started":
            if event.step_index is not None:
                state.current_step_index = event.step_index
                state.step_statuses[event.step_index] = "executing"
                state.output_by_step.setdefault(event.step_index, [])
                state.last_message = (
                    f"Running {state.target.step_label(event.step_index)}."
                )
            return

        if event_type == "output":
            if event.step_index is not None:
                content = _coerce_str(payload.get("content"), default="")
                state.current_step_index = event.step_index
                state.step_statuses.setdefault(event.step_index, "executing")
                state.append_output(event.step_index, content)
                if content.strip():
                    state.last_message = f"Streaming output for {state.target.step_label(event.step_index)}."
            return

        if event_type == "cache":
            if event.step_index is not None:
                state.step_statuses[event.step_index] = "cached"
                state.current_step_index = event.step_index
                state.last_message = (
                    f"Cache hit for {state.target.step_label(event.step_index)}."
                )
            return

        if event_type == "step_completed":
            if event.step_index is not None:
                state.step_statuses[event.step_index] = "completed"
                state.current_step_index = event.step_index
                state.last_message = (
                    f"Completed {state.target.step_label(event.step_index)}."
                )
            return

        if event_type == "awaiting_input":
            prompt = SecretPromptState(
                step_index=_coerce_int(payload.get("index"), default=0),
                secret_name=_coerce_str(payload.get("secretName"), default=""),
                has_saved=(
                    False
                    if self.transport.is_anonymous
                    else _coerce_bool(payload.get("hasSaved"), default=False)
                ),
                optional=_coerce_bool(payload.get("optional"), default=False),
                default_action=_coerce_optional_str(payload.get("defaultAction")),
                deadline_at_ms=_coerce_optional_int(payload.get("deadlineAt")),
                countdown_seconds=_coerce_optional_int(payload.get("countdownSeconds")),
                run_id=_coerce_optional_str(payload.get("runId")),
            )
            state.waiting_for_secret = prompt
            state.status = "awaiting_input"
            state.current_step_index = prompt.step_index
            state.step_statuses.setdefault(prompt.step_index, "executing")
            if prompt.optional:
                state.last_message = (
                    f"Optional secret {prompt.secret_name} is awaiting input."
                )
            else:
                state.last_message = (
                    f"Required secret {prompt.secret_name} is awaiting input."
                )
            return

        if event_type == "post_secret_instance":
            state.status = "running"
            state.last_message = _coerce_optional_str(payload.get("message")) or (
                "Resuming build after secret submission."
            )
            return

        if event_type == "completed":
            state.status = "completed"
            state.finished_at = time.time()
            instance = payload.get("instance")
            state.completed_devbox = instance if isinstance(instance, dict) else None
            state.completed_devbox_id = _resolve_completed_devbox_id(payload)
            services = _extract_http_services(payload)
            if services:
                state.exposed_services = services
            instance_error = _coerce_optional_str(payload.get("instanceError"))
            if instance_error:
                state.warnings.append(instance_error)
            warnings = payload.get("warnings")
            if isinstance(warnings, list):
                for warning in warnings:
                    if isinstance(warning, dict):
                        message = _coerce_optional_str(warning.get("message"))
                        if message:
                            state.warnings.append(message)
            if state.completed_devbox_id:
                state.last_message = f"Devbox {state.completed_devbox_id} is ready."
            else:
                state.last_message = "Workflow completed."
            return

        if event_type == "cancelled":
            state.status = "cancelled"
            state.finished_at = time.time()
            state.error_message = (
                _coerce_optional_str(payload.get("message")) or "Workflow cancelled."
            )
            state.last_message = state.error_message
            return

        if event_type == "step_failed":
            state.status = "error"
            state.finished_at = time.time()
            if event.step_index is not None:
                state.step_statuses[event.step_index] = "failed"
            state.error_message = _coerce_optional_str(payload.get("message")) or (
                "Template step failed."
            )
            state.last_message = state.error_message
            return

        if event_type == "error":
            state.status = "error"
            state.finished_at = time.time()
            message = _coerce_optional_str(payload.get("message")) or "Workflow failed."
            details = _coerce_optional_str(payload.get("details"))
            state.error_message = f"{message}: {details}" if details else message
            state.last_message = state.error_message
            return

        if event_type == "ping":
            return

        state.last_message = _coerce_optional_str(payload.get("message")) or event_type

    def _notify_reconnect(
        self,
        state: TemplateRunState,
        presenter: "BaseTemplatePresenter",
        *,
        attempt: int,
        reason: str,
    ) -> None:
        state.status = "running"
        state.last_message = (
            f"Template event stream interrupted ({reason}); reconnecting "
            f"{attempt}/{_MAX_STREAM_RECONNECTS}."
        )
        state.warnings.append(state.last_message)
        presenter.update(state)
        time.sleep(_RECONNECT_BACKOFF_SECONDS)

    def _availability_message(self, availability: InstantStartAvailability) -> str:
        if availability.available:
            return "Template is ready for instant start."
        if availability.reason == "not_ready":
            return "Template is not ready for instant start; starting a build instead."
        if availability.reason == "requires_build":
            return "Template requires a build for this user; starting a build."
        if availability.reason == "forbidden":
            return "Instant start is unavailable with the current credentials; starting a build."
        return "Instant start is unavailable; starting a build."

    def _should_attempt_instant_start(self, options: TemplateRunOptions) -> bool:
        return not options.requires_build


class BaseTemplatePresenter:
    """Presentation interface used by the workflow controller."""

    def __init__(self, *, interactive: bool):
        self.interactive = interactive

    def select_target(
        self,
        owned_templates: list[TemplateTarget],
        search_fn: t.Callable[[str], list[AliasSearchResult]],
    ) -> str:
        raise NotImplementedError

    def start(self, state: TemplateRunState) -> None:
        del state

    def update(
        self, state: TemplateRunState, event: TemplateRunEvent | None = None
    ) -> None:
        del state, event

    def prompt_for_secret(
        self, prompt: SecretPromptState, state: TemplateRunState
    ) -> SecretSubmission | None:
        del prompt, state
        return None

    def finish(self, state: TemplateRunState) -> None:
        del state

    def close(self) -> None:
        return None


class PlainTemplatePresenter(BaseTemplatePresenter):
    """Plain-text presenter used for non-TTY and `--plain` runs."""

    def __init__(self, *, interactive: bool, quiet: bool = False):
        super().__init__(interactive=interactive)
        self._quiet = quiet

    def select_target(
        self,
        owned_templates: list[TemplateTarget],
        search_fn: t.Callable[[str], list[AliasSearchResult]],
    ) -> str:
        if not self.interactive:
            raise TemplateRunnerError(
                "Provide a template id or alias when not running interactively."
            )

        current_search: list[AliasSearchResult] = []
        while True:
            self._print_target_list(owned_templates, current_search)
            answer = click.prompt(
                "Target (number, template id, alias, /search QUERY, or q)",
                prompt_suffix=": ",
                default="",
                show_default=False,
            ).strip()
            if not answer:
                continue
            lowered = answer.lower()
            if lowered in {"q", "quit", "exit"}:
                raise click.Abort()
            if lowered.startswith("/search ") or lowered.startswith("?"):
                query = (
                    answer[8:].strip()
                    if lowered.startswith("/search ")
                    else answer[1:].strip()
                )
                if not query:
                    raise TemplateRunnerError("Search query cannot be empty.")
                current_search = search_fn(query)
                continue
            if answer.isdigit():
                selected = self._resolve_number(
                    int(answer),
                    owned_templates=owned_templates,
                    search_results=current_search,
                )
                if selected:
                    return selected
            return answer

    def start(self, state: TemplateRunState) -> None:
        if self._quiet:
            return
        click.echo(
            f"Template: {state.target.name} ({state.target.template_id})"
            + (f" alias={state.target.alias}" if state.target.alias else "")
        )

    def update(
        self, state: TemplateRunState, event: TemplateRunEvent | None = None
    ) -> None:
        if self._quiet:
            return
        if event is None:
            if state.last_message:
                click.echo(state.last_message)
            return
        event_type = event.event_type
        if event_type == "output":
            content = _coerce_str(event.payload.get("content"), default="")
            click.echo(content, nl=not content.endswith("\n"))
            return
        if event_type == "step_started" and event.step_index is not None:
            click.echo(
                f"[step {event.step_index}] {state.target.step_label(event.step_index)}"
            )
            return
        if event_type == "step_completed" and event.step_index is not None:
            click.echo(
                f"[step {event.step_index}] completed {state.target.step_label(event.step_index)}"
            )
            return
        if event_type == "cache" and event.step_index is not None:
            click.echo(f"[step {event.step_index}] cache hit")
            return
        if event_type == "awaiting_input" and state.waiting_for_secret is not None:
            prompt = state.waiting_for_secret
            label = "optional" if prompt.optional else "required"
            message = f"[secret] {label} secret {prompt.secret_name} is awaiting input"
            remaining = _format_secret_countdown(prompt)
            if remaining:
                message += f" ({remaining})"
            click.echo(message)
            return
        if event_type == "completed":
            if state.completed_devbox_id:
                click.echo(f"Devbox created: {state.completed_devbox_id}")
            else:
                click.echo("Workflow completed.")
            return
        if event_type in {"error", "step_failed", "cancelled"} and state.error_message:
            click.echo(state.error_message, err=True)
            return
        if state.last_message:
            click.echo(state.last_message)

    def prompt_for_secret(
        self, prompt: SecretPromptState, state: TemplateRunState
    ) -> SecretSubmission | None:
        del state
        if not self.interactive:
            if prompt.optional and prompt.default_action == "skip":
                return SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)
            return None

        if prompt.has_saved:
            if click.confirm(
                f"Use the saved secret for {prompt.secret_name}?",
                default=True,
            ):
                return SecretSubmission(USE_SAVED_SECRET_TOKEN, False)

        if prompt.optional:
            countdown = _format_secret_countdown(prompt)
            choice = click.prompt(
                (
                    f"Provide optional {prompt.secret_name} or type 'skip'"
                    + (f" [{countdown}]" if countdown else "")
                ),
                prompt_suffix=": ",
                default="skip" if prompt.default_action == "skip" else "",
                show_default=prompt.default_action == "skip",
            ).strip()
            if not choice or choice.lower() == "skip":
                return SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)
            save = click.confirm(
                f"Save {prompt.secret_name} to your Morph secrets?",
                default=False,
            )
            return SecretSubmission(choice, save)

        while True:
            value = click.prompt(
                f"Enter {prompt.secret_name}",
                prompt_suffix=": ",
                hide_input=True,
                confirmation_prompt=False,
                default="",
                show_default=False,
            ).strip()
            if value:
                save = click.confirm(
                    f"Save {prompt.secret_name} to your Morph secrets?",
                    default=False,
                )
                return SecretSubmission(value, save)
            click.echo("A value is required for this secret.", err=True)

    def finish(self, state: TemplateRunState) -> None:
        if self._quiet:
            return
        for service in state.exposed_services:
            url = _coerce_optional_str(service.get("url"))
            if not url:
                continue
            name = _coerce_optional_str(service.get("name")) or "service"
            click.echo(f"Service {name}: {url}")
        if state.status == "completed" and state.completed_devbox_id:
            click.echo(f"Next: morphcloud devbox ssh {state.completed_devbox_id}")
            for session_name in _template_tmux_session_names(state.target):
                click.echo(
                    "Next: morphcloud devbox terminal connect "
                    f"{state.completed_devbox_id} {session_name}"
                )
        elif state.status == "awaiting_input" and state.waiting_for_secret is not None:
            click.echo(
                f"Run {state.run_id} is awaiting {state.waiting_for_secret.secret_name}.",
                err=True,
            )
        elif state.status == "error" and state.error_message:
            click.echo(state.error_message, err=True)

    def _print_target_list(
        self,
        owned_templates: list[TemplateTarget],
        search_results: list[AliasSearchResult],
    ) -> None:
        if owned_templates:
            click.echo("Owned templates:")
            for idx, item in enumerate(owned_templates, start=1):
                click.echo(
                    f"  {idx}. {item.name} ({item.template_id}) [{item.cached_step_count}/{item.step_count}]"
                )
        else:
            click.echo("No owned templates found.")

        if search_results:
            offset = len(owned_templates)
            click.echo("Shared aliases:")
            for idx, item in enumerate(search_results, start=1):
                click.echo(
                    f"  {offset + idx}. {item.alias} -> {item.template_id}"
                    + (f" ({item.description})" if item.description else "")
                )

    def _resolve_number(
        self,
        value: int,
        *,
        owned_templates: list[TemplateTarget],
        search_results: list[AliasSearchResult],
    ) -> str | None:
        if value < 1:
            return None
        if value <= len(owned_templates):
            return owned_templates[value - 1].template_id
        offset = value - len(owned_templates) - 1
        if 0 <= offset < len(search_results):
            return search_results[offset].alias
        raise TemplateRunnerError(f"Selection {value} is out of range.")


class PromptToolkitTemplatePresenter(BaseTemplatePresenter):
    """Prompt-toolkit interactive presenter with throttled screen redraws."""

    def __init__(self) -> None:
        super().__init__(interactive=True)
        try:
            from prompt_toolkit.shortcuts import (
                PromptSession,
            )
            from prompt_toolkit.shortcuts import clear as prompt_toolkit_clear
            from prompt_toolkit.shortcuts import (
                print_formatted_text as prompt_toolkit_print,
            )
        except ImportError as exc:
            raise TemplateRunnerError(
                "Interactive template mode requires prompt_toolkit. "
                "Reinstall morphcloud or use --plain."
            ) from exc

        self._session = PromptSession()
        self._clear = prompt_toolkit_clear
        self._print = prompt_toolkit_print
        self._last_rendered = ""
        self._last_render_at = 0.0

    def select_target(
        self,
        owned_templates: list[TemplateTarget],
        search_fn: t.Callable[[str], list[AliasSearchResult]],
    ) -> str:
        search_results: list[AliasSearchResult] = []
        while True:
            choices = self._render_target_browser(owned_templates, search_results)
            answer = self._session.prompt(
                "Target (number, template id, alias, /search QUERY, q): "
            ).strip()
            if not answer:
                continue
            lowered = answer.lower()
            if lowered in {"q", "quit", "exit"}:
                raise click.Abort()
            if lowered.startswith("/search ") or lowered.startswith("?"):
                query = (
                    answer[8:].strip()
                    if lowered.startswith("/search ")
                    else answer[1:].strip()
                )
                if not query:
                    raise TemplateRunnerError("Search query cannot be empty.")
                search_results = search_fn(query)
                continue
            if answer.isdigit():
                selected = choices.get(int(answer))
                if selected:
                    return selected
            return answer

    def start(self, state: TemplateRunState) -> None:
        self._render_state(state, force=True)

    def update(
        self, state: TemplateRunState, event: TemplateRunEvent | None = None
    ) -> None:
        force = event is None or event.event_type in {
            "started",
            "base_selected",
            "step_started",
            "step_completed",
            "cache",
            "awaiting_input",
            "post_secret_instance",
            "completed",
            "cancelled",
            "step_failed",
            "error",
        }
        self._render_state(state, force=force)

    def prompt_for_secret(
        self, prompt: SecretPromptState, state: TemplateRunState
    ) -> SecretSubmission | None:
        self._render_state(state, force=True)
        if prompt.has_saved:
            choice = self._prompt_choice(
                f"Secret {prompt.secret_name}",
                ["saved", "value", "skip"] if prompt.optional else ["saved", "value"],
                default="saved",
            )
            if choice == "saved":
                return SecretSubmission(USE_SAVED_SECRET_TOKEN, False)
            if choice == "skip":
                return SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)
        elif prompt.optional:
            choice = self._prompt_choice(
                f"Optional secret {prompt.secret_name}",
                ["value", "skip"],
                default="skip" if prompt.default_action == "skip" else "value",
            )
            if choice == "skip":
                return SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)

        while True:
            value = self._session.prompt(
                f"Enter {prompt.secret_name}: ",
                is_password=True,
            ).strip()
            if value:
                save = self._prompt_yes_no(
                    f"Save {prompt.secret_name} to your Morph secrets?",
                    default=False,
                )
                return SecretSubmission(value, save)
            if prompt.optional:
                return SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)
            self._print("This secret is required. Enter a value or interrupt the run.")

    def finish(self, state: TemplateRunState) -> None:
        self._render_state(state, force=True)

    def _prompt_choice(self, message: str, choices: list[str], *, default: str) -> str:
        expected = {choice.lower(): choice.lower() for choice in choices}
        options = "/".join(choices)
        while True:
            answer = (
                self._session.prompt(
                    f"{message} [{options}]: ",
                    default=default,
                )
                .strip()
                .lower()
            )
            if answer in expected:
                return expected[answer]
            self._print(f"Expected one of: {', '.join(choices)}")

    def _prompt_yes_no(self, message: str, *, default: bool) -> bool:
        suffix = "Y/n" if default else "y/N"
        while True:
            answer = self._session.prompt(f"{message} [{suffix}]: ").strip().lower()
            if not answer:
                return default
            if answer in {"y", "yes"}:
                return True
            if answer in {"n", "no"}:
                return False
            self._print("Expected yes or no.")

    def _render_target_browser(
        self,
        owned_templates: list[TemplateTarget],
        search_results: list[AliasSearchResult],
    ) -> dict[int, str]:
        lines = [
            "Devbox Template Runner",
            "======================",
            "Choose an owned template or search shared aliases.",
            "",
        ]
        choices: dict[int, str] = {}
        if owned_templates:
            lines.append("Owned Templates")
            lines.append("---------------")
            for idx, item in enumerate(owned_templates, start=1):
                choices[idx] = item.template_id
                lines.append(
                    f"{idx:>2}. {item.name} ({item.template_id}) [{item.cached_step_count}/{item.step_count}] {item.status}"
                )
        else:
            lines.extend(
                ["Owned Templates", "---------------", "No owned templates found."]
            )

        if search_results:
            lines.extend(["", "Shared Alias Search", "-------------------"])
            for offset, item in enumerate(
                search_results, start=len(owned_templates) + 1
            ):
                choices[offset] = item.alias
                description = f" ({item.description})" if item.description else ""
                lines.append(
                    f"{offset:>2}. {item.alias} -> {item.template_id}{description}"
                )

        lines.extend(["", "Tip: type `/search bun,vnc` to search shared aliases."])
        self._clear()
        self._print("\n".join(lines))
        return choices

    def _render_state(self, state: TemplateRunState, *, force: bool = False) -> None:
        rendered = self._render_state_text(state)
        now = time.monotonic()
        if not force:
            if rendered == self._last_rendered:
                return
            if now - self._last_render_at < _PROMPT_TOOLKIT_REFRESH_SECONDS:
                return
        self._clear()
        self._print(rendered)
        self._last_rendered = rendered
        self._last_render_at = now

    def _render_state_text(self, state: TemplateRunState) -> str:
        lines: list[str] = []

        target_label = state.target.name
        if state.target.alias:
            target_label += f" (alias {state.target.alias})"
        lines.extend(
            [
                "Template Run",
                "============",
                f"Template: {target_label}",
                f"Template ID: {state.target.template_id}",
                f"Status: {state.status}",
                f"Run: {state.run_id or '-'}",
                f"Elapsed: {state.duration_seconds:.1f}s",
            ]
        )
        if state.last_message:
            lines.append(f"Progress: {state.last_message}")

        lines.extend(["", "Build Status", "============"])
        if state.target.steps:
            for step in state.target.steps:
                status = state.step_statuses.get(step.index)
                if status is None:
                    if step.index < state.target.cached_step_count:
                        status = "cached"
                    else:
                        status = "pending"
                marker = ">" if state.current_step_index == step.index else " "
                lines.append(
                    f"{marker}{step.index:>2}  {status:<10}  {_truncate_line(step.label, 96)}"
                )
        else:
            lines.append("Steps will appear as events arrive.")

        lines.extend(["", "Live Output", "==========="])
        if (
            state.current_step_index is not None
            and state.current_step_index in state.output_by_step
        ):
            body = "".join(
                state.output_by_step[state.current_step_index][-40:]
            ).splitlines()
        else:
            body = list(state.recent_output[-40:])
        if not body:
            body = ["Waiting for workflow output..."]
        lines.extend(body[-20:])

        lines.extend(["", "Actions", "======="])
        lines.extend(self._footer_lines(state))
        return "\n".join(lines).rstrip() + "\n"

    def _footer_lines(self, state: TemplateRunState) -> list[str]:
        lines: list[str] = []
        if state.waiting_for_secret is not None:
            prompt = state.waiting_for_secret
            lines.append(f"Secret input required: {prompt.secret_name}")
            if prompt.optional:
                lines.append("Optional secret. Choose a value or skip.")
            else:
                lines.append(
                    "Required secret. The workflow is paused until you respond."
                )
            if prompt.has_saved:
                lines.append("A saved secret is available for this name.")
            countdown = _format_secret_countdown(prompt)
            if countdown:
                lines.append(f"Auto-skip: {countdown}")
        elif state.status == "completed":
            if state.completed_devbox_id:
                lines.append(f"Devbox ready: {state.completed_devbox_id}")
                lines.append(f"Next: morphcloud devbox ssh {state.completed_devbox_id}")
                for session_name in _template_tmux_session_names(state.target):
                    lines.append(
                        "Next: morphcloud devbox terminal connect "
                        f"{state.completed_devbox_id} {session_name}"
                    )
            else:
                lines.append("Workflow completed.")
            for service in state.exposed_services:
                url = _coerce_optional_str(service.get("url"))
                if not url:
                    continue
                name = _coerce_optional_str(service.get("name")) or "service"
                lines.append(f"Service {name}: {url}")
        elif state.status == "error" and state.error_message:
            lines.append(f"Build failed: {state.error_message}")
        elif state.status == "cancelled" and state.error_message:
            lines.append(f"Workflow cancelled: {state.error_message}")
        else:
            lines.append(
                "Watching the workflow stream. Output and step status update in place."
            )
        for warning in state.warnings[-3:]:
            lines.append(f"Warning: {warning}")
        return lines


RichTemplatePresenter = PromptToolkitTemplatePresenter


def build_presenter(*, plain: bool, json_output: bool) -> BaseTemplatePresenter:
    interactive = bool(
        getattr(click.get_text_stream("stdin"), "isatty", lambda: False)()
    ) and bool(getattr(click.get_text_stream("stdout"), "isatty", lambda: False)())
    if json_output:
        return PlainTemplatePresenter(interactive=False, quiet=True)
    if plain or not interactive:
        return PlainTemplatePresenter(interactive=interactive, quiet=False)
    return PromptToolkitTemplatePresenter()


def _coerce_bool(value: t.Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes"}:
            return True
        if lowered in {"0", "false", "no"}:
            return False
    return default


def _coerce_int(value: t.Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _coerce_optional_int(value: t.Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _coerce_str(value: t.Any, *, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _coerce_optional_str(value: t.Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text != "" else None


def _require_str(value: t.Any, *, name: str) -> str:
    text = _coerce_optional_str(value)
    if text is None:
        raise TemplateRunnerError(f"Missing {name} in template workflow response.")
    return text


def _extract_error_detail(payload: t.Any) -> str | None:
    if isinstance(payload, str):
        text = payload.strip()
        return text or None
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        if isinstance(detail, dict):
            inner = detail.get("message") or detail.get("detail")
            if isinstance(inner, str) and inner.strip():
                return inner.strip()
            error_block = detail.get("error")
            if isinstance(error_block, dict):
                message = error_block.get("message")
                if isinstance(message, str) and message.strip():
                    return message.strip()
        error_block = payload.get("error")
        if isinstance(error_block, dict):
            message = error_block.get("message")
            if isinstance(message, str) and message.strip():
                return message.strip()
        message = payload.get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()
    return None


def _get_mapping_value(value: t.Any, key: str) -> t.Any:
    if isinstance(value, dict):
        return value.get(key)
    return None


def _looks_like_template_id(value: str) -> bool:
    return bool(_TEMPLATE_ID_RE.match(value))


def _quote(value: str) -> str:
    return urllib.parse.quote(str(value), safe="")


def _resolve_completed_devbox_id(payload: dict[str, t.Any]) -> str | None:
    for key in ("instanceId", "instance_id", "devboxId", "devbox_id", "id"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    instance = payload.get("instance")
    if isinstance(instance, dict):
        instance_id = instance.get("id")
        if isinstance(instance_id, str) and instance_id:
            return instance_id
    return None


def _event_history_key(event: TemplateRunEvent) -> str:
    return f"{event.event_type}:{json.dumps(event.payload, sort_keys=True)}"


def _extract_http_services(payload: dict[str, t.Any]) -> list[dict[str, t.Any]]:
    services: list[dict[str, t.Any]] = []
    for candidate in (_extract_single_http_service(payload),):
        if candidate is not None:
            _merge_exposed_service(services, candidate)

    instance = payload.get("instance")
    container = instance if isinstance(instance, dict) else payload
    networking = container.get("networking") if isinstance(container, dict) else None
    raw_services = None
    if isinstance(networking, dict):
        raw_services = networking.get("http_services")
    elif isinstance(container, dict):
        raw_services = container.get("http_services")

    if isinstance(raw_services, list):
        for item in raw_services:
            service = _extract_single_http_service(item)
            if service is not None:
                _merge_exposed_service(services, service)
    return services


def _extract_single_http_service(
    payload: dict[str, t.Any] | t.Any,
) -> dict[str, t.Any] | None:
    if not isinstance(payload, dict):
        return None
    http_service = payload.get("http_service")
    source = http_service if isinstance(http_service, dict) else payload
    name = _coerce_optional_str(
        source.get("name") or payload.get("serviceName") or payload.get("service_name")
    )
    port = _coerce_optional_int(
        source.get("port") or payload.get("servicePort") or payload.get("service_port")
    )
    url = _coerce_optional_str(
        source.get("url") or payload.get("serviceUrl") or payload.get("service_url")
    )
    auth_mode = _coerce_optional_str(
        source.get("auth_mode") or payload.get("authMode") or payload.get("auth_mode")
    )
    if not any([name, port is not None, url]):
        return None
    return {
        "name": name,
        "port": port,
        "url": url,
        "auth_mode": auth_mode,
    }


def _merge_exposed_service(
    services: list[dict[str, t.Any]], service: dict[str, t.Any]
) -> None:
    candidate_name = _coerce_optional_str(service.get("name"))
    candidate_port = _coerce_optional_int(service.get("port"))
    candidate_url = _coerce_optional_str(service.get("url"))
    for existing in services:
        if (
            _coerce_optional_str(existing.get("name")) == candidate_name
            and _coerce_optional_int(existing.get("port")) == candidate_port
            and _coerce_optional_str(existing.get("url")) == candidate_url
        ):
            return
    services.append(service)


def _template_tmux_session_names(target: TemplateTarget) -> tuple[str, ...]:
    values: list[str] = []
    for step in target.steps:
        if step.step_type != "tmuxSession" or not step.session_name:
            continue
        if step.session_name in values:
            continue
        values.append(step.session_name)
    return tuple(values)


def _format_secret_countdown(prompt: SecretPromptState) -> str | None:
    if prompt.deadline_at_ms is not None:
        remaining_ms = max(0, prompt.deadline_at_ms - int(time.time() * 1000))
        remaining_seconds = remaining_ms // 1000
        return f"{remaining_seconds}s remaining"
    if prompt.countdown_seconds is not None:
        return f"{prompt.countdown_seconds}s remaining"
    return None


def _truncate_line(value: str, max_length: int) -> str:
    line = value.splitlines()[0] if "\n" in value else value
    if len(line) <= max_length:
        return line
    return line[: max_length - 1] + "…"


__all__ = [
    "AliasSearchResult",
    "BaseTemplatePresenter",
    "InstantStartAvailability",
    "PlainTemplatePresenter",
    "PromptToolkitTemplatePresenter",
    "RichTemplatePresenter",
    "SKIP_OPTIONAL_SECRET_TOKEN",
    "SecretPromptState",
    "SecretSubmission",
    "TemplateRunEvent",
    "TemplateRunOptions",
    "TemplateRunResult",
    "TemplateRunnerError",
    "TemplateStepSummary",
    "TemplateTarget",
    "TemplateWorkflowRunner",
    "TemplateWorkflowTransport",
    "USE_SAVED_SECRET_TOKEN",
    "build_presenter",
]
