"""Experimental local template YAML executor."""

from __future__ import annotations

import dataclasses
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time
import typing as t
import urllib.parse

import httpx
import yaml

from .template_runner import (
    SKIP_OPTIONAL_SECRET_TOKEN,
    USE_SAVED_SECRET_TOKEN,
    BaseTemplatePresenter,
    SecretPromptState,
    SecretSubmission,
    TemplateRunEvent,
    TemplateRunnerError,
    TemplateRunOptions,
    TemplateRunResult,
    TemplateRunState,
    TemplateStepSummary,
    TemplateTarget,
)


@dataclasses.dataclass(frozen=True)
class LocalTemplateStep:
    """Parsed local step definition."""

    summary: TemplateStepSummary
    command: str | None = None
    optional: bool = False
    redact: bool = True
    service_name: str | None = None
    service_port: int | None = None


@dataclasses.dataclass(frozen=True)
class LocalTemplateSpec:
    """Parsed local template YAML."""

    path: pathlib.Path
    target: TemplateTarget
    steps: tuple[LocalTemplateStep, ...]
    working_directory: pathlib.Path
    display_path: str
    cleanup: t.Callable[[], None] | None = None


@dataclasses.dataclass(frozen=True)
class _ResolvedLocalTemplateSource:
    path: pathlib.Path
    yaml_text: str
    working_directory: pathlib.Path
    display_path: str
    template_id: str
    default_name: str
    cleanup: t.Callable[[], None] | None = None


class ExperimentalLocalTemplateRunner:
    """Run a template YAML locally using the shared template TUI presenters."""

    def run(
        self,
        yaml_path: str,
        *,
        options: TemplateRunOptions,
        presenter: BaseTemplatePresenter,
    ) -> TemplateRunResult:
        spec = load_local_template_spec(yaml_path)
        state = TemplateRunState(
            target=spec.target,
            status="running",
            mode="local",
            run_id=f"local-{int(time.time())}",
        )
        presenter.start(state)
        env = dict(os.environ)
        env.update(options.workflow_context)
        env.update(
            {
                key: value
                for key, value in options.runtime_secrets.items()
                if value not in {USE_SAVED_SECRET_TOKEN, SKIP_OPTIONAL_SECRET_TOKEN}
            }
        )
        redactions: list[str] = []
        state.last_message = f"Loaded local template from {spec.display_path}."
        presenter.update(state)

        try:
            for step in spec.steps:
                self._step_started(state, presenter, step)
                if step.summary.step_type == "command":
                    if not self._run_shell_step(
                        step,
                        state,
                        presenter,
                        env=env,
                        redactions=redactions,
                        cwd=spec.working_directory,
                    ):
                        break
                    continue

                if step.summary.step_type == "exportSecret":
                    resolved = self._resolve_local_secret(
                        step,
                        state,
                        presenter,
                        env=env,
                        options=options,
                    )
                    if resolved is _ABORT:
                        break
                    if isinstance(resolved, SecretSubmission):
                        value = resolved.value
                        if value == SKIP_OPTIONAL_SECRET_TOKEN:
                            state.warnings.append(
                                f"Skipped optional secret {step.summary.secret_name} in local mode."
                            )
                            value = None
                        elif value == USE_SAVED_SECRET_TOKEN:
                            value = env.get(step.summary.secret_name or "", "")
                            if not value and not step.optional:
                                state.status = "error"
                                state.error_message = f"No local environment value exists for {step.summary.secret_name}."
                                presenter.update(
                                    state,
                                    TemplateRunEvent(
                                        "error",
                                        {"message": state.error_message},
                                    ),
                                )
                                break
                        elif resolved.save_to_account:
                            state.warnings.append(
                                "Local mode does not save secrets to Morph. The value was used only for this run."
                            )
                    else:
                        value = resolved

                    if value:
                        secret_name = step.summary.secret_name or ""
                        env[secret_name] = value
                        if step.redact:
                            redactions.append(value)

                    if step.command:
                        if not self._run_shell_step(
                            step,
                            state,
                            presenter,
                            env=env,
                            redactions=redactions,
                            cwd=spec.working_directory,
                        ):
                            break
                    else:
                        self._step_completed(state, presenter, step)
                    continue

                if step.summary.step_type == "exposeHttpService":
                    port = step.service_port or 0
                    url = f"http://127.0.0.1:{port}" if port else ""
                    if port and not _port_is_open(port):
                        state.warnings.append(
                            f"Service {step.service_name or 'service'} is not listening on port {port}."
                        )
                    state.last_message = f"Local service {step.service_name or 'service'} available at {url or 'unknown'}."
                    state.exposed_services.append(
                        {
                            "name": step.service_name,
                            "port": port or None,
                            "url": url or None,
                            "auth_mode": None,
                        }
                    )
                    presenter.update(
                        state,
                        TemplateRunEvent(
                            "step_completed",
                            {
                                "index": step.summary.index,
                                "serviceName": step.service_name,
                                "servicePort": port or None,
                                "serviceUrl": url or None,
                            },
                            step.summary.index,
                        ),
                    )
                    self._step_completed(state, presenter, step, emit=False)
                    continue

                if step.summary.step_type == "tmuxSession":
                    self._run_tmux_step(
                        step,
                        state,
                        presenter,
                        cwd=spec.working_directory,
                    )
                    if state.status == "error":
                        break
                    continue

                state.status = "error"
                state.error_message = (
                    f"Unsupported local step type: {step.summary.step_type}"
                )
                presenter.update(
                    state,
                    TemplateRunEvent("error", {"message": state.error_message}),
                )
                break

            if state.status == "running":
                state.status = "completed"
                state.finished_at = time.time()
                state.last_message = "Local template run completed."
                presenter.update(
                    state,
                    TemplateRunEvent("completed", {"instanceId": None}),
                )
            presenter.finish(state)
            return TemplateRunResult.from_state(state)
        finally:
            try:
                presenter.close()
            finally:
                if spec.cleanup is not None:
                    try:
                        spec.cleanup()
                    except Exception:
                        pass

    def _step_started(
        self,
        state: TemplateRunState,
        presenter: BaseTemplatePresenter,
        step: LocalTemplateStep,
    ) -> None:
        state.current_step_index = step.summary.index
        state.step_statuses[step.summary.index] = "executing"
        state.output_by_step.setdefault(step.summary.index, [])
        state.last_message = f"Running {step.summary.label} locally."
        presenter.update(
            state,
            TemplateRunEvent(
                "step_started",
                {"index": step.summary.index, "stepType": step.summary.step_type},
                step.summary.index,
            ),
        )

    def _step_completed(
        self,
        state: TemplateRunState,
        presenter: BaseTemplatePresenter,
        step: LocalTemplateStep,
        *,
        emit: bool = True,
    ) -> None:
        state.step_statuses[step.summary.index] = "completed"
        state.current_step_index = step.summary.index
        state.last_message = f"Completed {step.summary.label} locally."
        if emit:
            presenter.update(
                state,
                TemplateRunEvent(
                    "step_completed",
                    {"index": step.summary.index},
                    step.summary.index,
                ),
            )

    def _run_shell_step(
        self,
        step: LocalTemplateStep,
        state: TemplateRunState,
        presenter: BaseTemplatePresenter,
        *,
        env: dict[str, str],
        redactions: list[str],
        cwd: pathlib.Path,
    ) -> bool:
        command = step.command or ""
        if not command.strip():
            self._step_completed(state, presenter, step)
            return True

        proc = subprocess.Popen(
            [_preferred_shell(), "-lc", command],
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                rendered = _redact_output(line, redactions)
                state.append_output(step.summary.index, rendered)
                presenter.update(
                    state,
                    TemplateRunEvent(
                        "output",
                        {"index": step.summary.index, "content": rendered},
                        step.summary.index,
                    ),
                )
        finally:
            if proc.stdout is not None:
                proc.stdout.close()

        return_code = proc.wait()
        if return_code != 0:
            state.status = "error"
            state.finished_at = time.time()
            state.step_statuses[step.summary.index] = "failed"
            state.error_message = f"Local step '{step.summary.label}' failed with exit code {return_code}."
            presenter.update(
                state,
                TemplateRunEvent(
                    "step_failed",
                    {
                        "index": step.summary.index,
                        "message": state.error_message,
                    },
                    step.summary.index,
                ),
            )
            return False

        self._step_completed(state, presenter, step)
        return True

    def _resolve_local_secret(
        self,
        step: LocalTemplateStep,
        state: TemplateRunState,
        presenter: BaseTemplatePresenter,
        *,
        env: dict[str, str],
        options: TemplateRunOptions,
    ) -> str | SecretSubmission | None | object:
        secret_name = step.summary.secret_name or ""
        explicit = options.runtime_secrets.get(secret_name)
        if explicit == USE_SAVED_SECRET_TOKEN:
            explicit = env.get(secret_name)
        if explicit == SKIP_OPTIONAL_SECRET_TOKEN:
            return SecretSubmission(SKIP_OPTIONAL_SECRET_TOKEN, False)
        if explicit:
            return explicit

        workflow_value = options.workflow_context.get(secret_name)
        if workflow_value:
            return workflow_value

        local_env = env.get(secret_name)
        if local_env:
            return local_env

        prompt = SecretPromptState(
            step_index=step.summary.index,
            secret_name=secret_name,
            has_saved=False,
            optional=step.optional,
            default_action="skip" if step.optional else "wait",
        )
        state.waiting_for_secret = prompt
        state.status = "awaiting_input"
        state.last_message = f"Waiting for {'optional' if step.optional else 'required'} local secret {secret_name}."
        presenter.update(
            state,
            TemplateRunEvent(
                "awaiting_input",
                {
                    "index": step.summary.index,
                    "secretName": secret_name,
                    "hasSaved": False,
                    "optional": step.optional,
                    "defaultAction": "skip" if step.optional else "wait",
                    "runId": state.run_id,
                },
                step.summary.index,
            ),
        )
        submission = presenter.prompt_for_secret(prompt, state)
        if submission is None:
            return _ABORT
        state.waiting_for_secret = None
        state.status = "running"
        state.last_message = f"Resolved local secret {secret_name}."
        presenter.update(state)
        return submission

    def _run_tmux_step(
        self,
        step: LocalTemplateStep,
        state: TemplateRunState,
        presenter: BaseTemplatePresenter,
        *,
        cwd: pathlib.Path,
    ) -> None:
        session_name = step.summary.session_name or ""
        command = step.command or ""
        if shutil.which("tmux") is None:
            state.warnings.append(
                f"tmux is not installed; skipped local tmuxSession {session_name or step.summary.index}."
            )
            self._step_completed(state, presenter, step)
            return

        check = subprocess.run(
            ["tmux", "has-session", "-t", session_name],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if check.returncode == 0:
            state.warnings.append(
                f"tmux session {session_name} already exists; skipped creating it locally."
            )
            self._step_completed(state, presenter, step)
            return

        result = subprocess.run(
            ["tmux", "new-session", "-d", "-s", session_name, command],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.stdout:
            rendered = result.stdout
            state.append_output(step.summary.index, rendered)
            presenter.update(
                state,
                TemplateRunEvent(
                    "output",
                    {"index": step.summary.index, "content": rendered},
                    step.summary.index,
                ),
            )
        if result.returncode != 0:
            state.status = "error"
            state.finished_at = time.time()
            state.step_statuses[step.summary.index] = "failed"
            state.error_message = f"tmuxSession {session_name} failed locally with exit code {result.returncode}."
            presenter.update(
                state,
                TemplateRunEvent(
                    "step_failed",
                    {
                        "index": step.summary.index,
                        "message": state.error_message,
                    },
                    step.summary.index,
                ),
            )
            return

        self._step_completed(state, presenter, step)


def load_local_template_spec(yaml_path: str) -> LocalTemplateSpec:
    source = _resolve_local_template_source(yaml_path)

    try:
        data = yaml.safe_load(source.yaml_text) or {}
    except Exception as exc:
        raise TemplateRunnerError(f"Failed to parse template YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise TemplateRunnerError("Template YAML must be a mapping/object.")

    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise TemplateRunnerError(
            "Template YAML must contain a non-empty 'steps' list."
        )

    steps = tuple(
        _parse_local_step(index, step) for index, step in enumerate(raw_steps)
    )
    target = TemplateTarget(
        template_id=source.template_id,
        name=_coerce_optional_str(data.get("name")) or source.default_name,
        description=_coerce_optional_str(data.get("description")),
        status="local",
        step_count=len(steps),
        cached_step_count=0,
        steps=tuple(step.summary for step in steps),
    )
    return LocalTemplateSpec(
        path=source.path,
        target=target,
        steps=steps,
        working_directory=source.working_directory,
        display_path=source.display_path,
        cleanup=source.cleanup,
    )


def _resolve_local_template_source(yaml_path: str) -> _ResolvedLocalTemplateSource:
    requested_path = pathlib.Path(yaml_path).expanduser()
    if _looks_like_explicit_template_path(yaml_path):
        return _load_explicit_local_template_source(requested_path)

    remote_url = _morph_new_template_yaml_url(yaml_path)
    try:
        yaml_text = _fetch_morph_new_template_yaml(yaml_path)
    except TemplateRunnerError as exc:
        if requested_path.exists():
            return _load_explicit_local_template_source(requested_path)

        missing_path = requested_path.resolve()
        raise TemplateRunnerError(
            f"Template YAML file does not exist: {missing_path}. "
            f"Also failed to fetch shared template YAML from {remote_url}: {exc}"
        ) from exc

    temp_dir = pathlib.Path(tempfile.mkdtemp(prefix="morphcloud-template-"))
    temp_path = temp_dir / f"{_safe_template_filename(yaml_path)}.yaml"
    temp_path.write_text(yaml_text, encoding="utf-8")
    return _ResolvedLocalTemplateSource(
        path=temp_path,
        yaml_text=yaml_text,
        working_directory=pathlib.Path.cwd().resolve(),
        display_path=remote_url,
        template_id=remote_url,
        default_name=_safe_template_filename(yaml_path),
        cleanup=lambda: shutil.rmtree(temp_dir, ignore_errors=True),
    )


def _looks_like_explicit_template_path(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    candidate = pathlib.Path(stripped).expanduser()
    if candidate.is_absolute():
        return True
    if stripped.startswith((".", "~")):
        return True
    if any(separator and separator in stripped for separator in (os.sep, os.altsep)):
        return True
    return candidate.suffix.lower() in {".yaml", ".yml"}


def _load_explicit_local_template_source(
    requested_path: pathlib.Path,
) -> _ResolvedLocalTemplateSource:
    if not requested_path.exists():
        raise TemplateRunnerError(
            f"Template YAML file does not exist: {requested_path.resolve()}"
        )

    resolved_path = requested_path.resolve()
    if not resolved_path.is_file():
        raise TemplateRunnerError(f"Template YAML path is not a file: {resolved_path}")
    return _ResolvedLocalTemplateSource(
        path=resolved_path,
        yaml_text=resolved_path.read_text(encoding="utf-8"),
        working_directory=resolved_path.parent,
        display_path=str(resolved_path),
        template_id=str(resolved_path),
        default_name=resolved_path.stem,
    )


def _morph_new_template_yaml_url(alias: str) -> str:
    return f"https://morph.new/{urllib.parse.quote(alias.strip(), safe='')}/yaml"


def _fetch_morph_new_template_yaml(alias: str) -> str:
    url = _morph_new_template_yaml_url(alias)
    try:
        response = httpx.get(url, follow_redirects=True, timeout=10.0)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        reason = exc.response.reason_phrase or "HTTP error"
        raise TemplateRunnerError(f"{exc.response.status_code} {reason}") from exc
    except httpx.HTTPError as exc:
        raise TemplateRunnerError(str(exc)) from exc

    return response.text


def _safe_template_filename(value: str) -> str:
    filename = "".join(char if char.isalnum() else "-" for char in value).strip("-")
    while "--" in filename:
        filename = filename.replace("--", "-")
    return filename or "template"


def _parse_local_step(index: int, payload: t.Any) -> LocalTemplateStep:
    if not isinstance(payload, dict):
        raise TemplateRunnerError(f"Step {index} must be a mapping/object.")
    step_type = _coerce_optional_str(payload.get("type")) or "command"
    title = _coerce_optional_str(payload.get("title"))

    if step_type == "command":
        command = _command_value(payload)
        if not command:
            raise TemplateRunnerError(
                f"Step {index} command requires 'run' or 'command'."
            )
        summary = TemplateStepSummary(
            index=index,
            step_type=step_type,
            title=title,
            command=command,
        )
        return LocalTemplateStep(summary=summary, command=command)

    if step_type == "exportSecret":
        secret_name = _coerce_optional_str(
            payload.get("name") or _mapping_value(payload.get("export_secret"), "name")
        )
        if not secret_name:
            raise TemplateRunnerError(f"Step {index} exportSecret requires 'name'.")
        command = _command_value(payload)
        summary = TemplateStepSummary(
            index=index,
            step_type=step_type,
            title=title,
            command=command,
            secret_name=secret_name,
        )
        return LocalTemplateStep(
            summary=summary,
            command=command,
            optional=bool(payload.get("optional")),
            redact=_coerce_bool(payload.get("redact"), default=True),
        )

    if step_type == "exposeHttpService":
        service_cfg = (
            payload.get("http_service")
            if isinstance(payload.get("http_service"), dict)
            else payload
        )
        service_name = _coerce_optional_str(_mapping_value(service_cfg, "name"))
        service_port = _coerce_optional_int(_mapping_value(service_cfg, "port"))
        if not service_name or service_port is None:
            raise TemplateRunnerError(
                f"Step {index} exposeHttpService requires 'name' and 'port'."
            )
        summary = TemplateStepSummary(
            index=index,
            step_type=step_type,
            title=title,
            service_name=service_name,
            service_port=service_port,
        )
        return LocalTemplateStep(
            summary=summary,
            service_name=service_name,
            service_port=service_port,
        )

    if step_type == "tmuxSession":
        tmux_cfg = (
            payload.get("tmux_session")
            if isinstance(payload.get("tmux_session"), dict)
            else payload
        )
        session_name = _coerce_optional_str(_mapping_value(tmux_cfg, "name"))
        command = _command_value(payload)
        if not session_name or not command:
            raise TemplateRunnerError(
                f"Step {index} tmuxSession requires 'name' and 'run' or 'command'."
            )
        summary = TemplateStepSummary(
            index=index,
            step_type=step_type,
            title=title,
            command=command,
            session_name=session_name,
        )
        return LocalTemplateStep(summary=summary, command=command)

    raise TemplateRunnerError(
        f"Unsupported template step type '{step_type}' in step {index}."
    )


def _command_value(payload: dict[str, t.Any]) -> str | None:
    return _coerce_optional_str(
        payload.get("run")
        or payload.get("command")
        or _mapping_value(payload.get("export_secret"), "run")
        or _mapping_value(payload.get("export_secret"), "command")
        or _mapping_value(payload.get("tmux_session"), "run")
        or _mapping_value(payload.get("tmux_session"), "command")
    )


def _port_is_open(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        return sock.connect_ex(("127.0.0.1", port)) == 0
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _preferred_shell() -> str:
    if pathlib.Path("/bin/bash").exists():
        return "/bin/bash"
    return "/bin/sh"


def _redact_output(text: str, redactions: list[str]) -> str:
    rendered = text
    for value in redactions:
        if value:
            rendered = rendered.replace(value, "***")
    return rendered


def _mapping_value(payload: t.Any, key: str) -> t.Any:
    if isinstance(payload, dict):
        return payload.get(key)
    return None


def _coerce_optional_str(value: t.Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _coerce_optional_int(value: t.Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _coerce_bool(value: t.Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes"}:
            return True
        if lowered in {"0", "false", "no"}:
            return False
    return default


_ABORT = object()


__all__ = [
    "ExperimentalLocalTemplateRunner",
    "LocalTemplateSpec",
    "LocalTemplateStep",
    "load_local_template_spec",
]
