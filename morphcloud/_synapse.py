"""Managed Synapse sessions for Morph instances."""
from __future__ import annotations
import asyncio
import hashlib
import importlib
import importlib.metadata
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
import click
from packaging.version import InvalidVersion, Version
from .api import Instance, MorphCloudClient
from .cli_runtime import MorphRuntimeContext
from .plugins import installer as plugin_installer
METADATA_KEY = 'morph.synapse.v1'
RECORD_KIND = 'morphcloud.instance.synapse'
DEVBOX_RECORD_KIND = 'morphcloud.devbox.synapse'
RECORD_KINDS = frozenset({RECORD_KIND, DEVBOX_RECORD_KIND})
RECORD_VERSION = 1
CODEX_PACKAGE = '@openai/codex'
CODEX_VERSION = '0.150.1'
SYNAPSE_PACKAGE = 'morphcloud-synapse-service'
MIN_SYNAPSE_VERSION = Version('0.3.9')
RUNNER_VCPUS = 1
RUNNER_MEMORY_MIB = 1024
RUNNER_DISK_MIB = 1024
REQUIRED_CAPABILITIES = frozenset({'agents.codex-tui-attach.v1', 'agents.runner-spec.v1', 'resources.attach-existing-instance.v1', 'sessions.names.v1'})

class SynapseIntegrationError(click.ClickException):
    """A dependency or lifecycle contract prevents a safe attachment."""

class SynapseOwnershipError(SynapseIntegrationError):
    """Recorded resources cannot be proven to belong to this integration."""

class SynapseCapabilityError(SynapseIntegrationError):
    """The deployed Synapse contract cannot perform the requested lifecycle."""

@dataclass(frozen=True, slots=True)
class SynapseRecord:
    kind: str
    version: int
    endpoint: str
    instance_id: str
    session_id: str
    session_name: str
    objective: str
    agent_id: str
    resource_id: str
    binding: str
    runner_vcpus: int
    runner_memory_mib: int
    runner_disk_mib: int

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(',', ':'), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> SynapseRecord:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise SynapseOwnershipError(f'Instance metadata {METADATA_KEY!r} is not valid JSON. Remove it manually after verifying any referenced Synapse resources.') from exc
        if not isinstance(payload, dict) or set(payload) != set(cls.__annotations__):
            raise SynapseOwnershipError(f'Instance metadata {METADATA_KEY!r} has an unsupported shape. Remove it manually after verifying any referenced Synapse resources.')
        try:
            record = cls(**payload)
        except TypeError as exc:
            raise SynapseOwnershipError(f'Instance metadata {METADATA_KEY!r} is incomplete.') from exc
        if record.kind not in RECORD_KINDS or record.version != RECORD_VERSION:
            raise SynapseOwnershipError(f'Instance metadata {METADATA_KEY!r} uses an unsupported record version.')
        if (record.runner_vcpus, record.runner_memory_mib, record.runner_disk_mib) != (RUNNER_VCPUS, RUNNER_MEMORY_MIB, RUNNER_DISK_MIB):
            raise SynapseOwnershipError('Recorded Synapse agent runner size is not 1/1 GiB/1 GiB.')
        required_text = (record.endpoint, record.instance_id, record.session_id, record.session_name, record.objective, record.agent_id, record.resource_id, record.binding)
        if any((not isinstance(value, str) or not value.strip() for value in required_text)):
            raise SynapseOwnershipError('Recorded Synapse resource identities are invalid.')
        return record

class LifecycleAdapter(Protocol):
    endpoint: str

    async def require_capabilities(self) -> None:
        ...

    async def validate(self, record: SynapseRecord, instance_id: str) -> None:
        ...

    async def create(self, instance_id: str, *, replacement_of: str | None=None) -> SynapseRecord:
        ...

    async def close(self, record: SynapseRecord) -> None:
        ...

    async def aclose(self) -> None:
        ...

class SynapseTarget(Protocol):
    id: str
    metadata: Mapping[str, Any] | None

    def set_metadata(self, metadata: dict[str, Any]) -> None:
        ...

def _session_identity(instance_id: str, *, resource_kind: str='instance') -> tuple[str, str]:
    suffix = ''.join((character for character in instance_id.lower() if character.isalnum()))[-24:]
    name_prefix = 'morph' if resource_kind == 'instance' else f'morph-{resource_kind}'
    return (f'{name_prefix}-{suffix}', f'Manage Morph {resource_kind} {instance_id}')

def _session_attempt_name(base_name: str, attempt: str) -> str:
    if attempt == 'initial':
        return base_name
    digest = hashlib.sha256(attempt.encode()).hexdigest()[:8]
    return f'{base_name}-{digest}'

def _is_owned_session_name(name: str, base_name: str) -> bool:
    if name == base_name:
        return True
    suffix = name.removeprefix(f'{base_name}-')
    return len(suffix) == 8 and all((character in '0123456789abcdef' for character in suffix))

class SynapseSDKAdapter:
    """Strict adapter around the plugin SDK's public session and agent handles."""

    def __init__(self, morph_client: MorphCloudClient, *, resource_kind: str='instance') -> None:
        if resource_kind not in {'instance', 'devbox'}:
            raise ValueError(f'unsupported Synapse resource kind: {resource_kind}')
        client_module = importlib.import_module('synapse_sdk.client')
        self.resource_kind = resource_kind
        self.record_kind = RECORD_KIND if resource_kind == 'instance' else DEVBOX_RECORD_KIND
        self.endpoint = os.environ.get('SYNAPSE_BASE_URL', 'https://synapse.svc.cloud.morph.so').rstrip('/')
        self._client = client_module.SynapseClient(base_url=self.endpoint, api_key=morph_client.api_key, organization_id=os.environ.get('SYNAPSE_ORGANIZATION_ID'), client_surface='morphcloud-cli')

    async def require_capabilities(self) -> None:
        advertised = set((await self._client.capabilities()).capabilities)
        resource_capability = f'resources.attach-existing-{self.resource_kind}.v1'
        required = REQUIRED_CAPABILITIES - {'resources.attach-existing-instance.v1'} | {resource_capability}
        missing = sorted(required - advertised)
        if missing:
            raise SynapseCapabilityError(f'Synapse cannot yet attach this existing {self.resource_kind} with the requested 1 vCPU / 1 GiB RAM / 1 GiB disk agent runner. Missing capabilities: ' + ', '.join(missing) + '. No session or runner was created.')

    async def validate(self, record: SynapseRecord, instance_id: str) -> None:
        if record.endpoint.rstrip('/') != self.endpoint or record.instance_id != instance_id or record.kind != getattr(self, 'record_kind', RECORD_KIND):
            raise SynapseOwnershipError('Recorded Synapse resources target another endpoint or instance.')
        resource_kind = getattr(self, 'resource_kind', 'instance')
        expected_name, expected_objective = _session_identity(instance_id, resource_kind=resource_kind)
        if not _is_owned_session_name(record.session_name, expected_name) or record.objective != expected_objective:
            raise SynapseOwnershipError('Recorded Synapse session identity is not integration-owned.')
        session = await self._client.sessions.get(record.session_id)
        if session.id != record.session_id or session.view.name != record.session_name or session.view.objective != expected_objective or (str(session.view.state) != 'active'):
            raise SynapseOwnershipError('Recorded Synapse session is absent, inactive, or changed.')
        resources = await session.resources()
        if len(resources) != 1:
            raise SynapseOwnershipError('Recorded Synapse session has additional resources; refusing to reuse or destroy it.')
        attached = resources[0]
        safe_metadata = dict(getattr(attached, 'safe_metadata', {}) or {})
        attached_resource_kind = safe_metadata.get('morph_resource_kind', 'instance')
        if attached.id != record.resource_id or attached.remote_id != instance_id or attached.binding != record.binding or (str(attached.ownership) != 'borrowed') or (str(attached.access) != 'read_write_execute') or (str(attached.state) != 'ready') or (attached_resource_kind != getattr(self, 'resource_kind', 'instance')):
            raise SynapseOwnershipError(f'Recorded Synapse {resource_kind} attachment is absent or changed.')
        agents = await session.agents()
        if len(agents) != 1:
            raise SynapseOwnershipError('Recorded Synapse session has additional agents; refusing to reuse or destroy it.')
        agent = agents[0]
        if agent.id != record.agent_id or agent.session_id != record.session_id or str(agent.state) not in {'ready', 'busy'} or (tuple(agent.allowed_resource_bindings) != (record.binding,)):
            raise SynapseOwnershipError('Recorded Synapse agent is absent or changed.')

    async def create(self, instance_id: str, *, replacement_of: str | None=None) -> SynapseRecord:
        resource_kind = getattr(self, 'resource_kind', 'instance')
        base_name, objective = _session_identity(instance_id, resource_kind=resource_kind)
        attempt = replacement_of or 'initial'
        closed_sessions: set[str] = set()
        while True:
            name = _session_attempt_name(base_name, attempt)
            record_kind = getattr(self, 'record_kind', RECORD_KIND)
            create_key = f'{record_kind}:{instance_id}:{attempt}'
            created_session = await self._client.sessions.create(objective=objective, name=name, idempotency_key=create_key, wait=True, timeout_seconds=600)
            session = await self._client.sessions.get(created_session.id)
            if str(session.view.state) == 'active':
                break
            if str(created_session.view.state) != 'active':
                raise SynapseIntegrationError('Synapse created a closed session attempt; no runner was created.')
            if session.id in closed_sessions:
                raise SynapseIntegrationError('Synapse returned a cycle of closed session attempts; no runner was created.')
            closed_sessions.add(session.id)
            attempt = session.id
        attach_method_name = f'attach_existing_{resource_kind}'
        if not hasattr(session, attach_method_name):
            await session.close(idempotency_key=f'{create_key}:rollback', wait=True, timeout_seconds=1200)
            raise SynapseCapabilityError(f'The installed Synapse plugin advertises existing-{resource_kind} attachment but does not expose SessionHandle.{attach_method_name}(). The new session was closed.')
        binding = 'instance'
        try:
            attach_existing = getattr(session, attach_method_name)
            attached = await attach_existing(instance_id, display_name=f'Morph {resource_kind} {instance_id}', access='read_write_execute', ownership='borrowed', binding=binding, idempotency_key=f'{create_key}:resource')
            parameters = inspect.signature(session.create_agent).parameters
            required_parameters = {'runner_vcpus', 'runner_memory_mib', 'runner_disk_mib'}
            if not required_parameters <= set(parameters):
                raise SynapseCapabilityError('The installed Synapse plugin cannot select an exact agent runner size.')
            agent = await session.create_agent(system_prompt=f'Work only on the attached Morph {resource_kind} {instance_id}. Use the instance binding for all filesystem and command work.', allowed_resource_bindings=(binding,), idempotency_scope=f'{record_kind}:{instance_id}', runner_vcpus=RUNNER_VCPUS, runner_memory_mib=RUNNER_MEMORY_MIB, runner_disk_mib=RUNNER_DISK_MIB)
        except BaseException:
            await session.close(idempotency_key=f'{create_key}:rollback', wait=True, timeout_seconds=1200)
            raise
        return SynapseRecord(kind=record_kind, version=RECORD_VERSION, endpoint=self.endpoint, instance_id=instance_id, session_id=session.id, session_name=name, objective=objective, agent_id=agent.id, resource_id=attached.id, binding=binding, runner_vcpus=RUNNER_VCPUS, runner_memory_mib=RUNNER_MEMORY_MIB, runner_disk_mib=RUNNER_DISK_MIB)

    async def close(self, record: SynapseRecord) -> None:
        session = await self._client.sessions.get(record.session_id)
        await session.close(idempotency_key=f'{record.kind}:force:{record.session_id}', wait=True, timeout_seconds=1200)

    async def aclose(self) -> None:
        await self._client.aclose()

class SynapseLifecycleManager:

    def __init__(self, adapter: LifecycleAdapter) -> None:
        self.adapter = adapter

    @staticmethod
    def _write_record(instance: SynapseTarget, record: SynapseRecord | None) -> None:
        metadata = dict(instance.metadata or {})
        if record is None:
            metadata.pop(METADATA_KEY, None)
        else:
            metadata[METADATA_KEY] = record.to_json()
        instance.set_metadata(metadata)

    async def prepare(self, instance: SynapseTarget, *, force: bool) -> tuple[SynapseRecord, bool]:
        await self.adapter.require_capabilities()
        raw_record = (instance.metadata or {}).get(METADATA_KEY)
        record = SynapseRecord.from_json(raw_record) if raw_record else None
        if record is not None:
            await self.adapter.validate(record, instance.id)
            if not force:
                return (record, True)
            await self.adapter.close(record)
            self._write_record(instance, None)
        created = await self.adapter.create(instance.id, replacement_of=record.session_id if record is not None else None)
        self._write_record(instance, created)
        return (created, False)

def _plugin_available() -> bool:
    for module in ('synapse_cli.main', 'synapse_sdk.client'):
        try:
            if importlib.util.find_spec(module) is None:
                return False
        except (ModuleNotFoundError, ValueError):
            return False
    return True

def _installed_synapse_version() -> Version | None:
    if not _plugin_available():
        return None
    try:
        raw_version = importlib.metadata.version(SYNAPSE_PACKAGE)
        return Version(raw_version)
    except (importlib.metadata.PackageNotFoundError, InvalidVersion):
        return None

def ensure_synapse_plugin(client: MorphCloudClient) -> None:
    installed_version = _installed_synapse_version()
    if installed_version is not None and installed_version >= MIN_SYNAPSE_VERSION:
        return
    upgrading = installed_version is not None
    try:
        catalog = client.simple_index
        entry = catalog.get_plugin('synapse')
        if not entry.enabled:
            raise SynapseIntegrationError('The Synapse plugin exists but is disabled. Ask an administrator to enable it.')
        target = entry.install_target
        if not target:
            raise SynapseIntegrationError('The Synapse plugin has no installable artifact.')
        if entry.artifact_url:
            plugin_installer.install_artifact(entry.artifact_url, upgrade=upgrading, python_executable=sys.executable)
        else:
            plugin_installer.install_requirement(target, index_url=catalog.authenticated_simple_index_url(), upgrade=upgrading, python_executable=sys.executable)
        plugin_installer.verify_cli_entry_point(command_name='synapse', python_executable=sys.executable)
        importlib.invalidate_caches()
    except SynapseIntegrationError:
        raise
    except Exception as exc:
        raise SynapseIntegrationError('Unable to install the Synapse plugin. Run `morphcloud plugin install synapse` in this environment and retry.') from exc
    if not _plugin_available():
        raise SynapseIntegrationError('The Synapse plugin installation completed but its SDK/CLI modules are unavailable.')
    resolved_version = _installed_synapse_version()
    if resolved_version is None or resolved_version < MIN_SYNAPSE_VERSION:
        raise SynapseIntegrationError(f'Synapse plugin {MIN_SYNAPSE_VERSION} or newer is required. Run `morphcloud plugin upgrade synapse` in this environment and retry.')

def _managed_codex_directory(environment: Mapping[str, str]) -> Path:
    data_home = environment.get('XDG_DATA_HOME')
    root = Path(data_home) if data_home else Path.home() / '.local' / 'share'
    return root / 'morphcloud' / 'codex' / CODEX_VERSION

def ensure_codex(*, environment: dict[str, str] | None=None, runner: Callable[..., subprocess.CompletedProcess[str]]=subprocess.run) -> dict[str, str]:
    target_environment = dict(os.environ if environment is None else environment)
    if shutil.which('codex', path=target_environment.get('PATH')):
        return target_environment
    npm = shutil.which('npm', path=target_environment.get('PATH'))
    if npm is None:
        raise SynapseIntegrationError(f'Codex is not installed and npm is unavailable. Install Node.js/npm, then retry; Morph will vendor {CODEX_PACKAGE}@{CODEX_VERSION} without a global install.')
    target = _managed_codex_directory(target_environment)
    target.mkdir(mode=448, parents=True, exist_ok=True)
    os.chmod(target, 448)
    executable = target / 'node_modules' / '.bin' / 'codex'
    if not executable.is_file():
        process = runner([npm, 'install', '--no-audit', '--no-fund', '--prefix', str(target), f'{CODEX_PACKAGE}@{CODEX_VERSION}'], check=False, capture_output=True, text=True, timeout=300, env=target_environment)
        if process.returncode != 0 or not executable.is_file():
            detail = (process.stderr or process.stdout or '').strip().splitlines()[-1:]
            suffix = f' ({detail[0][:240]})' if detail else ''
            raise SynapseIntegrationError(f'Unable to vendor Codex {CODEX_VERSION}{suffix}')
    target_environment['PATH'] = os.pathsep.join([str(executable.parent), target_environment.get('PATH', '')])
    return target_environment

def attach_with_synapse_cli(record: SynapseRecord, client: MorphCloudClient, *, detach: bool, environment: dict[str, str]) -> None:
    command = [sys.executable, '-m', 'synapse_cli.main', '--base-url', record.endpoint, 'attach', record.session_id, '--agent', record.agent_id]
    if detach:
        command.append('--detach')
    child_environment = dict(environment)
    child_environment['MORPH_API_KEY'] = str(client.api_key)
    result = subprocess.run(command, check=False, env=child_environment)
    if result.returncode:
        raise SynapseIntegrationError(f'Synapse attach exited with status {result.returncode}; rerun the same command to reuse the session.')

def _translate_synapse_sdk_error(exc: Exception) -> SynapseIntegrationError | None:
    """Turn expected plugin transport failures into normal Click diagnostics."""
    try:
        client_module = importlib.import_module('synapse_sdk.client')
        error_type = getattr(client_module, 'SynapseError')
    except (AttributeError, ImportError):
        return None
    if not isinstance(exc, error_type):
        return None
    detail = str(exc).strip() or exc.__class__.__name__
    return SynapseIntegrationError(f'Synapse request failed: {detail}')

def run_instance_synapse(instance: SynapseTarget, client: MorphCloudClient, *, force: bool, detach: bool, resource_kind: str='instance') -> None:
    ensure_synapse_plugin(client)
    adapter = SynapseSDKAdapter(client, resource_kind=resource_kind)

    async def prepare() -> tuple[SynapseRecord, bool]:
        try:
            return await SynapseLifecycleManager(adapter).prepare(instance, force=force)
        finally:
            await adapter.aclose()
    try:
        record, reused = asyncio.run(prepare())
    except SynapseIntegrationError:
        raise
    except Exception as exc:
        translated = _translate_synapse_sdk_error(exc)
        if translated is None:
            raise
        raise translated from exc
    environment = ensure_codex()
    click.secho(f"{('Reusing' if reused else 'Created')} Synapse session {record.session_id}", fg='cyan', err=True)
    attach_with_synapse_cli(record, client, detach=detach, environment=environment)

def chat_instance(instance: Instance, ctx: MorphRuntimeContext, force: bool=False, detach: bool=False) -> None:
    """Open a managed Codex chat attached to this instance."""
    run_instance_synapse(instance, ctx.client, force=force, detach=detach)
