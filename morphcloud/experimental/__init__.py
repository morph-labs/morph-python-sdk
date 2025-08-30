from __future__ import annotations

import hashlib
import logging
import stat
import threading
import time
import typing
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Literal, Tuple, Union

import paramiko

from morphcloud.api import Instance, MorphCloudClient
from morphcloud.api import Snapshot as _Snapshot

# Configure logging for the experimental module
logger = logging.getLogger(__name__)


# ──────────────────────────── Logging System ─────────────────────────── #
class LoggingSystem:
    """Structured logging system to replace the Rich renderer."""

    def __init__(self):
        self._lock = threading.Lock()

    def add_system_panel(self, title: str, body: str):
        """Log system operations with structured data."""
        logger.info(f"{title}: {body}")

    def add_panel(self, panel_content: str):
        """Log panel content."""
        logger.info(panel_content)

    def refresh(self):
        """No-op for logging compatibility."""
        pass

    @property
    def lock(self):
        return self._lock

    @property
    def console(self):
        """Return a simple console-like object for compatibility."""
        return SimpleConsole()

    @contextmanager
    def pause(self):
        """Compatibility context manager."""
        with self._lock:
            yield

    @contextmanager
    def start_live(self):
        """Compatibility context manager for live rendering."""
        yield


class SimpleConsole:
    """Simple console replacement for logging."""

    def print(self, message: str):
        """Print message using logger."""
        logger.info(message)

    def clear(self):
        """No-op for logging compatibility."""
        pass


renderer = LoggingSystem()


# ───────────────────────────── Helpers ──────────────────────────── #


STREAM_MAX_LINES = 24
ELLIPSIS = "⋯ [output truncated] ⋯\n"

# each deque element: (line_text, style_or_None)
Line = tuple[str, str | None]


def _append_stream_chunk(
    buf: deque[Line],
    chunk: str,
    *,
    style: str | None = None,
    max_lines: int = STREAM_MAX_LINES,
):
    """Append stream chunk to buffer and log it."""
    # Split new data into logical lines (keep newlines)
    for ln in chunk.splitlines(keepends=True):
        buf.append((ln, style))
        # Log each line immediately
        if style == "error":
            logger.error(f"STDERR: {ln.rstrip()}")
        else:
            logger.info(f"STDOUT: {ln.rstrip()}")

    # Trim old lines
    while len(buf) > max_lines:
        buf.popleft()

    if len(buf) == max_lines:
        logger.info(ELLIPSIS.strip())


# ───────────────────────── Verification System ──────────────────────── #
class VerificationPanel:
    def __init__(self, verify_funcs: list[typing.Callable]):
        self._statuses = {v.__name__: "⏳ running" for v in verify_funcs}
        logger.info(
            "🔍 Verify: Starting verification",
            extra={"verify_funcs": [f.__name__ for f in verify_funcs]},
        )

    def update(self, fn_name: str, new_status: str):
        self._statuses[fn_name] = new_status
        logger.info(f"🔍 Verify: {fn_name} - {new_status}")

        # Check overall status
        if all(s.startswith("✅") for s in self._statuses.values()):
            logger.info("🔍 Verify: All verifications passed")
        elif any(s.startswith("❌") for s in self._statuses.values()):
            logger.error("🔍 Verify: Some verifications failed")

    @property
    def panel(self) -> str:
        """Return panel content as string for compatibility."""
        return f"Verification status: {self._statuses}"


# ───────────────────── Anthropic / agent setup ─────────────────── #

StreamTuple = Union[
    Tuple[Literal["stdout"], str],
    Tuple[Literal["stdin"], str],
    Tuple[Literal["exit_code"], int],
]


def ssh_stream(
    ssh: paramiko.SSHClient,
    command: str,
    *,
    encoding: str = "utf-8",
    chunk_size: int = 4096,
    poll: float = 0.01,
) -> Iterator[StreamTuple]:
    transport = ssh.get_transport()
    assert transport is not None, "SSH transport must be connected"
    chan = transport.open_session()
    chan.exec_command(command)

    while True:
        while chan.recv_ready():
            data = chan.recv(chunk_size)
            if data:
                yield ("stdout", data.decode(encoding, errors="replace"))
        while chan.recv_stderr_ready():
            data = chan.recv_stderr(chunk_size)
            if data:
                yield ("stderr", data.decode(encoding, errors="replace"))
        if (
            chan.exit_status_ready()
            and not chan.recv_ready()
            and not chan.recv_stderr_ready()
        ):
            break
        time.sleep(poll)

    yield ("exit_code", chan.recv_exit_status())
    chan.close()


def instance_exec(
    instance,
    command: str,
    on_stdout: typing.Callable[[str], None],
    on_stderr: typing.Callable[[str], None],
) -> int:
    with instance.ssh() as ssh:
        ssh_client = ssh._client  # type: ignore[attr-defined]
        for msg in ssh_stream(ssh_client, command):
            match msg:
                case ("stdout", txt):
                    on_stdout(txt)
                case ("stderr", txt):
                    on_stderr(txt)
                case ("exit_code", code):
                    return code
    raise RuntimeError("SSH stream did not yield exit code.")


client = MorphCloudClient()

InvalidateFn = typing.Callable[["Snapshot"], bool]

# MorphBrowser is available via: from morphcloud.experimental.browser import MorphBrowser


class Snapshot:
    def __init__(self, snapshot: _Snapshot):
        self.snapshot = snapshot

    @property
    def id(self) -> str:
        """Return the ID of the inner snapshot."""
        return self.snapshot.id

    @classmethod
    def create(
        cls,
        name: str,
        image_id: str = "morphvm-minimal",
        vcpus: int = 1,
        memory: int = 4096,
        disk_size: int = 8192,
        invalidate: InvalidateFn | bool = False,
    ) -> "Snapshot":
        logger.info(
            "🖼  Snapshot.create()",
            extra={
                "image_id": image_id,
                "vcpus": vcpus,
                "memory": memory,
                "disk_size": disk_size,
                "snapshot_name": name,
            },
        )
        if invalidate:
            invalidate_fn = (
                invalidate
                if isinstance(invalidate, typing.Callable)
                else lambda _: invalidate
            )
            snaps = client.snapshots.list(digest=name)
            for s in snaps:
                if invalidate_fn(Snapshot(s)):
                    s.delete()
        digest = f"{name}-{image_id}-{vcpus}-{memory}-{disk_size}"
        snap = client.snapshots.create(
            image_id=image_id,
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            digest=digest,
            metadata={"name": name},
        )
        return cls(snap)

    @classmethod
    def from_snapshot_id(cls, snapshot_id: str) -> "Snapshot":
        logger.info(
            "🔍 Snapshot.from_snapshot_id()", extra={"snapshot_id": snapshot_id}
        )
        snap = client.snapshots.get(snapshot_id)
        return cls(snap)

    @classmethod
    def from_tag(cls, tag: str) -> typing.Optional["Snapshot"]:
        logger.info("🏷️  Snapshot.from_tag()", extra={"tag": tag})
        snapshots = client.snapshots.list(metadata={"tag": tag})
        if not snapshots:
            return None
        # Return the most recent snapshot (assuming list is ordered by creation time)
        # The first item in the list is the most recently created
        return cls(snapshots[0])

    def start(
        self,
        metadata: typing.Optional[typing.Dict[str, str]] = None,
        ttl_seconds: typing.Optional[int] = None,
        ttl_action: typing.Union[None, typing.Literal["stop", "pause"]] = None,
    ):
        # Merge default metadata with any provided metadata
        default_metadata = dict(root=self.snapshot.id)
        if metadata:
            default_metadata.update(metadata)

        return client.instances.start(
            snapshot_id=self.snapshot.id,
            metadata=default_metadata,
            ttl_seconds=ttl_seconds,
            ttl_action=ttl_action,
        )

    @contextmanager
    def boot(
        self,
        vcpus: int | None = None,
        memory: int | None = None,
        disk_size: int | None = None,
    ):
        logger.info(
            "🔄 Snapshot.boot()",
            extra={
                "vcpus": vcpus or self.snapshot.spec.vcpus,
                "memory": memory or self.snapshot.spec.memory,
                "disk_size": disk_size or self.snapshot.spec.disk_size,
            },
        )
        with client.instances.boot(
            snapshot_id=self.snapshot.id,
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
        ) as inst:
            yield inst

    def key_to_digest(self, key: str) -> str:
        """
        Computes a digest hash based on the parent snapshot and operation key.
        Follows the same pattern as api.py's compute_chain_hash method.
        """
        parent_content = (self.snapshot.digest or "") + self.snapshot.id
        hasher = hashlib.sha256()
        hasher.update(parent_content.encode("utf-8"))
        hasher.update(b"\n")
        hasher.update(key.encode("utf-8"))
        return hasher.hexdigest()

    def apply(
        self,
        func,
        key: str | None = None,
        start_fn: typing.Union[
            typing.ContextManager[Instance],
            typing.Callable[[], typing.ContextManager[Instance]],
            None,
        ] = None,
        invalidate: InvalidateFn | bool = False,
        debug: bool = False,
    ):
        invalidate_fn = (
            invalidate
            if isinstance(invalidate, typing.Callable)
            else lambda _: invalidate
        )
        if key:
            digest = self.key_to_digest(key)
            snaps = client.snapshots.list(digest=digest)
            if invalidate:
                valid = []
                for s in snaps:
                    if invalidate_fn(Snapshot(s)):
                        s.delete()
                    else:
                        valid.append(s)
                snaps = valid
            if snaps:
                return Snapshot(snaps[0])

        if start_fn is None:
            context_manager = self.start(ttl_seconds=24 * 60 * 60, ttl_action="stop")
        elif callable(start_fn):
            context_manager = start_fn(ttl_seconds=24 * 60 * 60, ttl_action="stop")
        else:
            context_manager = start_fn

        if debug:
            inst = context_manager.__enter__()
            try:
                res = func(inst)
                inst = inst if res is None else res

                new_snapshot = Snapshot(
                    inst.snapshot(digest=self.key_to_digest(key) if key else None)
                )

                logger.info(
                    f"Debug mode - Command succeeded, stopping instance {inst.id}"
                )
                context_manager.__exit__(None, None, None)

                return new_snapshot

            except Exception as exc:
                logger.warning(
                    f"Debug mode - Command failed, leaving instance {inst.id} running for debugging "
                    f"(24-hour TTL active): {exc}"
                )
                raise
        else:
            with context_manager as inst:
                res = func(inst)
                inst = inst if res is None else res
                return Snapshot(
                    inst.snapshot(digest=self.key_to_digest(key) if key else None)
                )

    # -------------- run with stream between CMD/RET -------------- #
    def run(
        self, command: str, debug: bool = False, invalidate: InvalidateFn | bool = False
    ):
        logger.info(
            "🚀 Snapshot.run()", extra={"command": command, "debug_mode": debug}
        )

        def execute(instance):
            logger.info(
                "🖥  Snapshot.run() - Starting command execution",
                extra={"command": command, "debug_mode": debug},
            )

            buf = deque()

            def _out(c):
                _append_stream_chunk(buf, c)

            def _err(c):
                _append_stream_chunk(buf, c, style="error")

            exit_code = instance_exec(instance, command, _out, _err)
            logger.info(
                "🖥  Snapshot.run() - Command completed",
                extra={"command": command, "exit_code": exit_code, "debug_mode": debug},
            )

            if exit_code != 0:
                # Get the last few lines from buffer for error context
                recent_output = "".join([line for line, _ in list(buf)[-5:]])
                raise Exception(
                    f"Command execution failed: {command} exit={exit_code} recent_output={recent_output}"
                )

        return self.apply(execute, key=command, invalidate=invalidate, debug=debug)

    def copy_(self, src: str, dest: str, invalidate: InvalidateFn | bool = False):
        """
        Copy files/directories to the instance via SSH, similar to Docker COPY.

        Args:
            src: Source path on local machine (file or directory)
            dest: Destination path on remote instance
            invalidate: Whether to invalidate existing cached snapshots

        Returns:
            New Snapshot with the copied files
        """
        logger.info("📁 Snapshot.copy_()", extra={"src": src, "dest": dest})

        def execute_copy(instance):
            logger.info("📋 File Copy Progress - Starting copy operation")

            def update_progress(message: str, style: str | None = None):
                if style == "error":
                    logger.error(f"Copy Progress: {message}")
                else:
                    logger.info(f"Copy Progress: {message}")

            try:
                with instance.ssh() as ssh:
                    ssh_client = ssh._client
                    sftp = ssh_client.open_sftp()

                    src_path = Path(src)

                    # Check if source exists
                    if not src_path.exists():
                        update_progress(f"❌ Source not found: {src}", "error")
                        raise FileNotFoundError(f"Source path does not exist: {src}")

                    update_progress(f"📂 Copying {src} to {dest}")

                    # Helper function to create remote directories
                    def ensure_remote_dir(remote_path: str):
                        try:
                            sftp.stat(remote_path)
                        except FileNotFoundError:
                            # Directory doesn't exist, create it
                            parent = str(Path(remote_path).parent)
                            if parent != remote_path and parent != "/":
                                ensure_remote_dir(parent)
                            sftp.mkdir(remote_path)
                            update_progress(f"📁 Created directory: {remote_path}")

                    # Helper function to copy a single file
                    def copy_file(local_file: Path, remote_file: str):
                        # Ensure the remote directory exists
                        remote_dir = str(Path(remote_file).parent)
                        if remote_dir != remote_file:
                            ensure_remote_dir(remote_dir)

                        # Copy the file
                        sftp.put(str(local_file), remote_file)
                        update_progress(f"📄 Copied file: {local_file.name}")

                        # Try to preserve permissions
                        try:
                            local_stat = local_file.stat()
                            sftp.chmod(remote_file, local_stat.st_mode)
                        except (OSError, AttributeError):
                            # Permissions may not be preservable, continue anyway
                            pass

                    # Helper function to copy directory recursively
                    def copy_directory(local_dir: Path, remote_dir: str):
                        ensure_remote_dir(remote_dir)

                        for item in local_dir.iterdir():
                            remote_item = f"{remote_dir}/{item.name}"

                            if item.is_file():
                                copy_file(item, remote_item)
                            elif item.is_dir():
                                copy_directory(item, remote_item)

                    # Main copy logic
                    if src_path.is_file():
                        # Copying a single file
                        if dest.endswith("/"):
                            # Destination is a directory, copy file into it
                            remote_file = f"{dest.rstrip('/')}/{src_path.name}"
                        else:
                            # Check if destination is an existing directory
                            try:
                                dest_stat = sftp.stat(dest)
                                if stat.S_ISDIR(dest_stat.st_mode):
                                    remote_file = f"{dest}/{src_path.name}"
                                else:
                                    remote_file = dest
                            except FileNotFoundError:
                                # Destination doesn't exist, treat as file
                                remote_file = dest

                        copy_file(src_path, remote_file)

                    elif src_path.is_dir():
                        # Copying a directory
                        if dest.endswith("/"):
                            # Copy directory contents into destination
                            remote_base = dest.rstrip("/")
                            copy_directory(src_path, f"{remote_base}/{src_path.name}")
                        else:
                            # Check if destination exists and is a directory
                            try:
                                dest_stat = sftp.stat(dest)
                                if stat.S_ISDIR(dest_stat.st_mode):
                                    copy_directory(src_path, f"{dest}/{src_path.name}")
                                else:
                                    # Destination exists but is not a directory
                                    update_progress(
                                        f"❌ Destination exists and is not a directory: {dest}",
                                        "error",
                                    )
                                    raise ValueError(
                                        f"Cannot copy directory to non-directory: {dest}"
                                    )
                            except FileNotFoundError:
                                # Destination doesn't exist, create it
                                copy_directory(src_path, dest)

                    sftp.close()
                    update_progress("✅ Copy completed successfully")

            except Exception as e:
                update_progress(f"❌ Copy failed: {str(e)}", "error")
                raise

        return self.apply(execute_copy, key=f"copy-{src}-{dest}", invalidate=invalidate)

    # ------------------------------------------------------------------ #
    # Remaining Snapshot methods unchanged                               #
    # ------------------------------------------------------------------ #
    def do(
        self,
        instructions: str,
        verify=None,
        invalidate: InvalidateFn | bool = False,
    ):
        verify_funcs = [verify] if isinstance(verify, typing.Callable) else verify or []
        digest = self.key_to_digest(
            instructions + ",".join(v.__name__ for v in verify_funcs)
        )

        logger.info(
            "🔍 Snapshot.do() - Starting verification",
            extra={
                "instructions": instructions,
                "verify_funcs": [v.__name__ for v in verify_funcs],
            },
        )

        snaps_exist = client.snapshots.list(digest=digest)
        if snaps_exist and not invalidate:
            logger.info("💾 Cached ✅ - Using existing snapshot")
            return Snapshot(snaps_exist[0])

        def verifier(inst):
            if not verify_funcs:
                return True
            vpanel = VerificationPanel(verify_funcs)

            all_ok = True
            verification_errors = []

            for func in verify_funcs:
                try:
                    func(inst)
                    vpanel.update(func.__name__, "✅ passed")
                except Exception as e:
                    error_msg = str(e)
                    vpanel.update(func.__name__, f"❌ failed ({error_msg})")
                    verification_errors.append(f"{func.__name__}: {error_msg}")
                    all_ok = False

            # Store errors for debugging
            if verification_errors:
                logger.error(
                    "Verification errors", extra={"errors": verification_errors}
                )

            return all_ok

        def run_verification(instance):
            logger.info(
                "🔍 Starting verification", extra={"instructions": instructions}
            )
            success = verifier(instance)
            if not success:
                raise Exception("Verification failed.")
            return instance

        new_snap = self.apply(run_verification, key=digest, invalidate=invalidate)

        logger.info("🔍 Verification completed successfully")
        return new_snap

    def resize(
        self,
        vcpus: int | None = None,
        memory: int | None = None,
        disk_size: int | None = None,
        invalidate: bool = False,
    ):
        logger.info(
            "🔧 Snapshot.resize()",
            extra={
                "vcpus": vcpus or self.snapshot.spec.vcpus,
                "memory": memory or self.snapshot.spec.memory,
                "disk_size": disk_size or self.snapshot.spec.disk_size,
            },
        )

        @contextmanager
        def boot_snapshot():
            with self.boot(vcpus=vcpus, memory=memory, disk_size=disk_size) as instance:
                time.sleep(10)
                yield instance

        return self.apply(
            lambda x: x,
            key=f"resize-{vcpus}-{memory}-{disk_size}",
            start_fn=boot_snapshot,
            invalidate=invalidate,
        )

    @contextmanager
    def deploy(
        self,
        name: str,
        port: int,
        min_replicas: int = 0,
        max_replicas: int = 3,
    ):
        logger.info(
            "🌐 Snapshot.deploy()",
            extra={
                "service_name": name,
                "port": port,
                "min_replicas": min_replicas,
                "max_replicas": max_replicas,
            },
        )
        with self.start() as instance:
            url = instance.expose_http_service(name=name, port=port)
            logger.info(f"Started service at {url}")
            yield instance, url

    def tag(self, tag: str):
        logger.info("🏷  Snapshot.tag()", extra={"tag": tag})
        meta = self.snapshot.metadata.copy()
        meta.update({"tag": tag})
        self.snapshot.set_metadata(meta)
        logger.info("Snapshot tagged successfully!")

    @contextmanager
    @staticmethod
    def pretty_build():
        with renderer.start_live():
            yield renderer
