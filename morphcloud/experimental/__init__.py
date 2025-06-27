from __future__ import annotations

import time
import typing
import threading

from collections import deque
from contextlib import contextmanager
from typing import Iterator, Tuple, Union, Literal

import paramiko

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.tree import Tree

from morphcloud.api import MorphCloudClient, Instance, Snapshot as _Snapshot


PALETTE = {
    "bg":       "#2D2D2D",
    "success":  "#CEFF1A",
    "error":    "#F23F42",
    "accent":   "#F2777A",
    "running":  "yellow",
}

def _colour(kind: str) -> str:
    return PALETTE.get(kind, "white")


# ──────────────────────────── Renderer ─────────────────────────── #
class Renderer:
    """Rich console wrapper that enforces dark background + palette."""

    def __init__(self):
        theme = Theme(
            {
                "success":  PALETTE["success"],
                "error":    PALETTE["error"],
                "accent":   PALETTE["accent"],
                "running":  PALETTE["running"],
            }
        )
        self._console = Console(
            theme=theme,
            color_system="truecolor",
            style=f"white on {PALETTE['bg']}",
            highlight=False,
        )
        self._console.clear()

        self._lock   = threading.Lock()
        self._panels: list[Panel] = []
        self._live = Live(
            Group(),
            console=self._console,
            refresh_per_second=16,
            vertical_overflow="visible",
        )

    def _refresh(self):
        self._live.update(Group(*self._panels))

    def start_live(self):
        return self._live

    def add_panel(self, panel: Panel):
        with self._lock:
            self._panels.append(panel)
            self._refresh()

    def refresh(self):
        with self._lock:
            self._refresh()

    def add_system_panel(self, title: str, body: str):
        self.add_panel(
            Panel(
                Text(body),
                title=title,
                border_style=_colour("accent"),
                style=f"on {PALETTE['bg']}",
            )
        )

    @property
    def lock(self):
        return self._lock

    @property
    def console(self):
        return self._console

    @contextmanager
    def pause(self):
        """
        Stop Live and block other threads from updating while the
        block executes (typically to read user input).
        """
        with self._lock:
            # suspend Live by stopping its refresh thread
            live_was_running = self._live.is_started
            if live_was_running:
                self._live.stop()

            try:
                yield
            finally:
                # resume Live and refresh the screen
                if live_was_running:
                    self._live.start(refresh=True)
                else:
                    self._refresh_nolock()

    # ───────────────────────── internal ────────────────────────────── #

    def _refresh_nolock(self):
        """Update Live – assumes self._lock is already held."""
        self._live.update(Group(*self._panels))


renderer = Renderer()


# ───────────────────────────── Helpers ──────────────────────────── #


STREAM_MAX_LINES = 24
ELLIPSIS         = "⋯ [output truncated] ⋯\n"

# each deque element: (line_text, style_or_None)
Line = tuple[str, str | None]


def _append_stream_chunk(
    buf: deque[Line],
    chunk: str,
    text_obj: Text,
    *,
    style: str | None = None,
    max_lines: int = STREAM_MAX_LINES,
):
    # 1. split new data into logical lines (keep newlines)
    for ln in chunk.splitlines(keepends=True):
        buf.append((ln, style))

    # 2. trim old lines
    while len(buf) > max_lines:
        buf.popleft()

    # 3. rebuild the Rich Text object
    text_obj.plain = ""          # ‹NEW› wipe text
    text_obj.spans.clear()       # ‹NEW› wipe previous styling

    if len(buf) == max_lines:
        text_obj.append(ELLIPSIS, style="dim")

    for ln, st in buf:
        text_obj.append(ln, style=st)


def prettify_run(instructions: str) -> Panel:
    return Panel(
        Text(instructions, style="bold"),
        title="▶️ Run",
        border_style=_colour("accent"),
        style=f"on {PALETTE['bg']}",
    )


# ───────────────────────── Verification UI ──────────────────────── #
class VerificationPanel:
    def __init__(self, verify_funcs: list[typing.Callable]):
        self._statuses = {v.__name__: "⏳ running" for v in verify_funcs}
        self._panel = Panel(
            Align.left(self._make_table()),
            title="🔍 Verify",
            border_style=_colour("running"),
            style=f"on {PALETTE['bg']}",
        )

    def _make_table(self) -> Table:
        table = Table.grid(padding=(0, 1))
        table.add_column(justify="right", style=_colour("running"))
        table.add_column()
        for fn, status in self._statuses.items():
            colour = (
                _colour("success") if status.startswith("✅") else
                _colour("error")   if status.startswith("❌") else
                _colour("running")
            )
            table.add_row(fn, f"[{colour}]{status}[/{colour}]")
        return table

    @property
    def panel(self) -> Panel:
        return self._panel

    def update(self, fn_name: str, new_status: str):
        self._statuses[fn_name] = new_status
        self._panel.renderable = Align.left(self._make_table())
        if all(s.startswith("✅") for s in self._statuses.values()):
            self._panel.border_style = _colour("success")
        elif any(s.startswith("❌") for s in self._statuses.values()):
            self._panel.border_style = _colour("error")
        renderer.refresh()


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
                yield ("stdin", data.decode(encoding, errors="replace"))
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
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
                case ("stdin", txt):
                    on_stderr(txt)
                case ("exit_code", code):
                    return code
    raise RuntimeError("SSH stream did not yield exit code.")


client = MorphCloudClient()

InvalidateFn = typing.Callable[["Snapshot"], bool]

class Snapshot:
    def __init__(self, snapshot: _Snapshot):
        self.snapshot = snapshot

    @property
    def id(self) -> str:
        """Return the ID of the inner snapshot."""
        return self.snapshot.id

    @classmethod
    def create(cls, name: str, image_id: str = "morphvm-minimal",
               vcpus: int = 1, memory: int = 4096, disk_size: int = 8192,
               invalidate: InvalidateFn | bool = False) -> "Snapshot":
        renderer.add_system_panel("🖼  Snapshot.create()",
                                  f"image_id={image_id}, vcpus={vcpus}, memory={memory}MB, disk={disk_size}MB")
        if invalidate:
            invalidate_fn = invalidate if isinstance(invalidate, typing.Callable) else lambda _: invalidate
            snaps = client.snapshots.list(digest=name)
            for s in snaps:
                if invalidate_fn(Snapshot(s)):
                    s.delete()
        snap = client.snapshots.create(image_id=image_id, vcpus=vcpus,
                                       memory=memory, disk_size=disk_size,
                                       digest=name, metadata={"name": name})
        return cls(snap)

    @classmethod
    def from_snapshot_id(cls, snapshot_id: str) -> "Snapshot":
        renderer.add_system_panel("🔍 Snapshot.from_snapshot_id()",
                                  f"snapshot_id={snapshot_id}")
        snap = client.snapshots.get(snapshot_id)
        return cls(snap)

    def start(self):
        return client.instances.start(snapshot_id=self.snapshot.id, metadata=dict(root=self.snapshot.id))

    @contextmanager
    def boot(
        self,
        vcpus: int | None = None,
        memory: int | None = None,
        disk_size: int | None = None,
    ):
        renderer.add_system_panel(
            "🔄 Snapshot.boot()",
            f"vcpus={vcpus or self.snapshot.spec.vcpus}, memory={memory or self.snapshot.spec.memory}MB, disk={disk_size or self.snapshot.spec.disk_size}MB"
        )
        with client.instances.boot(
            snapshot_id=self.snapshot.id,
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
        ) as inst:
            yield inst


    def key_to_digest(self, key: str) -> str:
        return (self.snapshot.digest or "") + self.snapshot.id + key

    def apply(
        self,
        func,
        key: str | None = None,
        start_fn: typing.Union[
            typing.ContextManager[Instance], 
            typing.Callable[[], typing.ContextManager[Instance]], 
            None
        ] = None,
        invalidate: InvalidateFn | bool = False,
    ):
        invalidate_fn = invalidate if isinstance(invalidate, typing.Callable) else lambda _: invalidate
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
            context_manager = self.start()
        elif callable(start_fn):
            context_manager = start_fn()
        else:
            context_manager = start_fn

        with context_manager as inst:
            res = func(inst)
            inst = inst if res is None else res
            return Snapshot(inst.snapshot(digest=self.key_to_digest(key) if key else None))

    # -------------- run with stream between CMD/RET -------------- #
    def run(self, command: str, invalidate: InvalidateFn | bool = False):
        renderer.add_system_panel("🚀 Snapshot.run()", command)

        def execute(instance):
            header_tbl = Table.grid(padding=(0, 1))
            header_tbl.add_column(justify="right", style=_colour("running"))
            header_tbl.add_column()
            header_tbl.add_row("CMD", command)

            footer_tbl = Table.grid(padding=(0, 1))
            footer_tbl.add_column(justify="right", style=_colour("running"))
            footer_tbl.add_column()

            out_text = Text()
            grp = Group(Align.left(header_tbl), Align.left(out_text), Align.left(footer_tbl))
            panel = Panel(grp, title="🖥  Snapshot.run()", border_style=_colour("accent"), style=f"on {PALETTE['bg']}")
            renderer.add_panel(panel)

            buf = deque()

            def _out(c): _append_stream_chunk(buf, c, out_text); renderer.refresh()
            def _err(c): _append_stream_chunk(buf, c, out_text, style=_colour("error")); renderer.refresh()

            exit_code = instance_exec(instance, command, _out, _err)
            footer_tbl.add_row("RET", str(exit_code))
            renderer.refresh()

            if exit_code != 0:
                raise Exception(f"Command execution failed: {command} exit={exit_code} stdout={out_text.plain} stderr={out_text.plain}")

        return self.apply(execute, key=command, invalidate=invalidate)

    # ------------------------------------------------------------------ #
    # Remaining Snapshot methods unchanged                               #
    # ------------------------------------------------------------------ #
    def do(
        self,
        instructions: str,
        verify=None,
        invalidate: InvalidateFn | bool = False,
    ):
        verify_funcs = (
            [verify] if isinstance(verify, typing.Callable) else verify or []
        )
        digest = self.key_to_digest(
            instructions + ",".join(v.__name__ for v in verify_funcs)
        )

        tree_root = Tree("")
        renderer.add_panel(
            Panel(
                tree_root,
                title=instructions,
                border_style=_colour("accent"),
                style=f"on {PALETTE['bg']}",
            )
        )

        agent_visual = Agent(tree_root)

        snaps_exist = client.snapshots.list(digest=digest)
        if snaps_exist and not invalidate:
            agent_visual._set_status("💾 Cached ✅", "success")
            return Snapshot(snaps_exist[0])

        def verifier(inst):
            if not verify_funcs:
                return True
            current_agent: Agent | None = getattr(_agent_local, "current_agent", None)
            if current_agent is None:
                return True

            vpanel = VerificationPanel(verify_funcs)
            current_agent._append(vpanel.panel)

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

            # Store errors in the current agent for tool result retrieval
            if current_agent:
                current_agent._last_verification_errors = verification_errors

            return all_ok

        def run_agent(instance):
            agent_visual.run(instance, instructions, verifier)
            if agent_visual.running:
                raise Exception("Agent execution did not complete successfully.")
            return instance

        new_snap = self.apply(run_agent, key=digest, invalidate=invalidate)

        if agent_visual.running:
            agent_visual._set_status("💾 Cached ✅", "success")

        return new_snap

    def resize(
        self,
        vcpus: int | None = None,
        memory: int | None = None,
        disk_size: int | None = None,
        invalidate: bool = False,
    ):
        renderer.add_system_panel(
            "🔧 Snapshot.resize()",
            f"vcpus={vcpus or self.snapshot.spec.vcpus}, memory={memory or self.snapshot.spec.memory}MB, disk={disk_size or self.snapshot.spec.disk_size}MB"
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
        renderer.console.print(
            Panel(
                Text(
                    f"name={name}\nport={port}\nreplicas=[{min_replicas},{max_replicas}]",
                    justify="left",
                ),
                title="🌐 Snapshot.deploy()",
                border_style=_colour("success"),
                style=f"on {PALETTE['bg']}",
            )
        )
        with self.start() as instance:
            url = instance.expose_http_service(name=name, port=port)
            renderer.console.print(
                f"[{_colour('success')}]Started service at {url}[/]"
            )
            yield instance, url

    def tag(self, tag: str):
        renderer.console.print(
            Panel(
                Text(f"tag={tag}", justify="left"),
                title="🏷  Snapshot.tag()",
                border_style=_colour("accent"),
                style=f"on {PALETTE['bg']}",
            )
        )
        meta = self.snapshot.metadata.copy()
        meta.update({"tag": tag})
        self.snapshot.set_metadata(meta)
        renderer.console.print(
            f"[{_colour('success')}]Snapshot tagged successfully!"
        )

    @contextmanager
    @staticmethod
    def pretty_build():
        with renderer.start_live():
            yield renderer
