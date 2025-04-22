from __future__ import annotations

import fcntl
import io
import logging
import os
import pathlib
import select
import signal
import socket
import struct
import sys
import termios
import threading
import time
import tty
import typing
from dataclasses import dataclass

import paramiko

logger = logging.getLogger(__name__)


def _interactive_shell(
    client: paramiko.SSHClient, command: typing.Optional[str] = None
) -> int:
    """Create an interactive shell session or run a command interactively

    Returns:
        int: The exit code of the command or shell session
    """

    def get_terminal_size():
        """Get the size of the terminal window."""
        try:
            size = fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, " " * 8)
            rows, cols, xpix, ypix = struct.unpack("HHHH", size)
            return rows, cols
        except:
            return (24, 80)

    # Check if we're running in an interactive shell
    if not sys.stdin.isatty():
        raise SSHError("Interactive shell requires a TTY")

    # Get the original terminal settings
    oldtty = termios.tcgetattr(sys.stdin)

    try:
        # Set the terminal to raw mode
        tty.setraw(sys.stdin.fileno())

        # Get terminal dimensions and type
        rows, cols = get_terminal_size()
        term = os.getenv("TERM", "xterm")

        # Create the channel through SSHClient's underlying paramiko client
        channel = client.get_transport().open_session()
        channel.get_pty(term=term, width=cols, height=rows)

        if command:
            channel.exec_command(command)
        else:
            channel.invoke_shell()

        def sigwinch_handler(signum, frame):
            """Handle terminal window resize events."""
            rows, cols = get_terminal_size()
            channel.resize_pty(width=cols, height=rows)

        # Set up signal handler for window resize
        signal.signal(signal.SIGWINCH, sigwinch_handler)
        channel.settimeout(0.0)

        while True:
            r, w, e = select.select([channel, sys.stdin], [], [])
            if channel in r:
                try:
                    x = channel.recv(1024)
                    if len(x) == 0:
                        break
                    os.write(sys.stdout.fileno(), x)
                except Exception:
                    break
            if sys.stdin in r:
                x = os.read(sys.stdin.fileno(), 1024)
                if len(x) == 0:
                    break
                channel.send(x)

        # Wait for the channel to close and get exit status
        while not channel.exit_status_ready() and not channel.closed:
            time.sleep(0.1)

        exit_code = channel.recv_exit_status() if not channel.closed else -1
        return exit_code

    finally:
        # Restore the original terminal settings
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


class SSHError(Exception):
    """Base exception for SSH-related errors"""

    pass


class SSHCommandError(SSHError):
    """Exception raised when a command fails"""

    def __init__(
        self,
        command: typing.Union[str, list],
        returncode: int,
        stdout: str,
        stderr: str,
    ):
        self.command = command if isinstance(command, str) else " ".join(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"Command '{self.command}' failed with return code {returncode}\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        )


@dataclass
class CommandResult:
    """Result of running a command over SSH"""

    command: str

    returncode: int
    stdout: str
    stderr: str

    def raise_on_error(self):
        """Raise an exception if the command failed"""
        if self.returncode != 0:
            raise SSHCommandError(
                self.command, self.returncode, self.stdout, self.stderr
            )

    @property
    def exit_code(self):
        """The exit code of the command"""
        return self.returncode


class BackgroundProcess:
    """Represents a background process running on the remote machine"""

    def __init__(self, channel: paramiko.Channel, command: typing.Union[str, list]):
        self.channel = channel
        self.command = command if isinstance(command, str) else " ".join(command)
        self._stdout_buffer = io.StringIO()
        self._stderr_buffer = io.StringIO()

        self._stop_event = threading.Event()

        self._stdout_thread = threading.Thread(
            target=self._read_output,
            args=(self.channel.recv, self._stdout_buffer),
            name="BackgroundProcess-stdout",
        )
        self._stderr_thread = threading.Thread(
            target=self._read_output,
            args=(self.channel.recv_stderr, self._stderr_buffer),
            name="BackgroundProcess-stderr",
        )

        self._stdout_thread.start()
        self._stderr_thread.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _read_output(
        self, recv_func: typing.Callable[[int], bytes], buffer: io.StringIO
    ):
        try:
            while not self._stop_event.is_set():
                data = recv_func(1024)
                if not data:
                    break
                buffer.write(data.decode())
        except Exception as e:
            logger.debug("Exception in background process output thread: %s", e)
        finally:
            buffer.flush()

    @property
    def stdout(self) -> str:
        return self._stdout_buffer.getvalue()

    @property
    def stderr(self) -> str:
        return self._stderr_buffer.getvalue()

    def stop(self):
        """Stop the background process"""
        self._stop_event.set()
        if not self.channel.closed:
            self.channel.close()
        self._stdout_thread.join()
        self._stderr_thread.join()

    @property
    def completed(self) -> bool:
        """Check if the background process has completed"""
        return self.channel.exit_status_ready()


class PortTunnel:
    """Represents an SSH port tunnel"""

    def __init__(
        self, transport: paramiko.Transport, local_port: int, remote_port: int
    ):
        self.transport = transport
        self.local_port = local_port
        self.remote_port = remote_port
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", local_port))
        self._server.listen(5)

        self._running = True
        self._stop_event = threading.Event()
        self._connections = []

        self._thread = threading.Thread(
            target=self._forward_loop, name="PortTunnel-forward-loop"
        )
        self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _handle_connection(
        self, client_socket: socket.socket, channel: paramiko.Channel
    ):
        try:
            while self._running:
                r, w, x = select.select([client_socket, channel], [], [], 1.0)
                if client_socket in r:
                    data = client_socket.recv(4096)
                    if len(data) == 0:
                        break
                    channel.send(data)
                if channel in r:
                    data = channel.recv(4096)
                    if len(data) == 0:
                        break
                    client_socket.send(data)
        except Exception as e:
            logger.debug("Exception in tunnel connection handler: %s", e)
        finally:
            try:
                channel.close()
            except:
                pass
            try:
                client_socket.close()
            except:
                pass

    def _forward_loop(self):
        try:
            while self._running:
                client_socket = None
                try:
                    client_socket, addr = self._server.accept()
                    if not self._running:
                        # If stopped while accepting
                        if client_socket:
                            client_socket.close()
                        break
                    channel = self.transport.open_channel(
                        "direct-tcpip",
                        ("127.0.0.1", self.remote_port),
                        client_socket.getpeername(),
                    )
                    if channel is None:
                        logger.warning("Failed to open channel for port tunnel")
                        client_socket.close()
                        continue

                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, channel),
                        name="PortTunnel-connection",
                    )
                    thread.start()
                    self._connections.append(thread)
                except OSError as e:
                    if self._running:
                        logger.debug("OSError in forward loop: %s", e)
                except Exception as e:
                    logger.exception("Exception in tunnel forward loop: %s", e)
                    if client_socket:
                        client_socket.close()
        finally:
            self._server.close()

    def wait(self):
        """Wait until the tunnel is closed"""
        self._thread.join()

    def close(self):
        """Close the port tunnel"""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        try:
            # Connect to the server to break accept() call
            with socket.create_connection(("127.0.0.1", self.local_port)):
                pass
        except:
            pass
        self._thread.join()

        # Wait for all connection handler threads to finish
        for t in self._connections:
            t.join()


class SSHClient:
    """A clean, Pythonic SSH client interface"""

    def __init__(self, client: paramiko.SSHClient):
        self._client = client

    @typing.overload
    def run(
        self,
        command: typing.Union[str, list],
        background: typing.Literal[True],
        get_pty: bool = True,
        timeout: typing.Optional[float] = None,
    ) -> BackgroundProcess: ...

    @typing.overload
    def run(
        self,
        command: typing.Union[str, list],
        background: typing.Literal[False] = False,
        get_pty: bool = True,
        timeout: typing.Optional[float] = None,
    ) -> CommandResult: ...

    def run(
        self,
        command: typing.Union[str, list],
        background: bool = False,
        get_pty: bool = True,
        timeout: typing.Optional[float] = None,
    ) -> typing.Union[CommandResult, BackgroundProcess]:
        """Run a command with consistent output handling for both PTY and non-PTY modes"""
        if isinstance(command, list):
            command = " ".join(command)

        transport = self._client.get_transport()
        if not transport or not transport.is_active():
            raise SSHError("SSH transport is not active.")

        channel = transport.open_session()

        # Allocate a pseudo-terminal if requested:
        if get_pty:
            channel.get_pty(term="dumb")

        start = time.monotonic()
        channel.exec_command(command)

        # If the user wants a background process, return immediately:
        if background:
            return BackgroundProcess(channel, command)

        stdout_data = []
        stderr_data = []

        # Main read loop
        while True:
            # Pull any available data from stdout
            while channel.recv_ready():
                chunk = channel.recv(4096)
                stdout_data.append(chunk)

            # Pull any available data from stderr
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(4096)
                stderr_data.append(chunk)

            # Check if command is done (exit status ready)
            if channel.exit_status_ready():
                # Final pass: there could still be trailing data in the buffer
                # or arriving slightly after exit_status is set.
                final_start = time.monotonic()
                final_timeout = 0.1  # 100ms "grace period" (adjust as needed)

                while True:
                    data_read = False

                    # Read from stdout if any
                    while channel.recv_ready():
                        chunk = channel.recv(4096)
                        stdout_data.append(chunk)
                        data_read = True

                    # Read from stderr if any
                    while channel.recv_stderr_ready():
                        chunk = channel.recv_stderr(4096)
                        stderr_data.append(chunk)
                        data_read = True

                    if data_read:
                        # If we read anything, reset the final_start timer
                        final_start = time.monotonic()

                    # If we've gone final_timeout seconds with no new data, break
                    if (time.monotonic() - final_start) > final_timeout:
                        break

                    time.sleep(0.01)

                break  # exit main loop

            # Handle timeouts, if specified
            if timeout is not None and (time.monotonic() - start > timeout):
                # We'll raise an error but provide any partial stdout/stderr
                raise SSHError(
                    f"Command '{command}' timed out after {timeout} seconds.\n"
                    f"stdout: {b''.join(stdout_data).decode(errors='replace')}\n"
                    f"stderr: {b''.join(stderr_data).decode(errors='replace')}"
                )

            # Brief sleep to prevent busy-looping
            time.sleep(0.05)

        # Decode outputs
        stdout = b"".join(stdout_data).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_data).decode("utf-8", errors="replace")

        # Get the final exit code
        returncode = channel.recv_exit_status()

        return CommandResult(command, returncode, stdout, stderr)

    def copy_to(
        self,
        local_path: typing.Union[str, pathlib.Path],
        remote_path: str,
    ):
        """Copy a local file to the remote machine"""
        sftp = self._client.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
        finally:
            sftp.close()

    def copy_from(
        self,
        remote_path: str,
        local_path: typing.Union[str, pathlib.Path],
    ):
        """Copy a remote file to the local machine"""
        sftp = self._client.open_sftp()
        try:
            sftp.get(remote_path, str(local_path))
        finally:
            sftp.close()

    def tunnel(self, local_port: int, remote_port: int) -> PortTunnel:
        """Create a port tunnel from local machine to remote machine"""
        transport = self._client.get_transport()
        if not transport or not transport.is_active():
            raise SSHError("SSH transport is not active.")
        return PortTunnel(transport, local_port, remote_port)

    def close(self):
        """Close the SSH connection"""
        self._client.close()

    def interactive_shell(self, command: typing.Optional[str] = None):
        return _interactive_shell(self._client, command)

    def write_file(
        self, remote_path: str, content: typing.Union[str, bytes], mode: int = 0o644
    ) -> None:
        """
        Write content directly to a file on the remote machine.

        Parameters:
            remote_path: Path to the remote file
            content: Content to write (string or bytes)
            mode: File permissions (default: 0o644)
        """
        sftp = self._client.open_sftp()
        try:
            # Convert string to bytes if needed
            if isinstance(content, str):
                content = content.encode("utf-8")

            # Create a temporary file-like object
            with sftp.open(remote_path, "wb") as f:
                f.write(content)

            # Set file permissions
            sftp.chmod(remote_path, mode)
        finally:
            sftp.close()

    def read_file(
        self, remote_path: str, binary: bool = False
    ) -> typing.Union[str, bytes]:
        """
        Read content from a file on the remote machine.

        Parameters:
            remote_path: Path to the remote file
            binary: If True, return bytes; otherwise, return string (default: False)

        Returns:
            File content as string or bytes
        """
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote_path, "rb") as f:
                content = f.read()

            if binary:
                return content
            return content.decode("utf-8", errors="replace")
        finally:
            sftp.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
