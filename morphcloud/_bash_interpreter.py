import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple

import paramiko


class OSCType(Enum):
    """OSC 133 Semantic Prompt Sequence Types"""

    PROMPT_START = "P"  # Indicates start of prompt (k=i or k=s parameter)
    COMMAND_START = "C"  # Indicates start of command execution
    COMMAND_DONE = "D"  # Indicates command completion (includes exit code)
    PROMPT_CONT = "A"  # Indicates continuation of prompt (cl parameter)
    BLOCK_END = "B"  # Indicates end of a block


class PromptKind(Enum):
    """OSC 133 Prompt Types (k parameter)"""

    INITIAL = "i"  # Initial prompt
    SECONDARY = "s"  # Secondary prompt (like PS2)


class ContinuationKind(Enum):
    """OSC 133 Continuation Types (cl parameter)"""

    MESSAGE = "m"  # Message continuation
    PARTIAL = "p"  # Partial line
    COMPLETE = "c"  # Complete line


@dataclass
class OSCParams:
    """Structured representation of OSC 133 parameters"""

    type: OSCType
    prompt_kind: Optional[PromptKind] = None
    continuation: Optional[ContinuationKind] = None
    exit_code: Optional[int] = None
    aid: Optional[int] = None  # Activity ID
    raw_params: Dict[str, str] = None

    @classmethod
    def from_sequence(cls, sequence: str) -> "OSCParams":
        """Parse an OSC sequence into structured parameters"""
        # Split the sequence into type and parameters
        parts = sequence.split(";")
        if not parts:
            raise ValueError("Empty sequence")

        # Handle the sequence type
        type_str = parts[0]
        if type_str == "B":
            return cls(type=OSCType.BLOCK_END, raw_params={})

        try:
            osc_type = OSCType(type_str)
        except ValueError:
            raise ValueError(f"Unknown sequence type: {type_str}")

        raw_params = {}
        exit_code = None

        # Parse the remaining parameters
        if osc_type == OSCType.COMMAND_DONE and len(parts) > 1:
            try:
                exit_code = int(parts[1])
                raw_params["exit_code"] = parts[1]
            except ValueError:
                pass

        # Parse key-value pairs
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                raw_params[key] = value

        return cls(
            type=osc_type,
            prompt_kind=PromptKind(raw_params["k"]) if "k" in raw_params else None,
            continuation=(
                ContinuationKind(raw_params["cl"]) if "cl" in raw_params else None
            ),
            exit_code=(
                exit_code
                if exit_code is not None
                else (
                    int(raw_params["exit_code"]) if "exit_code" in raw_params else None
                )
            ),
            aid=int(raw_params["aid"]) if "aid" in raw_params else None,
            raw_params=raw_params,
        )


@dataclass
class CommandResult:
    prompt: str  # The shell prompt (e.g., "user@host:~$")
    command: str  # The command that was executed
    output: str  # The command's output (stdout/stderr)
    exit_code: int  # Command exit code
    osc_params: Dict[str, OSCParams]  # Structured OSC parameters


class SemanticShellClient:
    def __init__(
        self,
        hostname: str,
        username: str,
        port: int = 2222,
    ):
        self.hostname = hostname
        self.username = username
        self.port = port
        self.client = None

    def connect(self, password: str = None, key_filename: str = None):
        """Establish SSH connection with proper host key verification"""
        self.client = paramiko.SSHClient()

        # Load known hosts for proper verification
        known_hosts_file = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(known_hosts_file):
            self.client.load_host_keys(known_hosts_file)

        # Use RejectPolicy for security - reject unknown hosts
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

        # Connect with authentication
        connect_kwargs = {
            "hostname": self.hostname,
            "username": self.username,
            "port": self.port,
            "timeout": 30,
            "look_for_keys": True,
            "allow_agent": True,
        }

        if password:
            connect_kwargs["password"] = password
        if key_filename:
            connect_kwargs["key_filename"] = key_filename

        self.client.connect(**connect_kwargs)

    def _parse_osc_sequences(self, text: str) -> Dict[str, OSCParams]:
        """Parse OSC 133 sequences from text and return structured data"""
        import re

        # Find all OSC 133 sequences
        osc_pattern = r"\x1b\]133;([^\x07\x1b]*)(?:\x07|\x1b\\)"
        sequences = re.findall(osc_pattern, text)

        parsed = {}
        for i, seq in enumerate(sequences):
            try:
                parsed[f"sequence_{i}"] = OSCParams.from_sequence(seq)
            except ValueError as e:
                # Log parsing errors but continue
                print(f"Warning: Failed to parse OSC sequence '{seq}': {e}")

        return parsed

    def _split_repl_parts(
        self, text: str
    ) -> Tuple[str, str, str, Dict[str, OSCParams]]:
        """Split REPL output into prompt, command, and output sections"""
        # Parse OSC sequences first
        osc_params = self._parse_osc_sequences(text)

        # Find command start and end markers
        command_start = None
        command_end = None

        for key, params in osc_params.items():
            if params.type == OSCType.COMMAND_START:
                command_start = key
            elif params.type == OSCType.COMMAND_DONE:
                command_end = key

        if command_start and command_end:
            # Extract sections based on OSC markers
            start_marker = f"\x1b]133;{command_start}"
            end_marker = f"\x1b]133;{command_end}"
            start_idx = text.find(start_marker)
            end_idx = text.find(end_marker)

            if start_idx != -1 and end_idx != -1:
                prompt = text[:start_idx].strip()
                command_section = text[start_idx:end_idx]
                output = text[end_idx:].strip()

                # Extract command from command section
                command = ""
                for line in command_section.split("\n"):
                    if line.strip() and not line.startswith("\x1b"):
                        command = line.strip()
                        break

                return prompt, command, output, osc_params

        # Fallback: simple line-based parsing
        lines = text.split("\n")
        if len(lines) >= 3:
            prompt = lines[0].strip()
            command = lines[1].strip()
            output = "\n".join(lines[2:]).strip()
            return prompt, command, output, osc_params

        # Minimal fallback
        return text.strip(), "", "", osc_params

    def _read_until_prompt(self, timeout: float = 30) -> Tuple[str, int]:
        """Read from SSH channel until prompt is detected"""
        if not self.client:
            raise RuntimeError("Not connected. Call connect() first.")

        channel = self.client.get_transport().open_session()
        channel.get_pty()
        channel.exec_command("")

        output = ""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if channel.recv_ready():
                chunk = channel.recv(1024).decode("utf-8", errors="replace")
                output += chunk

                # Check if we have a complete prompt
                if output.strip().endswith("$") or output.strip().endswith("#"):
                    break

            if channel.exit_status_ready():
                break

            time.sleep(0.1)

        exit_code = channel.recv_exit_status()
        channel.close()

        return output, exit_code

    def execute_command(self, command: str, timeout: float = 30) -> CommandResult:
        """Execute a command and return structured result"""
        if not self.client:
            raise RuntimeError("Not connected. Call connect() first.")

        # Get initial prompt
        initial_output, _ = self._read_until_prompt(timeout)

        # Execute command
        channel = self.client.get_transport().open_session()
        channel.get_pty()
        channel.exec_command(command)

        # Read command output
        output = ""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if channel.recv_ready():
                chunk = channel.recv(1024).decode("utf-8", errors="replace")
                output += chunk

            if channel.exit_status_ready():
                break

            time.sleep(0.1)

        exit_code = channel.recv_exit_status()
        channel.close()

        # Get final prompt
        final_output, _ = self._read_until_prompt(timeout)

        # Combine all output
        full_output = initial_output + output + final_output

        # Parse into structured parts
        prompt, cmd, result_output, osc_params = self._split_repl_parts(full_output)

        return CommandResult(
            prompt=prompt,
            command=cmd or command,  # Use parsed command or fallback to input
            output=result_output,
            exit_code=exit_code,
            osc_params=osc_params,
        )

    def close(self):
        """Close the SSH connection"""
        if self.client:
            self.client.close()
            self.client = None
