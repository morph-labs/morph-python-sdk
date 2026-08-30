import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple
import paramiko

class OSCType(Enum):
    """OSC 133 Semantic Prompt Sequence Types"""
    PROMPT_START = 'P'
    COMMAND_START = 'C'
    COMMAND_DONE = 'D'
    PROMPT_CONT = 'A'
    BLOCK_END = 'B'

class PromptKind(Enum):
    """OSC 133 Prompt Types (k parameter)"""
    INITIAL = 'i'
    SECONDARY = 's'

class ContinuationKind(Enum):
    """OSC 133 Continuation Types (cl parameter)"""
    MESSAGE = 'm'
    PARTIAL = 'p'
    COMPLETE = 'c'

@dataclass
class OSCParams:
    """Structured representation of OSC 133 parameters"""
    type: OSCType
    prompt_kind: Optional[PromptKind] = None
    continuation: Optional[ContinuationKind] = None
    exit_code: Optional[int] = None
    aid: Optional[int] = None
    raw_params: Dict[str, str] = None

    @classmethod
    def from_sequence(cls, sequence: str) -> 'OSCParams':
        """Parse an OSC sequence into structured parameters"""
        parts = sequence.split(';')
        if not parts:
            raise ValueError(f'Empty sequence')
        type_str = parts[0]
        if type_str == 'B':
            return cls(type=OSCType.BLOCK_END, raw_params={})
        try:
            osc_type = OSCType(type_str)
        except ValueError:
            raise ValueError(f'Unknown sequence type: {type_str}')
        raw_params = {}
        exit_code = None
        if osc_type == OSCType.COMMAND_DONE and len(parts) > 1:
            try:
                exit_code = int(parts[1])
                raw_params['exit_code'] = parts[1]
            except ValueError:
                pass
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                raw_params[key] = value
        return cls(type=osc_type, prompt_kind=PromptKind(raw_params['k']) if 'k' in raw_params else None, continuation=ContinuationKind(raw_params['cl']) if 'cl' in raw_params else None, exit_code=exit_code if exit_code is not None else int(raw_params['exit_code']) if 'exit_code' in raw_params else None, aid=int(raw_params['aid']) if 'aid' in raw_params else None, raw_params=raw_params)

@dataclass
class CommandResult:
    prompt: str
    command: str
    output: str
    exit_code: int
    osc_params: Dict[str, OSCParams]

class SemanticShellClient:

    def __init__(self, hostname: str, username: str, port: int=2222):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname=hostname, username=username, port=port)
        self.channel = self.client.invoke_shell()
        self.buffer = ''
        self._read_until_prompt()

    def _parse_osc_sequences(self, text: str) -> Dict[str, OSCParams]:
        """Parse all OSC sequences in the text"""
        params = {}
        sequences = re.finditer('\\x1b]133;([^\\x07]*)\\x07', text)
        for i, seq in enumerate(sequences):
            try:
                params[f'seq_{i}'] = OSCParams.from_sequence(seq.group(1))
            except ValueError as e:
                continue
        return params

    def _split_repl_parts(self, text: str) -> Tuple[str, str, str, Dict[str, OSCParams]]:
        """
        Split the shell output into prompt, command output, and OSC parameters.
        Returns (prompt, command_output, output, osc_params)
        """
        osc_params = self._parse_osc_sequences(text)
        clean_text = re.sub('\\x1b]133;[^\\x07]*\\x07', '', text)
        clean_text = re.sub('\\x1b]122;[^\\x07]*\\x07', '', clean_text)
        lines = clean_text.split('\r\n')
        prompt = lines[-1] if lines else ''
        command_output = lines[0] if len(lines) > 0 else ''
        output = '\n'.join(lines[1:-1]) if len(lines) > 2 else ''
        prompt = re.sub('\\x1b[^m]*m', '', prompt).strip()
        command_output = re.sub('\\x1b[^m]*m', '', command_output).strip()
        output = re.sub('\\x1b[^m]*m', '', output).strip()
        return (prompt, command_output, output, osc_params)

    def _read_until_prompt(self, timeout: float=30) -> Tuple[str, int]:
        """
        Read the shell output until we see the OSC 133 command completion sequence.
        Returns the output and the exit code.
        """
        start_time = time.time()
        output = []
        exit_code = None
        while time.time() - start_time < timeout:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode('utf-8')
                self.buffer += chunk
                output.append(chunk)
                completion_match = re.search('\\x1b]133;D;(\\d+);aid=\\d+\\x07', self.buffer)
                if completion_match:
                    exit_code = int(completion_match.group(1))
                if re.search('\\x1b]133;A;cl=m;aid=\\d+\\x07', self.buffer):
                    complete_output = ''.join(output)
                    self.buffer = ''
                    return (complete_output, exit_code)
            time.sleep(0.1)
        raise TimeoutError('Timed out waiting for command completion')

    def execute_command(self, command: str, timeout: float=30) -> CommandResult:
        """
        Execute a command and wait for its completion.
        Returns a CommandResult with structured output and OSC parameters.
        """
        self.channel.send(command + '\n')
        raw_output, exit_code = self._read_until_prompt(timeout)
        prompt, command_output, output, osc_params = self._split_repl_parts(raw_output)
        return CommandResult(prompt=prompt, command=command_output or command, output=output, exit_code=exit_code or 0, osc_params=osc_params)

    def close(self):
        """Close the SSH connection."""
        self.channel.close()
        self.client.close()
