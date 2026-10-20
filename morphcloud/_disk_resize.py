"""Disk-capacity operation values and local waiting policy.

Waiting never changes a remote operation: timeouts and cancellation only stop
local observation. Every error preserves the request key and operation evidence
available to that invocation so a caller can safely resume observation or replay.
"""
from __future__ import annotations
import math
import time
import uuid
from datetime import datetime
from typing import Literal
from urllib.parse import quote
from pydantic import BaseModel, ConfigDict, Field

class DiskResizeOperationError(BaseModel):
    """Service rejection or failure details, including a measured minimum."""
    model_config = ConfigDict(frozen=True)
    code: str
    message: str
    retryable: bool
    minimum_target_mib: int | None = Field(default=None, ge=0)

class DiskResizeOperation(BaseModel):
    """An observed disk resize; byte observations are null until known.

    ``requested_disk_size`` and ``previous_disk_size`` use MiB. A successful
    operation changes effective capacity; backing storage observations may differ.
    ``idempotency_key`` is local recovery context, never inferred by GET calls.
    """
    model_config = ConfigDict(frozen=True)
    object: Literal['instance_disk_resize'] = 'instance_disk_resize'
    id: str = Field(min_length=1)
    instance_id: str = Field(min_length=1)
    previous_disk_size: int = Field(ge=0)
    requested_disk_size: int = Field(ge=256, le=1048576)
    capacity_mode: str
    status: Literal['pending', 'running', 'succeeded', 'failed', 'recovery_required']
    phase: Literal['accepted', 'geometry_ready', 'budget_applied', 'complete']
    capacity_generation: int = Field(ge=0)
    effective_capacity_bytes: int | None = Field(default=None, ge=0)
    statfs_total_bytes: int | None = Field(default=None, ge=0)
    charged_bytes: int | None = Field(default=None, ge=0)
    reserved_bytes: int | None = Field(default=None, ge=0)
    backing_bytes: int | None = Field(default=None, ge=0)
    guest_device_bytes: int | None = Field(default=None, ge=0)
    ext4_geometry_bytes: int | None = Field(default=None, ge=0)
    error: DiskResizeOperationError | None = None
    retry_after_seconds: float = Field(default=1, ge=0, allow_inf_nan=False)
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    idempotency_key: str | None = None

class DiskResizeError(Exception):
    """Base failure with enough evidence to resume or replay safely."""

    def __init__(self, message: str, *, operation: DiskResizeOperation | None=None, operation_id: str | None=None, idempotency_key: str | None=None) -> None:
        self.operation = operation
        self.operation_id = operation.id if operation else operation_id
        self.idempotency_key = idempotency_key or (operation.idempotency_key if operation else None)
        recovery = []
        if self.operation_id:
            recovery.append(f'operation_id={self.operation_id}')
        if self.idempotency_key:
            recovery.append(f'idempotency_key={self.idempotency_key}')
        if recovery:
            message += ' (' + ', '.join(recovery) + ')'
        super().__init__(message)

class DiskResizeFailed(DiskResizeError):
    """The observed operation failed; inspect its structured error."""

class DiskResizeRecoveryRequired(DiskResizeError):
    """The operation requires recovery; do not submit a replacement."""

class DiskResizeTimeout(DiskResizeError, TimeoutError):
    """Local waiting expired. The remote operation was not cancelled."""

class DiskResizeRequestError(DiskResizeError):
    """A request failed or returned invalid evidence; its cause is preserved."""

    def __init__(self, message: str, *, cause: Exception, operation: DiskResizeOperation | None=None, operation_id: str | None=None, idempotency_key: str | None=None) -> None:
        self.status_code = getattr(cause, 'status_code', None)
        self.error_code = getattr(cause, 'error_code', None)
        self.response_body = getattr(cause, 'response_body', None)
        if self.status_code is not None:
            message += f'; HTTP {self.status_code}'
        if self.error_code is not None:
            message += f'; {self.error_code}'
        super().__init__(message, operation=operation, operation_id=operation_id, idempotency_key=idempotency_key)

class DiskResizeRefreshError(DiskResizeError):
    """Resize succeeded, but refreshing the local Instance failed.

    ``operation`` remains the successful receipt. Do not repeat the resize to
    refresh an instance; retrieve the instance separately.
    """

def request_key(disk_size: int, idempotency_key: str | None) -> str:
    if type(disk_size) is not int or not 256 <= disk_size <= 1048576:
        raise ValueError('disk_size must be an integer MiB value from 256 to 1048576')
    if idempotency_key is None:
        return str(uuid.uuid4())
    if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128:
        raise ValueError('idempotency_key must contain 1 to 128 ASCII characters')
    if any((ord(character) < 33 or ord(character) > 126 for character in idempotency_key)):
        raise ValueError('idempotency_key must contain visible ASCII characters')
    return idempotency_key

def deadline(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError('timeout must be a finite positive number of seconds')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be a finite positive number of seconds')
    return time.monotonic() + timeout

def remaining(end: float, *, operation: DiskResizeOperation | None=None, operation_id: str | None=None, idempotency_key: str | None=None) -> float:
    seconds = end - time.monotonic()
    if seconds <= 0:
        raise DiskResizeTimeout('Disk resize waiting timed out; remote work may still be running', operation=operation, operation_id=operation_id, idempotency_key=idempotency_key)
    return seconds

def operation_path(instance_id: str, operation_id: str | None=None) -> str:
    if not isinstance(instance_id, str) or not instance_id:
        raise ValueError('instance_id must be a nonempty string')
    path = f"/instance/{quote(instance_id, safe='')}/disk-resize"
    if operation_id is not None:
        if not isinstance(operation_id, str) or not operation_id:
            raise ValueError('operation_id must be a nonempty string')
        path += f"/{quote(operation_id, safe='')}"
    return path

def parse_operation(payload: object, instance_id: str, *, operation_id: str | None=None, idempotency_key: str | None=None, requested_disk_size: int | None=None, previous: DiskResizeOperation | None=None) -> DiskResizeOperation:
    operation = DiskResizeOperation.model_validate(payload)
    if operation.instance_id != instance_id:
        raise ValueError('Disk resize response instance does not match the request')
    if operation_id is not None and operation.id != operation_id:
        raise ValueError('Disk resize response operation does not match the request')
    if requested_disk_size is not None and operation.requested_disk_size != requested_disk_size:
        raise ValueError('Disk resize response target does not match the request')
    if previous is not None and operation.capacity_generation < previous.capacity_generation:
        raise ValueError('Disk resize response capacity generation regressed')
    return operation.model_copy(update={'idempotency_key': idempotency_key})

def terminal(operation: DiskResizeOperation) -> bool:
    if operation.status == 'failed':
        raise DiskResizeFailed('Disk resize failed', operation=operation)
    if operation.status == 'recovery_required':
        raise DiskResizeRecoveryRequired('Disk resize requires recovery', operation=operation)
    return operation.status == 'succeeded'

def poll_delay(operation: DiskResizeOperation, end: float) -> float:
    return min(max(operation.retry_after_seconds, 0.1), 5, remaining(end, operation=operation))
