"""
Error Handling Module for MorphCloud SDK

This module provides:
- Custom exception classes for different error types
- Standardized error handling and reporting
- Error context and debugging information
- Error recovery and retry mechanisms
"""

import logging
import traceback
import sys
from typing import Any, Dict, Optional, List, Type, Callable
from dataclass import dataclass
from enum import Enum
import time
import asyncio


class ErrorSeverity(Enum):
    """Error severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories"""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    VALIDATION = "validation"
    RESOURCE = "resource"
    SYSTEM = "system"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CONFIGURATION = "configuration"


@dataclass
class ErrorContext:
    """Context information for errors"""

    timestamp: float
    module: str
    function: str
    line_number: int
    stack_trace: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class MorphCloudError(Exception):
    """Base exception class for MorphCloud SDK"""

    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        retryable: bool = False,
        max_retries: int = 3,
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code
        self.context = context or self._create_context()
        self.retryable = retryable
        self.max_retries = max_retries
        self.retry_count = 0

    def _create_context(self) -> ErrorContext:
        """Create error context from current stack frame"""
        try:
            frame = sys._getframe(2)  # Skip this method and __init__
            return ErrorContext(
                timestamp=time.time(),
                module=frame.f_globals.get("__name__", "unknown"),
                function=frame.f_code.co_name,
                line_number=frame.f_lineno,
                stack_trace=traceback.format_exc(),
            )
        except Exception:
            return ErrorContext(
                timestamp=time.time(),
                module="unknown",
                function="unknown",
                line_number=0,
                stack_trace=traceback.format_exc(),
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization"""
        return {
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "error_code": self.error_code,
            "retryable": self.retryable,
            "retry_count": self.retry_count,
            "context": (
                {
                    "timestamp": self.context.timestamp,
                    "module": self.context.module,
                    "function": self.context.function,
                    "line_number": self.context.line_number,
                    "user_id": self.context.user_id,
                    "session_id": self.context.session_id,
                    "request_id": self.context.request_id,
                    "additional_data": self.context.additional_data,
                }
                if self.context
                else None
            ),
        }

    def __str__(self):
        return f"{self.__class__.__name__}: {self.message} (Category: {self.category.value}, Severity: {self.severity.value})"


class AuthenticationError(MorphCloudError):
    """Authentication related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.AUTHENTICATION, **kwargs)


class AuthorizationError(MorphCloudError):
    """Authorization related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.AUTHORIZATION, **kwargs)


class NetworkError(MorphCloudError):
    """Network related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.NETWORK, retryable=True, **kwargs)


class ValidationError(MorphCloudError):
    """Validation related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.VALIDATION, **kwargs)


class ResourceError(MorphCloudError):
    """Resource related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.RESOURCE, retryable=True, **kwargs)


class SecurityError(MorphCloudError):
    """Security related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(
            message, ErrorCategory.SECURITY, severity=ErrorSeverity.HIGH, **kwargs
        )


class ConfigurationError(MorphCloudError):
    """Configuration related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.CONFIGURATION, **kwargs)


class PerformanceError(MorphCloudError):
    """Performance related errors"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorCategory.PERFORMANCE, **kwargs)


class ErrorHandler:
    """Central error handling and reporting system"""

    def __init__(self):
        self.logger = logging.getLogger("morphcloud.errors")
        self.error_history: List[MorphCloudError] = []
        self.error_callbacks: List[Callable[[MorphCloudError], None]] = []
        self.max_history_size = 1000

    def handle_error(
        self,
        error: MorphCloudError,
        log_error: bool = True,
        raise_error: bool = True,
        context_data: Optional[Dict[str, Any]] = None,
    ):
        """Handle an error with logging and callbacks"""
        # Add context data if provided
        if context_data and error.context:
            if error.context.additional_data is None:
                error.context.additional_data = {}
            error.context.additional_data.update(context_data)

        # Log the error
        if log_error:
            self._log_error(error)

        # Store in history
        self._store_error(error)

        # Execute callbacks
        self._execute_callbacks(error)

        # Raise if requested
        if raise_error:
            raise error

    def _log_error(self, error: MorphCloudError):
        """Log error with appropriate level"""
        log_message = f"{error.message} (Code: {error.error_code}, Category: {error.category.value})"

        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message, exc_info=True)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message, exc_info=True)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message, exc_info=True)
        else:
            self.logger.info(log_message, exc_info=True)

    def _store_error(self, error: MorphCloudError):
        """Store error in history"""
        self.error_history.append(error)

        # Maintain history size
        if len(self.error_history) > self.max_history_size:
            self.error_history.pop(0)

    def _execute_callbacks(self, error: MorphCloudError):
        """Execute registered error callbacks"""
        for callback in self.error_callbacks:
            try:
                callback(error)
            except Exception as e:
                self.logger.error(f"Error in error callback: {e}")

    def add_error_callback(self, callback: Callable[[MorphCloudError], None]):
        """Add an error callback function"""
        self.error_callbacks.append(callback)

    def remove_error_callback(self, callback: Callable[[MorphCloudError], None]):
        """Remove an error callback function"""
        if callback in self.error_callbacks:
            self.error_callbacks.remove(callback)

    def get_errors_by_category(self, category: ErrorCategory) -> List[MorphCloudError]:
        """Get errors filtered by category"""
        return [e for e in self.error_history if e.category == category]

    def get_errors_by_severity(self, severity: ErrorSeverity) -> List[MorphCloudError]:
        """Get errors filtered by severity"""
        return [e for e in self.error_history if e.severity == severity]

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of error statistics"""
        if not self.error_history:
            return {}

        summary = {
            "total_errors": len(self.error_history),
            "categories": {},
            "severities": {},
            "retryable_errors": 0,
            "recent_errors": [],
        }

        # Count by category and severity
        for error in self.error_history:
            category = error.category.value
            severity = error.severity.value

            summary["categories"][category] = summary["categories"].get(category, 0) + 1
            summary["severities"][severity] = summary["severities"].get(severity, 0) + 1

            if error.retryable:
                summary["retryable_errors"] += 1

        # Get recent errors (last 10)
        summary["recent_errors"] = [
            error.to_dict() for error in self.error_history[-10:]
        ]

        return summary

    def clear_history(self):
        """Clear error history"""
        self.error_history.clear()


class RetryHandler:
    """Handles retry logic for retryable errors"""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_backoff: bool = True,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff

    def should_retry(self, error: MorphCloudError) -> bool:
        """Check if error should be retried"""
        return (
            error.retryable
            and error.retry_count < error.max_retries
            and error.retry_count < self.max_retries
        )

    def get_retry_delay(self, error: MorphCloudError) -> float:
        """Calculate delay before next retry"""
        if self.exponential_backoff:
            delay = self.base_delay * (2**error.retry_count)
        else:
            delay = self.base_delay

        return min(delay, self.max_delay)

    async def retry_operation(
        self, operation: Callable, error_types: List[Type[Exception]] = None, **kwargs
    ) -> Any:
        """Retry an operation with exponential backoff"""
        if error_types is None:
            error_types = [MorphCloudError]

        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(operation):
                    result = await operation(**kwargs)
                else:
                    result = operation(**kwargs)
                return result

            except tuple(error_types) as e:
                last_error = e

                if not self.should_retry(e):
                    break

                # Increment retry count
                if hasattr(e, "retry_count"):
                    e.retry_count += 1

                # Wait before retry
                delay = self.get_retry_delay(e)
                await asyncio.sleep(delay)

        # All retries exhausted
        raise last_error


# Global error handler instance
_error_handler = ErrorHandler()
_retry_handler = RetryHandler()


def get_error_handler() -> ErrorHandler:
    """Get the global error handler instance"""
    return _error_handler


def get_retry_handler() -> RetryHandler:
    """Get the global retry handler instance"""
    return _retry_handler


def handle_error(error: MorphCloudError, **kwargs):
    """Handle an error using the global error handler"""
    _error_handler.handle_error(error, **kwargs)


def add_error_callback(callback: Callable[[MorphCloudError], None]):
    """Add an error callback to the global error handler"""
    _error_handler.add_error_callback(callback)


def get_error_summary() -> Dict[str, Any]:
    """Get error summary from global error handler"""
    return _error_handler.get_error_summary()


def retry_operation(operation: Callable, **kwargs) -> Any:
    """Retry an operation using the global retry handler"""
    return _retry_handler.retry_operation(operation, **kwargs)
