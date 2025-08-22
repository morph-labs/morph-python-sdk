"""
Testing and Validation Module for MorphCloud SDK

This module provides:
- Testing utilities and helpers
- Performance testing tools
- Load testing capabilities
- Validation and assertion utilities
"""

import time
import asyncio
import statistics
from typing import Any, Dict, List, Optional, Callable, TypeVar
from dataclasses import dataclass
from enum import Enum
import logging

T = TypeVar("T")


class TestResult(Enum):
    """Test result status"""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class TestCase:
    """Individual test case"""

    name: str
    description: str
    test_func: Callable
    timeout: float = 30.0
    retries: int = 0
    dependencies: List[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class TestResult:
    """Test execution result"""

    test_name: str
    status: TestResult
    duration: float
    message: str
    error: Optional[Exception] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class TestRunner:
    """Runs test suites and manages test execution"""

    def __init__(self):
        self.test_cases: List[TestCase] = []
        self.results: List[TestResult] = []
        self.logger = logging.getLogger("morphcloud.testing")

    def add_test(self, test_case: TestCase):
        """Add a test case"""
        self.test_cases.append(test_case)

    def run_tests(self, test_names: Optional[List[str]] = None) -> List[TestResult]:
        """Run all tests or specified tests"""
        tests_to_run = self.test_cases

        if test_names:
            tests_to_run = [t for t in self.test_cases if t.name in test_names]

        self.results = []

        for test_case in tests_to_run:
            result = self._run_single_test(test_case)
            self.results.append(result)

        return self.results

    def _run_single_test(self, test_case: TestCase) -> TestResult:
        """Run a single test case"""
        start_time = time.time()

        try:
            # Check dependencies
            if not self._check_dependencies(test_case):
                return TestResult(
                    test_name=test_case.name,
                    status=TestResult.SKIP,
                    duration=0.0,
                    message=f"Skipped due to failed dependencies: {test_case.dependencies}",
                )

            # Run test with timeout
            if asyncio.iscoroutinefunction(test_case.test_func):
                result = asyncio.run(
                    asyncio.wait_for(test_case.test_func(), timeout=test_case.timeout)
                )
            else:
                result = test_case.test_func()

            duration = time.time() - start_time

            return TestResult(
                test_name=test_case.name,
                status=TestResult.PASS,
                duration=duration,
                message="Test passed successfully",
            )

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            return TestResult(
                test_name=test_case.name,
                status=TestResult.FAIL,
                duration=duration,
                message=f"Test timed out after {test_case.timeout}s",
            )

        except Exception as e:
            duration = time.time() - start_time
            return TestResult(
                test_name=test_case.name,
                status=TestResult.ERROR,
                duration=duration,
                message=f"Test failed with error: {e}",
                error=e,
            )

    def _check_dependencies(self, test_case: TestCase) -> bool:
        """Check if test dependencies passed"""
        if not test_case.dependencies:
            return True

        for dep_name in test_case.dependencies:
            dep_result = next(
                (r for r in self.results if r.test_name == dep_name), None
            )
            if not dep_result or dep_result.status != TestResult.PASS:
                return False

        return True

    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of test results"""
        if not self.results:
            return {}

        status_counts = {
            TestResult.PASS: 0,
            TestResult.FAIL: 0,
            TestResult.SKIP: 0,
            TestResult.ERROR: 0,
        }

        for result in self.results:
            status_counts[result.status] += 1

        total_tests = len(self.results)
        passed_tests = status_counts[TestResult.PASS]
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0

        return {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": status_counts[TestResult.FAIL],
            "skipped": status_counts[TestResult.SKIP],
            "errors": status_counts[TestResult.ERROR],
            "success_rate": success_rate,
            "total_duration": sum(r.duration for r in self.results),
            "average_duration": (
                statistics.mean(r.duration for r in self.results) if self.results else 0
            ),
        }


class PerformanceTester:
    """Performs performance testing and benchmarking"""

    def __init__(self):
        self.logger = logging.getLogger("morphcloud.testing")

    def benchmark_function(
        self, func: Callable, iterations: int = 1000, warmup_iterations: int = 100
    ) -> Dict[str, Any]:
        """Benchmark a function's performance"""
        # Warmup
        for _ in range(warmup_iterations):
            try:
                func()
            except Exception:
                pass

        # Actual benchmark
        times = []
        errors = 0

        for _ in range(iterations):
            try:
                start_time = time.perf_counter()
                func()
                end_time = time.perf_counter()
                times.append(end_time - start_time)
            except Exception as e:
                errors += 1
                self.logger.warning(f"Benchmark iteration failed: {e}")

        if not times:
            return {
                "iterations": iterations,
                "successful_iterations": 0,
                "errors": errors,
                "error_rate": 100.0,
            }

        return {
            "iterations": iterations,
            "successful_iterations": len(times),
            "errors": errors,
            "error_rate": (errors / iterations) * 100,
            "min_time": min(times),
            "max_time": max(times),
            "mean_time": statistics.mean(times),
            "median_time": statistics.median(times),
            "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
            "total_time": sum(times),
        }

    async def benchmark_async_function(
        self, func: Callable, iterations: int = 1000, warmup_iterations: int = 100
    ) -> Dict[str, Any]:
        """Benchmark an async function's performance"""
        # Warmup
        for _ in range(warmup_iterations):
            try:
                await func()
            except Exception:
                pass

        # Actual benchmark
        times = []
        errors = 0

        for _ in range(iterations):
            try:
                start_time = time.perf_counter()
                await func()
                end_time = time.perf_counter()
                times.append(end_time - start_time)
            except Exception as e:
                errors += 1
                self.logger.warning(f"Async benchmark iteration failed: {e}")

        if not times:
            return {
                "iterations": iterations,
                "successful_iterations": 0,
                "errors": errors,
                "error_rate": 100.0,
            }

        return {
            "iterations": iterations,
            "successful_iterations": len(times),
            "errors": errors,
            "error_rate": (errors / iterations) * 100,
            "min_time": min(times),
            "max_time": max(times),
            "mean_time": statistics.mean(times),
            "median_time": statistics.median(times),
            "std_dev": statistics.stdev(times) if len(times) > 1 else 0,
            "total_time": sum(times),
        }


class LoadTester:
    """Performs load testing with concurrent operations"""

    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.logger = logging.getLogger("morphcloud.testing")

    async def load_test(
        self,
        operation: Callable,
        concurrent_users: int,
        operations_per_user: int,
        delay_between_ops: float = 0.0,
    ) -> Dict[str, Any]:
        """Perform load testing with concurrent users"""
        start_time = time.time()
        results = []
        errors = 0

        async def user_workflow(user_id: int):
            user_results = []
            for op_num in range(operations_per_user):
                try:
                    op_start = time.perf_counter()
                    result = await operation()
                    op_duration = time.perf_counter() - op_start

                    user_results.append(
                        {
                            "user_id": user_id,
                            "operation": op_num,
                            "duration": op_duration,
                            "success": True,
                            "result": result,
                        }
                    )

                    if delay_between_ops > 0:
                        await asyncio.sleep(delay_between_ops)

                except Exception as e:
                    errors += 1
                    user_results.append(
                        {
                            "user_id": user_id,
                            "operation": op_num,
                            "duration": 0.0,
                            "success": False,
                            "error": str(e),
                        }
                    )

            return user_results

        # Create tasks for concurrent users
        tasks = [user_workflow(user_id) for user_id in range(concurrent_users)]

        # Execute all tasks concurrently
        user_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten results
        for user_result in user_results:
            if isinstance(user_result, list):
                results.extend(user_result)
            else:
                # Handle exception in user workflow
                errors += 1

        total_duration = time.time() - start_time
        successful_ops = len([r for r in results if r["success"]])
        total_ops = len(results)

        if successful_ops > 0:
            durations = [r["duration"] for r in results if r["success"]]
            avg_duration = statistics.mean(durations)
            min_duration = min(durations)
            max_duration = max(durations)
        else:
            avg_duration = min_duration = max_duration = 0.0

        return {
            "concurrent_users": concurrent_users,
            "operations_per_user": operations_per_user,
            "total_operations": total_ops,
            "successful_operations": successful_ops,
            "failed_operations": errors,
            "success_rate": (successful_ops / total_ops) * 100 if total_ops > 0 else 0,
            "total_duration": total_duration,
            "operations_per_second": (
                total_ops / total_duration if total_duration > 0 else 0
            ),
            "average_response_time": avg_duration,
            "min_response_time": min_duration,
            "max_response_time": max_duration,
            "results": results,
        }


class ValidationUtils:
    """Utility functions for validation and assertions"""

    @staticmethod
    def assert_equals(actual: Any, expected: Any, message: str = ""):
        """Assert that actual equals expected"""
        if actual != expected:
            raise AssertionError(
                f"Assertion failed: {message}\n"
                f"Expected: {expected}\n"
                f"Actual: {actual}"
            )

    @staticmethod
    def assert_not_equals(actual: Any, expected: Any, message: str = ""):
        """Assert that actual does not equal expected"""
        if actual == expected:
            raise AssertionError(
                f"Assertion failed: {message}\n"
                f"Expected: not {expected}\n"
                f"Actual: {actual}"
            )

    @staticmethod
    def assert_true(condition: bool, message: str = ""):
        """Assert that condition is True"""
        if not condition:
            raise AssertionError(f"Assertion failed: {message}")

    @staticmethod
    def assert_false(condition: bool, message: str = ""):
        """Assert that condition is False"""
        if condition:
            raise AssertionError(f"Assertion failed: {message}")

    @staticmethod
    def assert_in(item: Any, container: Any, message: str = ""):
        """Assert that item is in container"""
        if item not in container:
            raise AssertionError(
                f"Assertion failed: {message}\n"
                f"Item: {item}\n"
                f"Container: {container}"
            )

    @staticmethod
    def assert_not_in(item: Any, container: Any, message: str = ""):
        """Assert that item is not in container"""
        if item in container:
            raise AssertionError(
                f"Assertion failed: {message}\n"
                f"Item: {item}\n"
                f"Container: {container}"
            )

    @staticmethod
    def assert_raises(exception_type: type, func: Callable, *args, **kwargs):
        """Assert that function raises specified exception"""
        try:
            func(*args, **kwargs)
            raise AssertionError(f"Expected {exception_type.__name__} to be raised")
        except exception_type:
            pass  # Expected exception
        except Exception as e:
            raise AssertionError(
                f"Expected {exception_type.__name__}, but got {type(e).__name__}: {e}"
            )


# Global instances
_test_runner = TestRunner()
_performance_tester = PerformanceTester()
_load_tester = LoadTester()


def get_test_runner() -> TestRunner:
    """Get the global test runner instance"""
    return _test_runner


def get_performance_tester() -> PerformanceTester:
    """Get the global performance tester instance"""
    return _performance_tester


def get_load_tester() -> LoadTester:
    """Get the global load tester instance"""
    return _load_tester


def run_tests(test_names: Optional[List[str]] = None) -> List[TestResult]:
    """Run tests using global test runner"""
    return _test_runner.run_tests(test_names)


def benchmark_function(func: Callable, **kwargs) -> Dict[str, Any]:
    """Benchmark function using global performance tester"""
    return _performance_tester.benchmark_function(func, **kwargs)


async def benchmark_async_function(func: Callable, **kwargs) -> Dict[str, Any]:
    """Benchmark async function using global performance tester"""
    return await _performance_tester.benchmark_async_function(func, **kwargs)


async def load_test(operation: Callable, **kwargs) -> Dict[str, Any]:
    """Perform load test using global load tester"""
    return await _load_tester.load_test(operation, **kwargs)
