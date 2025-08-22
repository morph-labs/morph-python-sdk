"""
Red Team Testing Framework

This module provides comprehensive red team testing capabilities including:
- Advanced penetration testing scenarios
- APT simulation and lateral movement testing
- Social engineering and phishing simulation
- Supply chain attack simulation
- Physical security testing scenarios
- Command & control detection testing
"""

import os
import json
import time
import uuid
import hashlib
import hmac
import base64
import logging
import asyncio
import threading
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from datetime import datetime, timedelta
from pathlib import Path
import requests
import paramiko
import docker
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)


class TestCategory(Enum):
    """Red team test categories"""

    API_SECURITY = "api_security"
    SOCIAL_ENGINEERING = "social_engineering"
    APT_SIMULATION = "apt_simulation"
    SUPPLY_CHAIN = "supply_chain"
    PHYSICAL_SECURITY = "physical_security"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_CONTROL = "command_control"


class TestSeverity(Enum):
    """Test severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TestStatus(Enum):
    """Test execution status"""

    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class TestResult:
    """Individual test result"""

    test_id: str
    test_name: str
    category: TestCategory
    severity: TestSeverity
    status: TestStatus
    description: str
    timestamp: float = field(default_factory=time.time)
    execution_time: Optional[float] = None
    details: Optional[Dict[str, Any]] = None
    recommendations: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    false_positive: bool = False


@dataclass
class RedTeamConfig:
    """Red team testing configuration"""

    enable_api_fuzzing: bool = True
    enable_social_engineering: bool = True
    enable_apt_simulation: bool = True
    enable_supply_chain: bool = True
    enable_physical_security: bool = False
    enable_lateral_movement: bool = True
    enable_data_exfiltration: bool = True
    enable_command_control: bool = True

    # API Testing
    api_fuzz_iterations: int = 1000
    api_fuzz_timeout: float = 30.0
    api_rate_limit_bypass: bool = True

    # Social Engineering
    phishing_simulation: bool = True
    credential_stuffing: bool = True
    social_media_recon: bool = True

    # APT Simulation
    lateral_movement_depth: int = 3
    privilege_escalation: bool = True
    persistence_mechanisms: bool = True

    # Supply Chain
    dependency_injection: bool = True
    build_pipeline_compromise: bool = True
    package_registry_poisoning: bool = True

    # Physical Security
    hardware_tampering: bool = False
    side_channel_attacks: bool = False
    physical_access: bool = False

    # Reporting
    generate_report: bool = True
    report_format: str = "json"
    include_evidence: bool = True
    anonymize_data: bool = True


class APIFuzzer:
    """Advanced API fuzzing and security testing"""

    def __init__(self, config: RedTeamConfig):
        self.config = config
        self.fuzz_patterns = self._load_fuzz_patterns()
        self.test_results: List[TestResult] = []

    def _load_fuzz_patterns(self) -> Dict[str, List[str]]:
        """Load comprehensive fuzz patterns"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users --",
                "admin'--",
                "admin'/*",
                "admin'#",
                "admin'/**/OR/**/1=1",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "& cat /etc/passwd",
                "`id`",
                "$(whoami)",
            ],
            "buffer_overflow": [
                "A" * 1000,
                "A" * 10000,
                "A" * 100000,
                "A" * 1000000,
            ],
            "format_string": [
                "%s%s%s%s%s",
                "%x%x%x%x%x",
                "%n%n%n%n%n",
                "%p%p%p%p%p",
            ],
            "null_byte": [
                "test%00.txt",
                "file%00.jpg",
                "data%00",
            ],
            "unicode": [
                "test\u0000.txt",
                "file\u0001.jpg",
                "data\u0002",
            ],
        }

    async def fuzz_api_endpoint(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> List[TestResult]:
        """Fuzz an API endpoint with various attack patterns"""
        results = []

        for attack_type, patterns in self.fuzz_patterns.items():
            for pattern in patterns:
                try:
                    start_time = time.time()

                    # Prepare test payload
                    test_payload = self._prepare_payload(method, pattern, data)

                    # Execute fuzz test
                    response = await self._execute_fuzz_test(
                        url, method, test_payload, headers
                    )

                    # Analyze response for vulnerabilities
                    vulnerabilities = self._analyze_response(
                        response, attack_type, pattern
                    )

                    execution_time = time.time() - start_time

                    # Create test result
                    result = TestResult(
                        test_id=str(uuid.uuid4()),
                        test_name=f"API_FUZZ_{attack_type.upper()}",
                        category=TestCategory.API_SECURITY,
                        severity=(
                            TestSeverity.HIGH if vulnerabilities else TestSeverity.LOW
                        ),
                        status=(
                            TestStatus.FAILED if vulnerabilities else TestStatus.PASSED
                        ),
                        description=f"API fuzzing test for {attack_type} using pattern: {pattern}",
                        execution_time=execution_time,
                        details={
                            "url": url,
                            "method": method,
                            "pattern": pattern,
                            "attack_type": attack_type,
                            "response_status": response.status_code,
                            "response_time": response.elapsed.total_seconds(),
                            "vulnerabilities": vulnerabilities,
                        },
                        recommendations=self._generate_recommendations(
                            vulnerabilities, attack_type
                        ),
                        evidence=(
                            [f"Response: {response.text[:500]}..."]
                            if vulnerabilities
                            else []
                        ),
                    )

                    results.append(result)

                    # Rate limiting
                    await asyncio.sleep(0.1)

                except Exception as e:
                    logger.error(f"Fuzz test failed for {attack_type}: {e}")
                    error_result = TestResult(
                        test_id=str(uuid.uuid4()),
                        test_name=f"API_FUZZ_{attack_type.upper()}_ERROR",
                        category=TestCategory.API_SECURITY,
                        severity=TestSeverity.MEDIUM,
                        status=TestStatus.ERROR,
                        description=f"API fuzzing test failed for {attack_type}",
                        details={"error": str(e)},
                        recommendations=["Review error handling and retry mechanism"],
                    )
                    results.append(error_result)

        return results

    def _prepare_payload(
        self, method: str, pattern: str, original_data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Prepare test payload based on method and pattern"""
        if method.upper() == "GET":
            return {"test": pattern}
        elif method.upper() in ["POST", "PUT", "PATCH"]:
            if original_data:
                # Inject pattern into existing data
                payload = original_data.copy()
                for key in payload:
                    if isinstance(payload[key], str):
                        payload[key] = pattern
                return payload
            else:
                return {"data": pattern}
        else:
            return {"test": pattern}

    async def _execute_fuzz_test(
        self,
        url: str,
        method: str,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]],
    ) -> requests.Response:
        """Execute individual fuzz test"""
        try:
            if method.upper() == "GET":
                response = requests.get(
                    url,
                    params=payload,
                    headers=headers,
                    timeout=self.config.api_fuzz_timeout,
                )
            elif method.upper() == "POST":
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.api_fuzz_timeout,
                )
            elif method.upper() == "PUT":
                response = requests.put(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.api_fuzz_timeout,
                )
            elif method.upper() == "DELETE":
                response = requests.delete(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.api_fuzz_timeout,
                )
            else:
                response = requests.request(
                    method,
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.config.api_fuzz_timeout,
                )

            return response

        except requests.exceptions.RequestException as e:
            # Create a mock response for error cases
            class MockResponse:
                def __init__(self, error):
                    self.status_code = 0
                    self.text = str(error)
                    self.elapsed = timedelta(seconds=0)

            return MockResponse(e)

    def _analyze_response(
        self, response: requests.Response, attack_type: str, pattern: str
    ) -> List[Dict[str, Any]]:
        """Analyze response for potential vulnerabilities"""
        vulnerabilities = []

        # Check for SQL injection indicators
        if attack_type == "sql_injection":
            sql_indicators = [
                "sql syntax",
                "mysql",
                "postgresql",
                "oracle",
                "sqlite",
                "syntax error",
                "unclosed quotation mark",
                "unterminated string",
            ]
            for indicator in sql_indicators:
                if indicator.lower() in response.text.lower():
                    vulnerabilities.append(
                        {
                            "type": "sql_injection",
                            "indicator": indicator,
                            "confidence": "high",
                        }
                    )

        # Check for XSS indicators
        elif attack_type == "xss":
            if pattern in response.text:
                vulnerabilities.append(
                    {
                        "type": "xss",
                        "indicator": "payload reflected in response",
                        "confidence": "high",
                    }
                )

        # Check for command injection indicators
        elif attack_type == "command_injection":
            cmd_indicators = ["uid=", "gid=", "groups=", "root:", "bin:", "daemon:"]
            for indicator in cmd_indicators:
                if indicator in response.text:
                    vulnerabilities.append(
                        {
                            "type": "command_injection",
                            "indicator": indicator,
                            "confidence": "high",
                        }
                    )

        # Check for path traversal indicators
        elif attack_type == "path_traversal":
            if "root:" in response.text or "/etc/passwd" in response.text:
                vulnerabilities.append(
                    {
                        "type": "path_traversal",
                        "indicator": "file content exposed",
                        "confidence": "high",
                    }
                )

        # Check for error disclosure
        if response.status_code >= 500:
            error_indicators = [
                "stack trace",
                "error in",
                "exception",
                "traceback",
                "debug",
                "internal server error",
            ]
            for indicator in error_indicators:
                if indicator.lower() in response.text.lower():
                    vulnerabilities.append(
                        {
                            "type": "error_disclosure",
                            "indicator": indicator,
                            "confidence": "medium",
                        }
                    )

        return vulnerabilities

    def _generate_recommendations(
        self, vulnerabilities: List[Dict[str, Any]], attack_type: str
    ) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        if not vulnerabilities:
            return ["No vulnerabilities detected"]

        for vuln in vulnerabilities:
            if vuln["type"] == "sql_injection":
                recommendations.extend(
                    [
                        "Implement parameterized queries",
                        "Use ORM with built-in SQL injection protection",
                        "Validate and sanitize all user inputs",
                    ]
                )
            elif vuln["type"] == "xss":
                recommendations.extend(
                    [
                        "Implement output encoding",
                        "Use Content Security Policy (CSP)",
                        "Validate and sanitize all user inputs",
                    ]
                )
            elif vuln["type"] == "command_injection":
                recommendations.extend(
                    [
                        "Avoid shell command execution",
                        "Use built-in functions instead of shell commands",
                        "Implement strict input validation",
                    ]
                )
            elif vuln["type"] == "path_traversal":
                recommendations.extend(
                    [
                        "Use absolute paths",
                        "Implement path validation",
                        "Use chroot or containerization",
                    ]
                )
            elif vuln["type"] == "error_disclosure":
                recommendations.extend(
                    [
                        "Disable detailed error messages in production",
                        "Implement custom error handling",
                        "Use generic error messages for users",
                    ]
                )

        return list(set(recommendations))  # Remove duplicates


class SocialEngineeringTester:
    """Social engineering and phishing simulation testing"""

    def __init__(self, config: RedTeamConfig):
        self.config = config
        self.test_results: List[TestResult] = []
        self.phishing_templates = self._load_phishing_templates()

    def _load_phishing_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load phishing email templates"""
        return {
            "credential_harvesting": {
                "subject": "Security Alert - Action Required",
                "body": "Your account has been compromised. Click here to verify: {url}",
                "urgency": "high",
                "target_emotion": "fear",
            },
            "password_reset": {
                "subject": "Password Reset Request",
                "body": "We received a password reset request. Click here: {url}",
                "urgency": "medium",
                "target_emotion": "concern",
            },
            "system_update": {
                "subject": "System Maintenance Required",
                "body": "System update required. Please login: {url}",
                "urgency": "medium",
                "target_emotion": "obligation",
            },
            "social_media": {
                "subject": "New Message from {friend_name}",
                "body": "You have a new message. View it here: {url}",
                "urgency": "low",
                "target_emotion": "curiosity",
            },
        }

    async def test_credential_stuffing(
        self, login_endpoint: str, credentials_file: str
    ) -> List[TestResult]:
        """Test credential stuffing attacks"""
        results = []

        try:
            # Load test credentials
            credentials = self._load_test_credentials(credentials_file)

            for i, (username, password) in enumerate(credentials):
                start_time = time.time()

                try:
                    # Attempt login
                    response = await self._attempt_login(
                        login_endpoint, username, password
                    )

                    # Analyze response
                    success = self._analyze_login_response(response)

                    execution_time = time.time() - start_time

                    result = TestResult(
                        test_id=str(uuid.uuid4()),
                        test_name="CREDENTIAL_STUFFING",
                        category=TestCategory.SOCIAL_ENGINEERING,
                        severity=TestSeverity.HIGH if success else TestSeverity.MEDIUM,
                        status=TestStatus.FAILED if success else TestStatus.PASSED,
                        description=f"Credential stuffing test with {username}:{password}",
                        execution_time=execution_time,
                        details={
                            "username": username,
                            "password": password,
                            "response_status": response.status_code,
                            "success": success,
                            "response_time": (
                                response.elapsed.total_seconds()
                                if hasattr(response, "elapsed")
                                else 0
                            ),
                        },
                        recommendations=(
                            [
                                "Implement account lockout after failed attempts",
                                "Use CAPTCHA for repeated login attempts",
                                "Implement rate limiting on login endpoints",
                                "Use strong password policies",
                            ]
                            if success
                            else ["Credential stuffing protection working correctly"]
                        ),
                        evidence=(
                            [f"Login successful with {username}:{password}"]
                            if success
                            else []
                        ),
                    )

                    results.append(result)

                    # Rate limiting
                    await asyncio.sleep(0.5)

                except Exception as e:
                    logger.error(f"Credential stuffing test failed: {e}")
                    error_result = TestResult(
                        test_id=str(uuid.uuid4()),
                        test_name="CREDENTIAL_STUFFING_ERROR",
                        category=TestCategory.SOCIAL_ENGINEERING,
                        severity=TestSeverity.MEDIUM,
                        status=TestStatus.ERROR,
                        description=f"Credential stuffing test failed",
                        details={"error": str(e)},
                        recommendations=["Review error handling and retry mechanism"],
                    )
                    results.append(error_result)

        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")

        return results

    def _load_test_credentials(self, credentials_file: str) -> List[Tuple[str, str]]:
        """Load test credentials from file"""
        credentials = []

        try:
            with open(credentials_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        username, password = line.split(":", 1)
                        credentials.append((username, password))
        except FileNotFoundError:
            # Use default test credentials
            credentials = [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("user", "user"),
                ("user", "password"),
                ("test", "test"),
                ("guest", "guest"),
                ("root", "root"),
                ("administrator", "admin"),
                ("admin", "administrator"),
            ]

        return credentials

    async def _attempt_login(
        self, endpoint: str, username: str, password: str
    ) -> requests.Response:
        """Attempt login with given credentials"""
        payload = {"username": username, "password": password}

        try:
            response = requests.post(endpoint, json=payload, timeout=30)
            return response
        except requests.exceptions.RequestException as e:
            # Create mock response for error cases
            class MockResponse:
                def __init__(self, error):
                    self.status_code = 0
                    self.text = str(error)
                    self.elapsed = timedelta(seconds=0)

            return MockResponse(e)

    def _analyze_login_response(self, response: requests.Response) -> bool:
        """Analyze login response to determine if login was successful"""
        # Check for success indicators
        success_indicators = [
            "welcome",
            "dashboard",
            "home",
            "success",
            "logged in",
            "authentication successful",
            "login successful",
        ]

        # Check for failure indicators
        failure_indicators = [
            "invalid",
            "failed",
            "error",
            "incorrect",
            "not found",
            "authentication failed",
            "login failed",
        ]

        response_text = response.text.lower()

        # Check status code
        if response.status_code == 200:
            # Look for success indicators in response
            for indicator in success_indicators:
                if indicator in response_text:
                    return True

        elif response.status_code == 401 or response.status_code == 403:
            return False

        # Check response content
        for indicator in success_indicators:
            if indicator in response_text:
                return True

        for indicator in failure_indicators:
            if indicator in response_text:
                return False

        # Default to failure if unclear
        return False


class APTSimulator:
    """Advanced Persistent Threat simulation testing"""

    def __init__(self, config: RedTeamConfig):
        self.config = config
        self.test_results: List[TestResult] = []
        self.lateral_movement_paths: List[List[str]] = []

    async def simulate_lateral_movement(
        self, target_systems: List[str], credentials: Dict[str, str]
    ) -> List[TestResult]:
        """Simulate lateral movement between systems"""
        results = []

        for start_system in target_systems:
            try:
                start_time = time.time()

                # Find lateral movement paths
                paths = await self._find_lateral_movement_paths(
                    start_system, target_systems, credentials
                )

                execution_time = time.time() - start_time

                # Analyze lateral movement success
                successful_paths = [path for path in paths if path["success"]]

                result = TestResult(
                    test_id=str(uuid.uuid4()),
                    test_name="LATERAL_MOVEMENT_SIMULATION",
                    category=TestCategory.APT_SIMULATION,
                    severity=(
                        TestSeverity.CRITICAL
                        if successful_paths
                        else TestSeverity.MEDIUM
                    ),
                    status=TestStatus.FAILED if successful_paths else TestStatus.PASSED,
                    description=f"Lateral movement simulation from {start_system}",
                    execution_time=execution_time,
                    details={
                        "start_system": start_system,
                        "total_paths": len(paths),
                        "successful_paths": len(successful_paths),
                        "paths": paths,
                        "max_depth": self.config.lateral_movement_depth,
                    },
                    recommendations=(
                        [
                            "Implement network segmentation",
                            "Use zero-trust network access",
                            "Implement strong authentication between systems",
                            "Monitor inter-system communications",
                            "Use privileged access management",
                        ]
                        if successful_paths
                        else ["Lateral movement protection working correctly"]
                    ),
                    evidence=[
                        f"Successfully moved to: {path['target']}"
                        for path in successful_paths
                    ],
                )

                results.append(result)

            except Exception as e:
                logger.error(f"Lateral movement simulation failed: {e}")
                error_result = TestResult(
                    test_id=str(uuid.uuid4()),
                    test_name="LATERAL_MOVEMENT_ERROR",
                    category=TestCategory.APT_SIMULATION,
                    severity=TestSeverity.MEDIUM,
                    status=TestStatus.ERROR,
                    description=f"Lateral movement simulation failed",
                    details={"error": str(e)},
                    recommendations=["Review error handling and retry mechanism"],
                )
                results.append(error_result)

        return results

    async def _find_lateral_movement_paths(
        self, start_system: str, target_systems: List[str], credentials: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Find possible lateral movement paths"""
        paths = []
        visited = set()

        def dfs(current_system: str, path: List[str], depth: int):
            if depth > self.config.lateral_movement_depth:
                return

            if current_system in visited:
                return

            visited.add(current_system)
            path.append(current_system)

            # Check if we can access other systems
            for target in target_systems:
                if target != current_system and target not in path:
                    # Attempt lateral movement
                    success = await self._attempt_lateral_movement(
                        current_system, target, credentials
                    )

                    if success:
                        paths.append(
                            {
                                "source": start_system,
                                "target": target,
                                "path": path.copy(),
                                "depth": depth,
                                "success": True,
                                "method": "credential_reuse",
                            }
                        )

                    # Continue exploring from target if successful
                    if success and depth < self.config.lateral_movement_depth:
                        dfs(target, path.copy(), depth + 1)

            # Check for other lateral movement methods
            await self._check_alternative_methods(current_system, path, depth, paths)

        # Start DFS from start system
        dfs(start_system, [], 0)

        return paths

    async def _attempt_lateral_movement(
        self, source: str, target: str, credentials: Dict[str, str]
    ) -> bool:
        """Attempt lateral movement between systems"""
        try:
            # Try SSH connection
            if await self._test_ssh_access(target, credentials):
                return True

            # Try HTTP/HTTPS access
            if await self._test_http_access(target, credentials):
                return True

            # Try database connection
            if await self._test_database_access(target, credentials):
                return True

            # Try file sharing
            if await self._test_file_sharing(source, target, credentials):
                return True

            return False

        except Exception as e:
            logger.error(f"Lateral movement test failed: {e}")
            return False

    async def _test_ssh_access(self, target: str, credentials: Dict[str, str]) -> bool:
        """Test SSH access to target system"""
        try:
            for username, password in credentials.items():
                try:
                    # Create SSH client
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    # Attempt connection
                    client.connect(
                        target, username=username, password=password, timeout=10
                    )
                    client.close()
                    return True

                except Exception:
                    continue

            return False

        except Exception:
            return False

    async def _test_http_access(self, target: str, credentials: Dict[str, str]) -> bool:
        """Test HTTP access to target system"""
        try:
            # Try common ports
            ports = [80, 443, 8080, 8443, 3000, 5000, 8000]

            for port in ports:
                try:
                    url = f"http://{target}:{port}"
                    response = requests.get(url, timeout=5)
                    if response.status_code < 400:
                        return True
                except:
                    continue

            return False

        except Exception:
            return False

    async def _test_database_access(
        self, target: str, credentials: Dict[str, str]
    ) -> bool:
        """Test database access to target system"""
        # This would test various database connections
        # Implementation depends on available database drivers
        return False

    async def _test_file_sharing(
        self, source: str, target: str, credentials: Dict[str, str]
    ) -> bool:
        """Test file sharing between systems"""
        # This would test SMB, NFS, or other file sharing protocols
        # Implementation depends on available libraries
        return False

    async def _check_alternative_methods(
        self,
        current_system: str,
        path: List[str],
        depth: int,
        paths: List[Dict[str, Any]],
    ):
        """Check for alternative lateral movement methods"""
        # Check for shared credentials
        # Check for trust relationships
        # Check for service accounts
        # Check for scheduled tasks
        pass


class RedTeamTestRunner:
    """Main red team test runner"""

    def __init__(self, config: RedTeamConfig):
        self.config = config
        self.api_fuzzer = APIFuzzer(config)
        self.social_engineering = SocialEngineeringTester(config)
        self.apt_simulator = APTSimulator(config)
        self.all_results: List[TestResult] = []

    async def run_comprehensive_tests(self, targets: Dict[str, Any]) -> Dict[str, Any]:
        """Run comprehensive red team tests"""
        start_time = time.time()

        logger.info("Starting comprehensive red team testing...")

        # Run API security tests
        if self.config.enable_api_fuzzing and "api_endpoints" in targets:
            logger.info("Running API security tests...")
            api_results = await self._run_api_tests(targets["api_endpoints"])
            self.all_results.extend(api_results)

        # Run social engineering tests
        if self.config.enable_social_engineering and "login_endpoints" in targets:
            logger.info("Running social engineering tests...")
            social_results = await self._run_social_engineering_tests(
                targets["login_endpoints"]
            )
            self.all_results.extend(social_results)

        # Run APT simulation tests
        if self.config.enable_apt_simulation and "target_systems" in targets:
            logger.info("Running APT simulation tests...")
            apt_results = await self._run_apt_tests(targets["target_systems"])
            self.all_results.extend(apt_results)

        # Run supply chain tests
        if self.config.enable_supply_chain:
            logger.info("Running supply chain tests...")
            supply_chain_results = await self._run_supply_chain_tests()
            self.all_results.extend(supply_chain_results)

        execution_time = time.time() - start_time

        # Generate comprehensive report
        report = self._generate_report(execution_time)

        logger.info(f"Red team testing completed in {execution_time:.2f} seconds")

        return report

    async def _run_api_tests(
        self, api_endpoints: List[Dict[str, Any]]
    ) -> List[TestResult]:
        """Run API security tests"""
        results = []

        for endpoint in api_endpoints:
            try:
                endpoint_results = await self.api_fuzzer.fuzz_api_endpoint(
                    url=endpoint["url"],
                    method=endpoint.get("method", "GET"),
                    headers=endpoint.get("headers"),
                    data=endpoint.get("data"),
                )
                results.extend(endpoint_results)

            except Exception as e:
                logger.error(f"API test failed for {endpoint['url']}: {e}")

        return results

    async def _run_social_engineering_tests(
        self, login_endpoints: List[Dict[str, Any]]
    ) -> List[TestResult]:
        """Run social engineering tests"""
        results = []

        for endpoint in login_endpoints:
            try:
                endpoint_results = (
                    await self.social_engineering.test_credential_stuffing(
                        login_endpoint=endpoint["url"],
                        credentials_file=endpoint.get(
                            "credentials_file", "test_credentials.txt"
                        ),
                    )
                )
                results.extend(endpoint_results)

            except Exception as e:
                logger.error(
                    f"Social engineering test failed for {endpoint['url']}: {e}"
                )

        return results

    async def _run_apt_tests(self, target_systems: List[str]) -> List[TestResult]:
        """Run APT simulation tests"""
        # This would use real credentials in a controlled environment
        # For safety, we'll use mock credentials
        mock_credentials = {
            "admin": "password123",
            "user": "user123",
            "service": "service123",
        }

        results = await self.apt_simulator.simulate_lateral_movement(
            target_systems, mock_credentials
        )

        return results

    async def _run_supply_chain_tests(self) -> List[TestResult]:
        """Run supply chain security tests"""
        # This would test dependency injection, build pipeline compromise, etc.
        # Implementation depends on the specific environment
        return []

    def _generate_report(self, execution_time: float) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        # Calculate statistics
        total_tests = len(self.all_results)
        passed_tests = len(
            [r for r in self.all_results if r.status == TestStatus.PASSED]
        )
        failed_tests = len(
            [r for r in self.all_results if r.status == TestStatus.FAILED]
        )
        blocked_tests = len(
            [r for r in self.all_results if r.status == TestStatus.BLOCKED]
        )
        error_tests = len([r for r in self.all_results if r.status == TestStatus.ERROR])

        # Calculate security score
        security_score = self._calculate_security_score()

        # Group results by category
        results_by_category = {}
        for result in self.all_results:
            category = result.category.value
            if category not in results_by_category:
                results_by_category[category] = []
            results_by_category[category].append(result)

        # Generate recommendations
        recommendations = self._generate_overall_recommendations()

        report = {
            "test_summary": {
                "total_tests": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "blocked": blocked_tests,
                "errors": error_tests,
                "execution_time": execution_time,
                "security_score": security_score,
            },
            "results_by_category": results_by_category,
            "critical_findings": [
                r for r in self.all_results if r.severity == TestSeverity.CRITICAL
            ],
            "high_findings": [
                r for r in self.all_results if r.severity == TestSeverity.HIGH
            ],
            "recommendations": recommendations,
            "timestamp": datetime.utcnow().isoformat(),
            "config": {
                "enable_api_fuzzing": self.config.enable_api_fuzzing,
                "enable_social_engineering": self.config.enable_social_engineering,
                "enable_apt_simulation": self.config.enable_apt_simulation,
                "enable_supply_chain": self.config.enable_supply_chain,
            },
        }

        return report

    def _calculate_security_score(self) -> float:
        """Calculate overall security score"""
        if not self.all_results:
            return 100.0

        # Weight scores by severity
        severity_weights = {
            TestSeverity.LOW: 1,
            TestSeverity.MEDIUM: 2,
            TestSeverity.HIGH: 3,
            TestSeverity.CRITICAL: 4,
        }

        total_weight = 0
        weighted_score = 0

        for result in self.all_results:
            weight = severity_weights.get(result.severity, 1)
            total_weight += weight

            if result.status == TestStatus.PASSED:
                weighted_score += weight * 100
            elif result.status == TestStatus.BLOCKED:
                weighted_score += weight * 90
            elif result.status == TestStatus.FAILED:
                weighted_score += weight * 0
            elif result.status == TestStatus.ERROR:
                weighted_score += weight * 50

        if total_weight == 0:
            return 100.0

        return weighted_score / total_weight

    def _generate_overall_recommendations(self) -> List[str]:
        """Generate overall security recommendations"""
        recommendations = []

        # Count vulnerabilities by type
        vuln_counts = {}
        for result in self.all_results:
            if result.status == TestStatus.FAILED:
                category = result.category.value
                vuln_counts[category] = vuln_counts.get(category, 0) + 1

        # Generate category-specific recommendations
        if vuln_counts.get("api_security", 0) > 0:
            recommendations.append(
                "Implement comprehensive input validation and sanitization"
            )
            recommendations.append("Add rate limiting and DDoS protection")
            recommendations.append(
                "Implement proper error handling without information disclosure"
            )

        if vuln_counts.get("social_engineering", 0) > 0:
            recommendations.append(
                "Implement account lockout and rate limiting on authentication endpoints"
            )
            recommendations.append("Add CAPTCHA and multi-factor authentication")
            recommendations.append("Implement strong password policies")

        if vuln_counts.get("apt_simulation", 0) > 0:
            recommendations.append(
                "Implement network segmentation and zero-trust architecture"
            )
            recommendations.append("Add privileged access management")
            recommendations.append("Implement comprehensive monitoring and alerting")

        if vuln_counts.get("supply_chain", 0) > 0:
            recommendations.append("Implement dependency scanning and verification")
            recommendations.append("Add build pipeline security controls")
            recommendations.append("Implement package signing and verification")

        # General recommendations
        if len(recommendations) > 0:
            recommendations.append(
                "Conduct regular security assessments and penetration testing"
            )
            recommendations.append(
                "Implement security monitoring and incident response procedures"
            )
            recommendations.append(
                "Provide security training for development and operations teams"
            )

        return recommendations


# Utility functions
def get_red_team_runner(config: RedTeamConfig = None) -> RedTeamTestRunner:
    """Get red team test runner instance"""
    if config is None:
        config = RedTeamConfig()
    return RedTeamTestRunner(config)


async def run_red_team_tests(
    targets: Dict[str, Any], config: RedTeamConfig = None
) -> Dict[str, Any]:
    """Quick function to run red team tests"""
    runner = get_red_team_runner(config)
    return await runner.run_comprehensive_tests(targets)


def generate_red_team_report(results: List[TestResult]) -> Dict[str, Any]:
    """Generate report from test results"""
    runner = RedTeamTestRunner(RedTeamConfig())
    runner.all_results = results
    return runner._generate_report(0.0)
