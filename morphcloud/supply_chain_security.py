"""
Supply Chain Security Module

This module provides comprehensive supply chain security including:
- Dependency poisoning detection and prevention
- Build system security analysis
- Package signing verification (GPG, checksums)
- Vulnerability scanning for third-party dependencies
- Secure dependency management
- Advanced typosquatting detection
- CI/CD pipeline security analysis
- Package integrity verification
"""

import os
import hashlib
import subprocess
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from pathlib import Path
import yaml
import re
import difflib
import aiohttp
from datetime import datetime


logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Supply chain security levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityType(Enum):
    """Types of supply chain vulnerabilities"""

    DEPENDENCY_POISONING = "dependency_poisoning"
    BUILD_COMPROMISE = "build_compromise"
    PACKAGE_TAMPERING = "package_tampering"
    VERSION_PINNING = "version_pinning"
    INSECURE_DEPENDENCY = "inssecure_dependency"
    LICENSE_VIOLATION = "license_ violation"
    TYPOSQUATTING = "typosquatting"
    MALICIOUS_CODE_INJECTION = "malicious_code_injection"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    UNSAFE_BUILD_COMMANDS = "unsafe_build_commands"


class ThreatLevel(Enum):
    """Threat levels for security events"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DependencyInfo:
    """Information about a dependency"""

    name: str
    version: str
    source: str
    checksum: Optional[str] = None
    signature: Optional[str] = None
    license: Optional[str] = None
    maintainer: Optional[str] = None
    last_updated: Optional[str] = None
    vulnerability_count: int = 0
    security_score: float = 0.0
    typosquatting_risk: float = 0.0
    maintainer_reputation: float = 0.0
    download_count: Optional[int] = None
    github_stars: Optional[int] = None
    last_commit_date: Optional[str] = None


@dataclass
class VulnerabilityInfo:
    """Information about a vulnerability"""

    vulnerability_id: str
    type: VulnerabilityType
    severity: SecurityLevel
    description: str
    affected_packages: List[str]
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    discovered_date: Optional[datetime] = None
    exploit_available: bool = False
    patch_available: bool = False


@dataclass
class BuildSystemInfo:
    """Information about build system security"""

    build_file_path: str
    build_file_type: str
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    security_score: float = 100.0
    unsafe_commands: List[str] = field(default_factory=list)
    hardcoded_secrets: List[str] = field(default_factory=list)
    insecure_urls: List[str] = field(default_factory=list)
    wildcard_permissions: List[str] = field(default_factory=list)
    dependency_injection_risks: List[str] = field(default_factory=list)


@dataclass
class PackageIntegrityInfo:
    """Information about package integrity"""

    package_path: str
    checksum_verified: bool = False
    signature_verified: bool = False
    gpg_verified: bool = False
    integrity_score: float = 0.0
    verification_errors: List[str] = field(default_factory=list)
    checksum_algorithm: Optional[str] = None
    expected_checksum: Optional[str] = None
    actual_checksum: Optional[str] = None
    gpg_key_id: Optional[str] = None
    gpg_signature: Optional[str] = None


@dataclass
class SupplyChainConfig:
    """Supply chain security configuration"""

    security_level: SecurityLevel = SecurityLevel.HIGH
    enable_dependency_scanning: bool = True
    enable_build_analysis: bool = True
    enable_package_verification: bool = True
    enable_typosquatting_detection: bool = True
    enable_license_checking: bool = True
    enable_ci_cd_analysis: bool = True
    enable_package_integrity_checking: bool = True
    max_vulnerability_severity: SecurityLevel = SecurityLevel.MEDIUM
    typosquatting_similarity_threshold: float = 0.8
    allowed_licenses: Set[str] = field(
        default_factory=lambda: {
            "MIT",
            "Apache-2.0",
            "BSD-3-Clause",
            "BSD-2-Clause",
            "ISC",
            "Unlicense",
        }
    )
    blocked_licenses: Set[str] = field(
        default_factory=lambda: {"GPL-3.0", "AGPL-3.0", "LGPL-3.0"}
    )
    trusted_maintainers: Set[str] = field(default_factory=set)
    checksum_verification: bool = True
    gpg_verification: bool = True
    npm_registry_url: str = "https://registry.npmjs.org"
    pypi_index_url: str = "https://pypi.org/simple"
    github_api_url: str = "https://api.github.com"
    github_token: Optional[str] = None


class AdvancedDependencyScanner:
    """Advanced dependency scanner with enhanced security analysis"""

    def __init__(self, config: SupplyChainConfig):
        self.config = config
        self.typosquatting_patterns = self._init_typosquatting_patterns()
        self.vulnerability_cache = {}
        self.maintainer_reputation_cache = {}
        self._init_vulnerability_database()

    def _init_typosquatting_patterns(self) -> Dict[str, List[str]]:
        """Initialize typosquatting detection patterns"""
        return {
            "common_typos": [
                "urllib",
                "urllib2",
                "urllib3",  # Python
                "request",
                "requests",  # Python
                "lodash",
                "lodash-",
                "lodash.",  # Node.js
                "express",
                "express-",
                "express.",  # Node.js
                "react",
                "react-",
                "react.",  # Node.js
                "vue",
                "vue-",
                "vue.",  # Node.js
            ],
            "homograph_attacks": [
                "xn--",  # Punycode domains
                "xn--",  # IDN homographs
            ],
            "similar_packages": [
                "moment",
                "moment-timezone",
                "momentjs",
                "lodash",
                "lodash-es",
                "lodash-fp",
                "axios",
                "axios-",
                "axios.",
            ],
        }

    def _init_vulnerability_database(self):
        """Initialize vulnerability database connections"""
        # This would connect to NVD, GitHub Security Advisories, etc.
        pass

    async def comprehensive_scan(self, project_path: str = ".") -> Dict[str, Any]:
        """Perform comprehensive supply chain security scan"""
        try:
            scan_results = {
                "project_path": project_path,
                "scan_timestamp": datetime.utcnow().isoformat(),
                "dependencies": {},
                "build_system": {},
                "package_integrity": {},
                "overall_security_score": 0.0,
                "critical_issues": [],
                "recommendations": [],
            }

            # Scan dependencies
            if self.config.enable_dependency_scanning:
                scan_results["dependencies"] = await self._scan_dependencies(
                    project_path
                )

            # Analyze build system
            if self.config.enable_build_analysis:
                scan_results["build_system"] = await self._analyze_build_system(
                    project_path
                )

            # Check package integrity
            if self.config.enable_package_verification:
                scan_results["package_integrity"] = (
                    await self._verify_package_integrity(project_path)
                )

            # Calculate overall security score
            scan_results["overall_security_score"] = self._calculate_overall_score(
                scan_results
            )

            # Identify critical issues
            scan_results["critical_issues"] = self._identify_critical_issues(
                scan_results
            )

            # Generate recommendations
            scan_results["recommendations"] = self._generate_recommendations(
                scan_results
            )

            return scan_results

        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            return {"error": str(e)}

    async def _scan_dependencies(self, project_path: str) -> Dict[str, Any]:
        """Enhanced dependency scanning with advanced security checks"""
        try:
            dependencies = await self._parse_dependencies(project_path)
            enhanced_deps = {}

            for dep in dependencies:
                dep_info = await self._enhance_dependency_info(dep)
                enhanced_deps[dep.name] = dep_info

            return {
                "total_dependencies": len(enhanced_deps),
                "vulnerable_dependencies": len(
                    [d for d in enhanced_deps.values() if d.vulnerability_count > 0]
                ),
                "high_risk_dependencies": len(
                    [d for d in enhanced_deps.values() if d.security_score < 50]
                ),
                "dependencies": enhanced_deps,
            }

        except Exception as e:
            logger.error(f"Dependency scanning failed: {e}")
            return {"error": str(e)}

    async def _enhance_dependency_info(self, dep: DependencyInfo) -> DependencyInfo:
        """Enhance dependency information with security analysis"""
        try:
            # Check for typosquatting
            dep.typosquatting_risk = await self._check_typosquatting_risk(dep.name)

            # Check maintainer reputation
            dep.maintainer_reputation = await self._check_maintainer_reputation(
                dep.maintainer
            )

            # Get package statistics
            stats = await self._get_package_statistics(dep.name, dep.source)
            if stats:
                dep.download_count = stats.get("download_count")
                dep.github_stars = stats.get("github_stars")
                dep.last_commit_date = stats.get("last_commit_date")

            # Check for vulnerabilities
            vulnerabilities = await self._check_vulnerabilities(dep.name, dep.version)
            dep.vulnerability_count = len(vulnerabilities)

            # Calculate security score
            dep.security_score = self._calculate_dependency_security_score(
                dep, vulnerabilities
            )

            return dep

        except Exception as e:
            logger.error(f"Failed to enhance dependency info for {dep.name}: {e}")
            return dep

    async def _check_typosquatting_risk(self, package_name: str) -> float:
        """Check for typosquatting risk using advanced algorithms"""
        try:
            risk_score = 0.0

            # Check against known popular packages
            popular_packages = [
                "requests",
                "urllib3",
                "numpy",
                "pandas",
                "tensorflow",
                "react",
                "vue",
                "angular",
                "express",
                "lodash",
            ]

            for popular_pkg in popular_packages:
                similarity = self._calculate_similarity(
                    package_name.lower(), popular_pkg.lower()
                )
                if similarity > self.config.typosquatting_similarity_threshold:
                    risk_score = max(risk_score, similarity)

            # Check for homograph attacks
            if any(
                pattern in package_name
                for pattern in self.typosquatting_patterns["homograph_attacks"]
            ):
                risk_score = max(risk_score, 0.9)

            # Check for common typos
            for typo_pattern in self.typosquatting_patterns["common_typos"]:
                if typo_pattern in package_name:
                    risk_score = max(risk_score, 0.8)

            # Check for similar package names
            for similar_pattern in self.typosquatting_patterns["similar_packages"]:
                if similar_pattern in package_name:
                    similarity = self._calculate_similarity(
                        package_name, similar_pattern
                    )
                    if similarity > 0.7:
                        risk_score = max(risk_score, similarity * 0.8)

            return min(risk_score, 1.0)

        except Exception as e:
            logger.error(f"Typosquatting check failed for {package_name}: {e}")
            return 0.0

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using multiple algorithms"""
        try:
            # Levenshtein distance
            def levenshtein_distance(s1, s2):
                if len(s1) < len(s2):
                    return levenshtein_distance(s2, s1)
                if len(s2) == 0:
                    return len(s1)
                previous_row = list(range(len(s2) + 1))
                for i, c1 in enumerate(s1):
                    current_row = [i + 1]
                    for j, c2 in enumerate(s2):
                        insertions = previous_row[j + 1] + 1
                        deletions = current_row[j] + 1
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))
                    previous_row = current_row
                return previous_row[-1]

            # Calculate similarity scores
            max_len = max(len(str1), len(str2))
            if max_len == 0:
                return 1.0

            levenshtein_sim = 1 - (levenshtein_distance(str1, str2) / max_len)

            # Sequence matcher similarity
            sequence_sim = difflib.SequenceMatcher(None, str1, str2).ratio()

            # Jaccard similarity for character sets
            set1, set2 = set(str1), set(str2)
            jaccard_sim = (
                len(set1.intersection(set2)) / len(set1.union(set2))
                if set1.union(set2)
                else 0
            )

            # Weighted average of similarity scores
            weighted_sim = (
                levenshtein_sim * 0.4 + sequence_sim * 0.4 + jaccard_sim * 0.2
            )

            return weighted_sim

        except Exception as e:
            logger.error(f"Similarity calculation failed: {e}")
            return 0.0

    async def _check_maintainer_reputation(self, maintainer: Optional[str]) -> float:
        """Check maintainer reputation and trustworthiness"""
        if not maintainer:
            return 0.0

        try:
            # Check cache first
            if maintainer in self.maintainer_reputation_cache:
                return self.maintainer_reputation_cache[maintainer]

            reputation_score = 0.0

            # Check if maintainer is in trusted list
            if maintainer in self.config.trusted_maintainers:
                reputation_score = 1.0
            else:
                # Check GitHub profile if available
                github_info = await self._get_github_user_info(maintainer)
                if github_info:
                    reputation_score = self._calculate_github_reputation(github_info)

            # Cache the result
            self.maintainer_reputation_cache[maintainer] = reputation_score
            return reputation_score

        except Exception as e:
            logger.error(f"Maintainer reputation check failed for {maintainer}: {e}")
            return 0.0

    async def _get_github_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get GitHub user information"""
        try:
            if not self.config.github_token:
                return None

            headers = {
                "Authorization": f"token {self.config.github_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.config.github_api_url}/users/{username}", headers=headers
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    return None

        except Exception as e:
            logger.debug(f"Failed to get GitHub user info for {username}: {e}")
            return None

    def _calculate_github_reputation(self, github_info: Dict[str, Any]) -> float:
        """Calculate reputation score based on GitHub information"""
        try:
            score = 0.0

            # Account age (older accounts are generally more trusted)
            created_at = github_info.get("created_at")
            if created_at:
                account_age = (
                    datetime.utcnow()
                    - datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                ).days
                if account_age > 365 * 2:  # 2+ years
                    score += 0.3
                elif account_age > 365:  # 1+ years
                    score += 0.2

            # Public repositories
            public_repos = github_info.get("public_repos", 0)
            if public_repos > 50:
                score += 0.3
            elif public_repos > 20:
                score += 0.2
            elif public_repos > 5:
                score += 0.1

            # Followers
            followers = github_info.get("followers", 0)
            if followers > 100:
                score += 0.2
            elif followers > 50:
                score += 0.1

            # Verified email
            if github_info.get("email"):
                score += 0.1

            # Company/organization
            if github_info.get("company"):
                score += 0.1

            return min(score, 1.0)

        except Exception as e:
            logger.error(f"GitHub reputation calculation failed: {e}")
            return 0.0

    async def _get_package_statistics(
        self, package_name: str, source: str
    ) -> Optional[Dict[str, Any]]:
        """Get package statistics from various sources"""
        try:
            if source == "pypi":
                return await self._get_pypi_statistics(package_name)
            elif source == "npm":
                return await self._get_npm_statistics(package_name)
            else:
                return None

        except Exception as e:
            logger.debug(f"Failed to get package statistics for {package_name}: {e}")
            return None

    async def _get_pypi_statistics(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Get PyPI package statistics"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.config.pypi_index_url}/{package_name}/"
                ) as response:
                    if response.status == 200:
                        # Parse PyPI simple index
                        content = await response.text()
                        # Extract version information and calculate download stats
                        # This is a simplified implementation
                        return {
                            "download_count": None,  # Would need PyPI JSON API
                            "github_stars": None,  # Would need GitHub API
                            "last_commit_date": None,
                        }
                    return None

        except Exception as e:
            logger.debug(f"Failed to get PyPI statistics for {package_name}: {e}")
            return None

    async def _get_npm_statistics(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Get NPM package statistics"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.config.npm_registry_url}/{package_name}"
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "download_count": data.get("downloads", {}).get("total"),
                            "github_stars": None,  # Would need GitHub API
                            "last_commit_date": data.get("time", {}).get("modified"),
                        }
                    return None

        except Exception as e:
            logger.debug(f"Failed to get NPM statistics for {package_name}: {e}")
            return None

    async def _check_vulnerabilities(
        self, package_name: str, version_spec: str
    ) -> List[VulnerabilityInfo]:
        """Check for known vulnerabilities in package"""
        try:
            # Check cache first
            cache_key = f"{package_name}_{version_spec}"
            if cache_key in self.vulnerability_cache:
                return self.vulnerability_cache[cache_key]

            vulnerabilities = []

            # Check NVD database
            nvd_vulns = await self._check_nvd_vulnerabilities(
                package_name, version_spec
            )
            vulnerabilities.extend(nvd_vulns)

            # Check GitHub Security Advisories
            github_vulns = await self._check_github_advisories(
                package_name, version_spec
            )
            vulnerabilities.extend(github_vulns)

            # Cache results
            self.vulnerability_cache[cache_key] = vulnerabilities
            return vulnerabilities

        except Exception as e:
            logger.error(f"Vulnerability check failed for {package_name}: {e}")
            return []

    async def _check_nvd_vulnerabilities(
        self, package_name: str, version_spec: str
    ) -> List[VulnerabilityInfo]:
        """Check NVD database for vulnerabilities"""
        # This would implement NVD API calls
        # For now, return empty list
        return []

    async def _check_github_advisories(
        self, package_name: str, version_spec: str
    ) -> List[VulnerabilityInfo]:
        """Check GitHub Security Advisories"""
        # This would implement GitHub Security Advisories API calls
        # For now, return empty list
        return []

    def _calculate_dependency_security_score(
        self, dep: DependencyInfo, vulnerabilities: List[VulnerabilityInfo]
    ) -> float:
        """Calculate security score for a dependency"""
        try:
            base_score = 100.0

            # Deduct points for vulnerabilities
            for vuln in vulnerabilities:
                if vuln.severity == SecurityLevel.CRITICAL:
                    base_score -= 25
                elif vuln.severity == SecurityLevel.HIGH:
                    base_score -= 15
                elif vuln.severity == SecurityLevel.MEDIUM:
                    base_score -= 10
                elif vuln.severity == SecurityLevel.LOW:
                    base_score -= 5

            # Deduct points for typosquatting risk
            base_score -= dep.typosquatting_risk * 20

            # Deduct points for low maintainer reputation
            base_score -= (1 - dep.maintainer_reputation) * 15

            # Deduct points for license violations
            if dep.license in self.config.blocked_licenses:
                base_score -= 20

            return max(0.0, base_score)

        except Exception as e:
            logger.error(f"Security score calculation failed for {dep.name}: {e}")
            return 0.0

    async def _analyze_build_system(self, project_path: str) -> Dict[str, Any]:
        """Analyze build system security"""
        try:
            build_files = self._find_build_files(project_path)
            build_analysis = {}

            for build_file in build_files:
                analysis = await self._analyze_build_file(build_file)
                build_analysis[build_file] = analysis

            return {
                "total_build_files": len(build_files),
                "files_analyzed": build_analysis,
                "overall_security_score": self._calculate_build_security_score(
                    build_analysis.values()
                ),
                "critical_issues": self._identify_build_critical_issues(
                    build_analysis.values()
                ),
            }

        except Exception as e:
            logger.error(f"Build system analysis failed: {e}")
            return {"error": str(e)}

    def _identify_build_critical_issues(self, build_analyses) -> List[str]:
        """Identify critical security issues in build system"""
        critical_issues = []

        for analysis in build_analyses:
            if analysis.security_score < 50:
                critical_issues.append(
                    f"Critical security issues in {analysis.build_file_path}"
                )

            for issue in analysis.security_issues:
                if issue.get("severity") == "critical":
                    critical_issues.append(
                        f"Critical: {issue.get('description')} in {analysis.build_file_path}"
                    )

        return critical_issues

    def _calculate_overall_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate overall security score"""
        try:
            scores = []
            weights = []

            # Dependency security score
            if (
                "dependencies" in scan_results
                and "dependencies" in scan_results["dependencies"]
            ):
                deps = scan_results["dependencies"]["dependencies"]
                if deps:
                    dep_scores = [dep.security_score for dep in deps.values()]
                    scores.append(sum(dep_scores) / len(dep_scores))
                    weights.append(0.4)

            # Build system security score
            if (
                "build_system" in scan_results
                and "overall_security_score" in scan_results["build_system"]
            ):
                scores.append(scan_results["build_system"]["overall_security_score"])
                weights.append(0.3)

            # Package integrity score
            if (
                "package_integrity" in scan_results
                and "overall_score" in scan_results["package_integrity"]
            ):
                scores.append(scan_results["package_integrity"]["overall_score"])
                weights.append(0.3)

            if not scores:
                return 0.0

            # Calculate weighted average
            weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
            total_weight = sum(weights)

            return weighted_sum / total_weight if total_weight > 0 else 0.0

        except Exception as e:
            logger.error(f"Overall score calculation failed: {e}")
            return 0.0

    def _identify_critical_issues(self, scan_results: Dict[str, Any]) -> List[str]:
        """Identify critical security issues"""
        critical_issues = []

        # Check dependencies
        if "dependencies" in scan_results:
            deps = scan_results["dependencies"].get("dependencies", {})
            for dep_name, dep_info in deps.items():
                if dep_info.security_score < 30:
                    critical_issues.append(
                        f"Critical: {dep_name} has very low security score ({dep_info.security_score})"
                    )
                if dep_info.typosquatting_risk > 0.8:
                    critical_issues.append(
                        f"Critical: {dep_name} has high typosquatting risk ({dep_info.typosquatting_risk})"
                    )

        # Check build system
        if "build_system" in scan_results:
            build_issues = scan_results["build_system"].get("critical_issues", [])
            critical_issues.extend(build_issues)

        return critical_issues

    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Dependency recommendations
        if "dependencies" in scan_results:
            deps = scan_results["dependencies"].get("dependencies", {})
            low_score_deps = [
                name for name, info in deps.items() if info.security_score < 50
            ]
            if low_score_deps:
                recommendations.append(
                    f"Review and update low-security dependencies: {', '.join(low_score_deps)}"
                )

            high_typo_deps = [
                name for name, info in deps.items() if info.typosquatting_risk > 0.7
            ]
            if high_typo_deps:
                recommendations.append(
                    f"Verify high-typosquatting-risk dependencies: {', '.join(high_typo_deps)}"
                )

        # Build system recommendations
        if "build_system" in scan_results:
            build_score = scan_results["build_system"].get(
                "overall_security_score", 100
            )
            if build_score < 70:
                recommendations.append("Review build system security configuration")

        # General recommendations
        if scan_results.get("overall_security_score", 100) < 70:
            recommendations.append(
                "Implement comprehensive supply chain security measures"
            )
            recommendations.append(
                "Consider using dependency lock files and reproducible builds"
            )

        return recommendations


class BuildSystemAnalyzer:
    """Analyze build system security"""

    def __init__(self, config: SupplyChainConfig):
        self.config = config

    def analyze_build_system(self, project_path: str = ".") -> Dict[str, Any]:
        """Analyze build system security"""
        analysis_result = {
            "build_files": [],
            "security_issues": [],
            "security_score": 100.0,
            "recommendations": [],
        }

        try:
            # Check for common build files
            build_files = self._find_build_files(project_path)
            analysis_result["build_files"] = build_files

            # Analyze each build file
            for build_file in build_files:
                file_issues = self._analyze_build_file(build_file)
                analysis_result["security_issues"].extend(file_issues)

            # Calculate security score
            analysis_result["security_score"] = self._calculate_build_security_score(
                analysis_result["security_issues"]
            )

            # Generate recommendations
            analysis_result["recommendations"] = self._generate_build_recommendations(
                analysis_result
            )

        except Exception as e:
            logger.error(f"Build system analysis failed: {e}")
            analysis_result["error"] = str(e)

        return analysis_result

    def _find_build_files(self, project_path: str) -> List[str]:
        """Find build system files in project"""
        build_files = []

        common_build_files = [
            "setup.py",
            "setup.cfg",
            "pyproject.toml",
            "requirements.txt",
            "Pipfile",
            "poetry.lock",
            "tox.ini",
            "pytest.ini",
            ".flake8",
            "Makefile",
            "Dockerfile",
            "docker-compose.yml",
            ".github/workflows/",
            ".gitlab-ci.yml",
            ".travis.yml",
            "Jenkinsfile",
        ]

        for file_name in common_build_files:
            file_path = os.path.join(project_path, file_name)
            if os.path.exists(file_path):
                build_files.append(file_path)

        return build_files

    def _analyze_build_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze security of a build file"""
        issues = []

        try:
            with open(file_path, "r") as f:
                content = f.read()

            # Check for common security issues
            if self._contains_hardcoded_secrets(content):
                issues.append(
                    {
                        "type": "hardcoded_secrets",
                        "severity": SecurityLevel.HIGH,
                        "description": f"Hardcoded secrets found in {file_path}",
                        "file": file_path,
                    }
                )

            if self._contains_unsafe_commands(content):
                issues.append(
                    {
                        "type": "unsafe_commands",
                        "severity": SecurityLevel.MEDIUM,
                        "description": f"Potentially unsafe commands found in {file_path}",
                        "file": file_path,
                    }
                )

            if self._contains_insecure_urls(content):
                issues.append(
                    {
                        "type": "insecure_urls",
                        "severity": SecurityLevel.MEDIUM,
                        "description": f"Insecure URLs found in {file_path}",
                        "file": file_path,
                    }
                )

            if self._contains_wildcard_permissions(content):
                issues.append(
                    {
                        "type": "wildcard_permissions",
                        "severity": SecurityLevel.LOW,
                        "description": f"Wildcard permissions found in {file_path}",
                        "file": file_path,
                    }
                )

        except Exception as e:
            logger.warning(f"Failed to analyze {file_path}: {e}")

        return issues

    def _contains_hardcoded_secrets(self, content: str) -> bool:
        """Check for hardcoded secrets in content"""
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'private_key\s*=\s*["\'][^"\']+["\']',
        ]

        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    def _contains_unsafe_commands(self, content: str) -> bool:
        """Check for potentially unsafe commands"""
        unsafe_patterns = [
            r"rm\s+-rf",
            r"chmod\s+777",
            r"chown\s+root",
            r"sudo\s+",
            r"eval\s*\(",
            r"exec\s*\(",
            r"os\.system\s*\(",
        ]

        for pattern in unsafe_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    def _contains_insecure_urls(self, content: str) -> bool:
        """Check for insecure URLs"""
        insecure_patterns = [r'http://[^\s"\']+', r'ftp://[^\s"\']+']

        for pattern in insecure_patterns:
            if re.search(pattern, content):
                return True

        return False

    def _contains_wildcard_permissions(self, content: str) -> bool:
        """Check for wildcard permissions"""
        wildcard_patterns = [r"chmod\s+[0-7][0-7][0-7]", r"umask\s+000"]

        for pattern in wildcard_patterns:
            if re.search(pattern, content):
                return True

        return False

    def _calculate_build_security_score(self, issues: List[Dict[str, Any]]) -> float:
        """Calculate build system security score"""
        score = 100.0

        for issue in issues:
            severity = issue.get("severity", SecurityLevel.LOW)
            if severity == SecurityLevel.CRITICAL:
                score -= 40.0
            elif severity == SecurityLevel.HIGH:
                score -= 25.0
            elif severity == SecurityLevel.MEDIUM:
                score -= 15.0
            elif severity == SecurityLevel.LOW:
                score -= 5.0

        return max(0.0, score)

    def _generate_build_recommendations(
        self, analysis_result: Dict[str, Any]
    ) -> List[str]:
        """Generate build system security recommendations"""
        recommendations = []

        if analysis_result["security_score"] < 50:
            recommendations.append(
                "Build system security score is very low. Review all build files immediately."
            )

        # Check for specific issues
        if any(
            issue["type"] == "hardcoded_secrets"
            for issue in analysis_result["security_issues"]
        ):
            recommendations.append(
                "Remove hardcoded secrets from build files. Use environment variables or secure secret management."
            )

        if any(
            issue["type"] == "unsafe_commands"
            for issue in analysis_result["security_issues"]
        ):
            recommendations.append(
                "Review and secure unsafe commands in build files. Use least privilege principles."
            )

        if any(
            issue["type"] == "insecure_urls"
            for issue in analysis_result["security_issues"]
        ):
            recommendations.append("Replace insecure URLs with HTTPS equivalents.")

        if not recommendations:
            recommendations.append(
                "No immediate build system security issues found. Continue monitoring build files."
            )

        return recommendations


class PackageVerifier:
    """Verify package integrity and signatures"""

    def __init__(self, config: SupplyChainConfig):
        self.config = config

    def verify_package(self, package_path: str) -> Dict[str, Any]:
        """Verify package integrity and signatures"""
        verification_result = {
            "package_path": package_path,
            "checksum_verified": False,
            "signature_verified": False,
            "security_score": 0.0,
            "issues": [],
        }

        try:
            # Check if file exists
            if not os.path.exists(package_path):
                verification_result["issues"].append("Package file not found")
                return verification_result

            # Verify checksum if available
            if self.config.checksum_verification:
                checksum_verified = self._verify_checksum(package_path)
                verification_result["checksum_verified"] = checksum_verified
                if checksum_verified:
                    verification_result["security_score"] += 50.0
                else:
                    verification_result["issues"].append("Checksum verification failed")

            # Verify GPG signature if available
            if self.config.gpg_verification:
                signature_verified = self._verify_gpg_signature(package_path)
                verification_result["signature_verified"] = signature_verified
                if signature_verified:
                    verification_result["security_score"] += 50.0
                else:
                    verification_result["issues"].append(
                        "GPG signature verification failed"
                    )

            # If no verification methods available, give partial credit
            if (
                not self.config.checksum_verification
                and not self.config.gpg_verification
            ):
                verification_result["security_score"] = 25.0
                verification_result["issues"].append(
                    "No verification methods configured"
                )

        except Exception as e:
            logger.error(f"Package verification failed: {e}")
            verification_result["issues"].append(f"Verification error: {str(e)}")

        return verification_result

    def _verify_checksum(self, package_path: str) -> bool:
        """Verify package checksum"""
        try:
            # Look for checksum file
            checksum_file = package_path + ".sha256"
            if os.path.exists(checksum_file):
                with open(checksum_file, "r") as f:
                    expected_checksum = f.read().strip().split()[0]

                # Calculate actual checksum
                actual_checksum = self._calculate_sha256(package_path)

                return expected_checksum == actual_checksum

            return False

        except Exception as e:
            logger.warning(f"Checksum verification failed: {e}")
            return False

    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    def _verify_gpg_signature(self, package_path: str) -> bool:
        """Verify GPG signature of package"""
        try:
            # Look for signature file
            signature_file = package_path + ".asc"
            if not os.path.exists(signature_file):
                return False

            # Verify signature using gpg command
            result = subprocess.run(
                ["gpg", "--verify", signature_file, package_path],
                capture_output=True,
                text=True,
            )

            return result.returncode == 0

        except Exception as e:
            logger.warning(f"GPG signature verification failed: {e}")
            return False


class SupplyChainSecurityManager:
    """Main supply chain security manager"""

    def __init__(self, config: SupplyChainConfig):
        self.config = config
        self.dependency_scanner = AdvancedDependencyScanner(config)
        self.build_analyzer = BuildSystemAnalyzer(config)
        self.package_verifier = PackageVerifier(config)

    def comprehensive_scan(self, project_path: str = ".") -> Dict[str, Any]:
        """Perform comprehensive supply chain security scan"""
        scan_result = {
            "timestamp": time.time(),
            "project_path": project_path,
            "dependency_scan": {},
            "build_analysis": {},
            "overall_security_score": 0.0,
            "critical_issues": [],
            "recommendations": [],
        }

        try:
            # Scan dependencies
            if self.config.enable_dependency_scanning:
                scan_result["dependency_scan"] = (
                    self.dependency_scanner.comprehensive_scan()
                )

            # Analyze build system
            if self.config.enable_build_analysis:
                scan_result["build_analysis"] = (
                    self.build_analyzer.analyze_build_system(project_path)
                )

            # Calculate overall security score
            scores = []
            if scan_result["dependency_scan"]:
                scores.append(
                    scan_result["dependency_scan"].get("overall_security_score", 0)
                )
            if scan_result["build_analysis"]:
                scores.append(
                    scan_result["build_analysis"].get("overall_security_score", 0)
                )

            if scores:
                scan_result["overall_security_score"] = sum(scores) / len(scores)

            # Identify critical issues
            scan_result["critical_issues"] = self._identify_critical_issues(scan_result)

            # Generate overall recommendations
            scan_result["recommendations"] = self._generate_overall_recommendations(
                scan_result
            )

        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            scan_result["error"] = str(e)

        return scan_result

    def _identify_critical_issues(self, scan_result: Dict[str, Any]) -> List[str]:
        """Identify critical security issues"""
        critical_issues = []

        # Check dependency vulnerabilities
        if "dependency_scan" in scan_result:
            dep_scan = scan_result["dependency_scan"]
            if "vulnerable_dependencies" in dep_scan:
                critical_vulns = [
                    f"Found {dep_scan['vulnerable_dependencies']} vulnerable dependencies"
                ]
                if critical_vulns:
                    critical_issues.append(
                        f"Found {dep_scan['vulnerable_dependencies']} vulnerable dependencies"
                    )

        # Check build system issues
        if "build_analysis" in scan_result:
            build_analysis = scan_result["build_analysis"]
            if "critical_issues" in build_analysis:
                critical_build_issues = [i for i in build_analysis["critical_issues"]]
                if critical_build_issues:
                    critical_issues.append(
                        f"Found {len(critical_build_issues)} critical build system security issues"
                    )

        # Check overall security score
        if scan_result.get("overall_security_score", 100) < 50:
            critical_issues.append("Overall security score is critically low")

        return critical_issues

    def _generate_overall_recommendations(
        self, scan_result: Dict[str, Any]
    ) -> List[str]:
        """Generate overall security recommendations"""
        recommendations = []

        # Overall score recommendations
        overall_score = scan_result.get("overall_security_score", 100)
        if overall_score < 50:
            recommendations.append(
                "Immediate action required: Security score is critically low"
            )
        elif overall_score < 75:
            recommendations.append(
                "High priority: Address security issues to improve score"
            )
        elif overall_score < 90:
            recommendations.append(
                "Medium priority: Review and address remaining security issues"
            )
        else:
            recommendations.append(
                "Good security posture. Continue monitoring and maintenance."
            )

        # Add specific recommendations from scans
        if (
            "dependency_scan" in scan_result
            and "recommendations" in scan_result["dependency_scan"]
        ):
            recommendations.extend(scan_result["dependency_scan"]["recommendations"])

        if (
            "build_analysis" in scan_result
            and "recommendations" in scan_result["build_analysis"]
        ):
            recommendations.extend(scan_result["build_analysis"]["recommendations"])

        return recommendations


# Utility functions
def get_supply_chain_security_manager(
    config: SupplyChainConfig = None,
) -> SupplyChainSecurityManager:
    """Get supply chain security manager instance"""
    if config is None:
        config = SupplyChainConfig()
    return SupplyChainSecurityManager(config)


def scan_project_security(project_path: str = ".") -> Dict[str, Any]:
    """Quick function to scan project security"""
    config = SupplyChainConfig()
    manager = get_supply_chain_security_manager(config)
    return manager.comprehensive_scan(project_path)


def scan_dependencies(requirements_file: str = None) -> Dict[str, Any]:
    """Quick function to scan dependencies"""
    config = SupplyChainConfig()
    manager = get_supply_chain_security_manager(config)
    return manager.dependency_scanner.comprehensive_scan()


def analyze_build_system(project_path: str = ".") -> Dict[str, Any]:
    """Quick function to analyze build system"""
    config = SupplyChainConfig()
    manager = get_supply_chain_security_manager(config)
    return manager.build_analyzer.analyze_build_system(project_path)
