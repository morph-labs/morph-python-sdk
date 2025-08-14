#!/usr/bin/env python3
"""
Red Team Testing Demo

This demo showcases the comprehensive red team testing capabilities including:
- API security testing and fuzzing
- Social engineering simulation
- APT simulation and lateral movement testing
- Command & control detection
- Supply chain security testing
"""

import asyncio
import json
import time
import logging
from typing import Dict, Any, List
from pathlib import Path

# Import our red team modules
from morphcloud.red_team_testing import (
    RedTeamConfig,
    run_red_team_tests,
)
from morphcloud.command_control_detection import (
    C2DetectionConfig,
    start_c2_monitoring,
    get_threat_summary,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class RedTeamDemo:
    """Comprehensive red team testing demonstration"""

    def __init__(self):
        self.config = self._create_demo_config()
        self.test_runner = None
        self.c2_engine = None
        self.demo_results = {}

    def _create_demo_config(self) -> RedTeamConfig:
        """Create configuration for the demo"""
        return RedTeamConfig(
            enable_api_fuzzing=True,
            enable_social_engineering=True,
            enable_apt_simulation=True,
            enable_supply_chain=True,
            enable_physical_security=False,  # Disabled for demo safety
            enable_lateral_movement=True,
            enable_data_exfiltration=True,
            enable_command_control=True,
            # API Testing
            api_fuzz_iterations=100,  # Reduced for demo
            api_fuzz_timeout=10.0,
            api_rate_limit_bypass=True,
            # Social Engineering
            phishing_simulation=True,
            credential_stuffing=True,
            social_media_recon=True,
            # APT Simulation
            lateral_movement_depth=2,  # Reduced for demo
            privilege_escalation=True,
            persistence_mechanisms=True,
            # Supply Chain
            dependency_injection=True,
            build_pipeline_compromise=True,
            package_registry_poisoning=True,
            # Reporting
            generate_report=True,
            report_format="json",
            include_evidence=True,
            anonymize_data=True,
        )

    async def run_comprehensive_demo(self) -> Dict[str, Any]:
        """Run the complete red team testing demonstration"""
        logger.info("🚀 Starting Comprehensive Red Team Testing Demo")

        try:
            # Phase 1: API Security Testing
            await self._demo_api_security()

            # Phase 2: Social Engineering Testing
            await self._demo_social_engineering()

            # Phase 3: APT Simulation
            await self._demo_apt_simulation()

            # Phase 4: Supply Chain Security
            await self._demo_supply_chain_security()

            # Phase 5: Command & Control Detection
            await self._demo_c2_detection()

            # Phase 6: Generate Final Report
            final_report = self._generate_final_report()

            logger.info("✅ Red Team Testing Demo Completed Successfully")
            return final_report

        except Exception as e:
            logger.error(f"❌ Demo failed: {e}")
            return {"error": str(e), "status": "failed"}

    async def _demo_api_security(self):
        """Demonstrate API security testing capabilities"""
        logger.info("🔒 Phase 1: API Security Testing")

        # Define test targets
        api_targets = {
            "api_endpoints": [
                {
                    "url": "https://httpbin.org/get",
                    "method": "GET",
                    "description": "Test GET endpoint",
                },
                {
                    "url": "https://httpbin.org/post",
                    "method": "POST",
                    "data": {"test": "data"},
                    "description": "Test POST endpoint",
                },
                {
                    "url": "https://httpbin.org/status/500",
                    "method": "GET",
                    "description": "Test error handling",
                },
            ]
        }

        # Run API security tests
        logger.info("Running API fuzzing tests...")
        api_results = await run_red_team_tests(api_targets, self.config)

        self.demo_results["api_security"] = api_results

        # Display results
        self._display_api_results(api_results)

    async def _demo_social_engineering(self):
        """Demonstrate social engineering testing capabilities"""
        logger.info("🎭 Phase 2: Social Engineering Testing")

        # Define test targets
        social_targets = {
            "login_endpoints": [
                {
                    "url": "https://httpbin.org/status/401",  # Simulated login endpoint
                    "credentials_file": "demo_credentials.txt",
                    "description": "Test credential stuffing",
                }
            ]
        }

        # Create demo credentials file
        self._create_demo_credentials()

        # Run social engineering tests
        logger.info("Running social engineering tests...")
        social_results = await run_red_team_tests(social_targets, self.config)

        self.demo_results["social_engineering"] = social_results

        # Display results
        self._display_social_results(social_results)

    async def _demo_apt_simulation(self):
        """Demonstrate APT simulation capabilities"""
        logger.info("🕵️ Phase 3: APT Simulation Testing")

        # Define test targets
        apt_targets = {
            "target_systems": [
                "192.168.1.10",  # Simulated internal systems
                "192.168.1.20",
                "192.168.1.30",
            ]
        }

        # Run APT simulation tests
        logger.info("Running APT simulation tests...")
        apt_results = await run_red_team_tests(apt_targets, self.config)

        self.demo_results["apt_simulation"] = apt_results

        # Display results
        self._display_apt_results(apt_results)

    async def _demo_supply_chain_security(self):
        """Demonstrate supply chain security testing"""
        logger.info("🔗 Phase 4: Supply Chain Security Testing")

        # For demo purposes, we'll simulate supply chain tests
        # In a real environment, this would test actual dependencies

        supply_chain_results = {
            "test_summary": {
                "total_tests": 5,
                "passed": 4,
                "failed": 1,
                "blocked": 0,
                "errors": 0,
                "execution_time": 2.5,
                "security_score": 80.0,
            },
            "results_by_category": {
                "supply_chain": [
                    {
                        "test_name": "DEPENDENCY_SCANNING",
                        "status": "passed",
                        "description": "Dependency vulnerability scanning completed",
                    },
                    {
                        "test_name": "PACKAGE_VERIFICATION",
                        "status": "passed",
                        "description": "Package integrity verification completed",
                    },
                    {
                        "test_name": "BUILD_PIPELINE_ANALYSIS",
                        "status": "passed",
                        "description": "Build pipeline security analysis completed",
                    },
                    {
                        "test_name": "TYPOSQUATTING_DETECTION",
                        "status": "passed",
                        "description": "Typosquatting detection completed",
                    },
                    {
                        "test_name": "MALICIOUS_CODE_DETECTION",
                        "status": "failed",
                        "description": "Potential malicious code detected in dependency",
                    },
                ]
            },
            "critical_findings": [],
            "high_findings": [
                {
                    "test_name": "MALICIOUS_CODE_DETECTION",
                    "description": "Potential malicious code detected in dependency",
                    "recommendations": [
                        "Review suspicious dependency",
                        "Implement additional scanning",
                        "Update dependency if necessary",
                    ],
                }
            ],
            "recommendations": [
                "Implement additional dependency scanning",
                "Review suspicious dependencies",
                "Update security policies",
            ],
        }

        self.demo_results["supply_chain"] = supply_chain_results

        # Display results
        self._display_supply_chain_results(supply_chain_results)

    async def _demo_c2_detection(self):
        """Demonstrate command & control detection capabilities"""
        logger.info("🕸️ Phase 5: Command & Control Detection")

        # Create C2 detection configuration
        c2_config = C2DetectionConfig(
            enable_network_monitoring=True,
            enable_dns_monitoring=True,
            enable_http_monitoring=True,
            enable_behavioral_analysis=True,
            enable_process_monitoring=True,
            enable_file_monitoring=True,
            suspicious_domain_threshold=2,
            suspicious_ip_threshold=3,
            connection_frequency_threshold=5,
        )

        # Start C2 monitoring
        logger.info("Starting C2 detection monitoring...")
        self.c2_engine = start_c2_monitoring(c2_config)

        # Simulate some threat events
        await self._simulate_threat_events()

        # Wait a bit for processing
        await asyncio.sleep(3)

        # Get threat summary
        threat_summary = get_threat_summary(self.c2_engine)

        self.demo_results["c2_detection"] = threat_summary

        # Display results
        self._display_c2_results(threat_summary)

        # Stop monitoring
        if self.c2_engine:
            self.c2_engine.stop_monitoring()

    async def _simulate_threat_events(self):
        """Simulate threat events for demo purposes"""
        logger.info("Simulating threat events...")

        # Simulate suspicious network activity
        if self.c2_engine and self.c2_engine.pattern_detector:
            # Simulate suspicious DNS query
            threat_event = self.c2_engine.pattern_detector.analyze_dns_query(
                domain="malware.example.com", query_type="A", source_ip="192.168.1.100"
            )

            if threat_event:
                logger.info(f"Detected threat: {threat_event.description}")

            # Simulate suspicious HTTP request
            threat_event = self.c2_engine.pattern_detector.analyze_http_request(
                url="http://suspicious-site.xyz",
                method="POST",
                headers={"User-Agent": "Python-urllib/2.7"},
                payload="encoded_data_here",
                source_ip="192.168.1.100",
            )

            if threat_event:
                logger.info(f"Detected threat: {threat_event.description}")

        # Simulate behavioral threats
        if self.c2_engine and self.c2_engine.behavioral_analyzer:
            # Simulate suspicious process creation
            threat_event = self.c2_engine.behavioral_analyzer.analyze_process_creation(
                process_name="cmd.exe",
                process_id=1234,
                parent_process="iexplore.exe",
                command_line="cmd.exe /c powershell -enc encoded_command",
                source_ip="192.168.1.100",
            )

            if threat_event:
                logger.info(f"Detected threat: {threat_event.description}")

    def _create_demo_credentials(self):
        """Create demo credentials file for testing"""
        demo_credentials = [
            "admin:admin",
            "admin:password",
            "admin:123456",
            "user:user",
            "user:password",
            "test:test",
            "guest:guest",
            "root:root",
        ]

        credentials_file = Path("demo_credentials.txt")
        with open(credentials_file, "w") as f:
            for cred in demo_credentials:
                f.write(f"{cred}\n")

        logger.info("Created demo credentials file: %s", credentials_file)

    def _display_api_results(self, results: Dict[str, Any]):
        """Display API security test results"""
        summary = results.get("test_summary", {})

        print("\n" + "=" * 60)
        print("🔒 API SECURITY TESTING RESULTS")
        print("=" * 60)
        print(f"Total Tests: {summary.get('total_tests', 0)}")
        print(f"Passed: {summary.get('passed', 0)}")
        print(f"Failed: {summary.get('failed', 0)}")
        print(f"Security Score: {summary.get('security_score', 0):.1f}%")
        print(f"Execution Time: {summary.get('execution_time', 0):.2f}s")

        # Show critical findings
        critical_findings = results.get("critical_findings", [])
        if critical_findings:
            print(f"\n🚨 CRITICAL FINDINGS: {len(critical_findings)}")
            for finding in critical_findings[:3]:  # Show first 3
                print(
                    f"  • {finding.get('test_name', 'Unknown')}: {finding.get('description', 'No description')}"
                )

        # Show high findings
        high_findings = results.get("high_findings", [])
        if high_findings:
            print(f"\n⚠️ HIGH FINDINGS: {len(high_findings)}")
            for finding in high_findings[:3]:  # Show first 3
                print(
                    f"  • {finding.get('test_name', 'Unknown')}: {finding.get('description', 'No description')}"
                )

    def _display_social_results(self, results: Dict[str, Any]):
        """Display social engineering test results"""
        summary = results.get("test_summary", {})

        print("\n" + "=" * 60)
        print("🎭 SOCIAL ENGINEERING TESTING RESULTS")
        print("=" * 60)
        print(f"Total Tests: {summary.get('total_tests', 0)}")
        print(f"Passed: {summary.get('passed', 0)}")
        print(f"Failed: {summary.get('failed', 0)}")
        print(f"Security Score: {summary.get('security_score', 0):.1f}%")
        print(f"Execution Time: {summary.get('execution_time', 0):.2f}s")

        # Show findings
        high_findings = results.get("high_findings", [])
        if high_findings:
            print(f"\n⚠️ HIGH FINDINGS: {len(high_findings)}")
            for finding in high_findings[:3]:  # Show first 3
                print(
                    f"  • {finding.get('test_name', 'Unknown')}: {finding.get('description', 'No description')}"
                )

    def _display_apt_results(self, results: Dict[str, Any]):
        """Display APT simulation test results"""
        summary = results.get("test_summary", {})

        print("\n" + "=" * 60)
        print("🕵️ APT SIMULATION TESTING RESULTS")
        print("=" * 60)
        print(f"Total Tests: {summary.get('total_tests', 0)}")
        print(f"Passed: {summary.get('passed', 0)}")
        print(f"Failed: {summary.get('failed', 0)}")
        print(f"Security Score: {summary.get('security_score', 0):.1f}%")
        print(f"Execution Time: {summary.get('execution_time', 0):.2f}s")

        # Show findings
        critical_findings = results.get("critical_findings", [])
        if critical_findings:
            print(f"\n🚨 CRITICAL FINDINGS: {len(critical_findings)}")
            for finding in critical_findings[:3]:  # Show first 3
                print(
                    f"  • {finding.get('test_name', 'Unknown')}: {finding.get('description', 'No description')}"
                )

    def _display_supply_chain_results(self, results: Dict[str, Any]):
        """Display supply chain security test results"""
        summary = results.get("test_summary", {})

        print("\n" + "=" * 60)
        print("🔗 SUPPLY CHAIN SECURITY TESTING RESULTS")
        print("=" * 60)
        print(f"Total Tests: {summary.get('total_tests', 0)}")
        print(f"Passed: {summary.get('passed', 0)}")
        print(f"Failed: {summary.get('failed', 0)}")
        print(f"Security Score: {summary.get('security_score', 0):.1f}%")
        print(f"Execution Time: {summary.get('execution_time', 0):.2f}s")

        # Show findings
        high_findings = results.get("high_findings", [])
        if high_findings:
            print(f"\n⚠️ HIGH FINDINGS: {len(high_findings)}")
            for finding in high_findings[:3]:  # Show first 3
                print(
                    f"  • {finding.get('test_name', 'Unknown')}: {finding.get('description', 'No description')}"
                )

    def _display_c2_results(self, results: Dict[str, Any]):
        """Display C2 detection results"""
        print("\n" + "=" * 60)
        print("🕸️ COMMAND & CONTROL DETECTION RESULTS")
        print("=" * 60)
        print(f"Total Threats: {results.get('total_threats', 0)}")
        print(f"Critical Threats: {results.get('critical_threats', 0)}")
        print(f"High Threats: {results.get('high_threats', 0)}")
        print(f"Monitoring Active: {results.get('monitoring_active', False)}")
        print(f"Last Updated: {results.get('last_updated', 'Unknown')}")

        # Show threats by type
        threats_by_type = results.get("threats_by_type", {})
        if threats_by_type:
            print(f"\nThreats by Type:")
            for threat_type, threats in threats_by_type.items():
                print(f"  • {threat_type}: {len(threats)}")

    def _generate_final_report(self) -> Dict[str, Any]:
        """Generate comprehensive final report"""
        logger.info("📊 Generating Final Report")

        # Calculate overall statistics
        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_critical = 0
        total_high = 0

        for phase, results in self.demo_results.items():
            if isinstance(results, dict) and "test_summary" in results:
                summary = results["test_summary"]
                total_tests += summary.get("total_tests", 0)
                total_passed += summary.get("passed", 0)
                total_failed += summary.get("failed", 0)

            if isinstance(results, dict):
                total_critical += len(results.get("critical_findings", []))
                total_high += len(results.get("high_findings", []))

        # Calculate overall security score
        overall_score = 0.0
        if total_tests > 0:
            overall_score = (total_passed / total_tests) * 100

        # Generate recommendations
        recommendations = self._generate_overall_recommendations()

        final_report = {
            "demo_summary": {
                "total_phases": 5,
                "phases_completed": len(self.demo_results),
                "overall_status": "completed",
            },
            "test_summary": {
                "total_tests": total_tests,
                "total_passed": total_passed,
                "total_failed": total_failed,
                "overall_security_score": overall_score,
            },
            "threat_summary": {
                "total_critical_findings": total_critical,
                "total_high_findings": total_high,
                "overall_risk_level": self._calculate_risk_level(
                    total_critical, total_high
                ),
            },
            "phase_results": self.demo_results,
            "recommendations": recommendations,
            "timestamp": time.time(),
            "demo_duration": time.time() - getattr(self, "_start_time", time.time()),
        }

        # Display final summary
        self._display_final_summary(final_report)

        return final_report

    def _generate_overall_recommendations(self) -> List[str]:
        """Generate overall security recommendations"""
        recommendations = []

        # Analyze results and generate recommendations
        for phase, results in self.demo_results.items():
            if isinstance(results, dict):
                if results.get("critical_findings"):
                    recommendations.append(
                        f"Address critical findings in {phase.replace('_', ' ')} phase"
                    )

                if results.get("high_findings"):
                    recommendations.append(
                        f"Review high-severity findings in {phase.replace('_', ' ')} phase"
                    )

        # General recommendations
        if recommendations:
            recommendations.extend(
                [
                    "Implement comprehensive security monitoring",
                    "Conduct regular red team assessments",
                    "Update security policies based on findings",
                    "Provide security training for teams",
                    "Implement automated threat detection",
                ]
            )
        else:
            recommendations.append(
                "No critical issues found - maintain current security posture"
            )

        return recommendations

    def _calculate_risk_level(self, critical: int, high: int) -> str:
        """Calculate overall risk level"""
        if critical > 0:
            return "CRITICAL"
        elif high > 2:
            return "HIGH"
        elif high > 0:
            return "MEDIUM"
        else:
            return "LOW"

    def _display_final_summary(self, report: Dict[str, Any]):
        """Display final demo summary"""
        print("\n" + "=" * 80)
        print("🎯 RED TEAM TESTING DEMO - FINAL SUMMARY")
        print("=" * 80)

        # Demo summary
        demo_summary = report.get("demo_summary", {})
        print(
            f"Phases Completed: {demo_summary.get('phases_completed', 0)}/{demo_summary.get('total_phases', 0)}"
        )
        print(f"Overall Status: {demo_summary.get('overall_status', 'Unknown')}")

        # Test summary
        test_summary = report.get("test_summary", {})
        print(f"\nTotal Tests: {test_summary.get('total_tests', 0)}")
        print(f"Passed: {test_summary.get('total_passed', 0)}")
        print(f"Failed: {test_summary.get('total_failed', 0)}")
        print(
            f"Overall Security Score: {test_summary.get('overall_security_score', 0):.1f}%"
        )

        # Threat summary
        threat_summary = report.get("threat_summary", {})
        print(
            f"\nCritical Findings: {threat_summary.get('total_critical_findings', 0)}"
        )
        print(f"High Findings: {threat_summary.get('total_high_findings', 0)}")
        print(
            f"Overall Risk Level: {threat_summary.get('overall_risk_level', 'Unknown')}"
        )

        # Recommendations
        recommendations = report.get("recommendations", [])
        if recommendations:
            print(f"\n🔧 RECOMMENDATIONS:")
            for i, rec in enumerate(recommendations[:5], 1):  # Show first 5
                print(f"  {i}. {rec}")

        print("\n" + "=" * 80)
        print("✅ Red Team Testing Demo Completed Successfully!")
        print("=" * 80)


async def main():
    """Main demo function"""
    print("🚀 Starting Red Team Testing Demo")
    print("This demo will showcase comprehensive security testing capabilities")
    print("Please ensure you have proper authorization for security testing\n")

    # Create and run demo
    demo = RedTeamDemo()
    demo._start_time = time.time()  # Set start time for duration calculation

    try:
        results = await demo.run_comprehensive_demo()

        # Save results to file
        output_file = "red_team_demo_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n📁 Demo results saved to: {output_file}")

        return results

    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by user")
        return {"status": "interrupted"}
    except Exception as e:
        print(f"\n\n❌ Demo failed with error: {e}")
        return {"status": "failed", "error": str(e)}


if __name__ == "__main__":
    # Run the demo
    try:
        results = asyncio.run(main())
        if results and results.get("status") != "failed":
            print("\n🎉 Demo completed successfully!")
        else:
            print("\n💥 Demo encountered issues")
    except Exception as e:
        print(f"\n💥 Demo failed to start: {e}")
