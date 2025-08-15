#!/usr/bin/env python3
"""
Advanced Security & Performance Demo

This script demonstrates the comprehensive security and performance features
implemented in the morph-python-sdk, including:

1. Container Security & Sandboxing
2. Zero-Trust Architecture
3. Advanced Performance Optimization
4. Supply Chain Security
5. Runtime Security
6. Network Security
7. Data Security

Usage:
    python advanced_security_demo.py [--demo-type TYPE] [--config-file PATH]
"""

import asyncio
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional

# Import all security and performance modules
from morphcloud.container_security import (
    ContainerSecurityConfig,
    SecurityLevel,
    IsolationType,
    get_container_security_manager,
)
from morphcloud.zero_trust import (
    ZeroTrustConfig,
    TrustLevel,
    AuthenticationMethod,
    get_zero_trust_manager,
)
from morphcloud.advanced_performance import (
    PerformanceConfig,
    GPUType,
    OptimizationLevel,
    get_advanced_performance_manager,
)
from morphcloud.supply_chain_security import SupplyChainConfig, get_supply_chain_manager
from morphcloud.runtime_security import (
    RuntimeSecurityConfig,
    get_runtime_security_manager,
)
from morphcloud.network_security import (
    NetworkSecurityConfig,
    get_network_security_manager,
)
from morphcloud.data_security import DataSecurityConfig, get_data_security_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class AdvancedSecurityDemo:
    """Comprehensive demonstration of advanced security and performance features"""

    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.configs = self._load_configurations()
        self.managers = {}

    def _load_configurations(self) -> Dict[str, Any]:
        """Load all security and performance configurations"""
        logger.info("Loading security and performance configurations...")

        # Container Security - Maximum security
        container_config = ContainerSecurityConfig(
            security_level=SecurityLevel.PARANOID,
            isolation_type=(IsolationType.MAXIMUM),
            enable_scanning=True,
            enable_runtime_protection=True,
            enable_resource_monitoring=True,
            allow_privileged=False,
            allow_host_network=False,
            scan_timeout=600,  # 10 minutes
            max_scan_retries=5,
        )

        # Zero-Trust - High security
        zero_trust_config = ZeroTrustConfig(
            trust_level=TrustLevel.HIGH,
            authentication_method=AuthenticationMethod.MTLS,
            enable_service_mesh=True,
            enable_api_gateway=True,
            enable_secret_management=True,
            jwt_expiry_hours=12,
        )

        # Performance - Optimized for production
        performance_config = PerformanceConfig(
            gpu_type=GPUType.CUDA,  # Will fallback to CPU if no GPU
            optimization_level=OptimizationLevel.MAXIMUM,
            enable_gpu_acceleration=True,
            enable_memory_mapping=True,
            enable_async_optimization=True,
            enable_coroutine_optimization=True,
            enable_distributed_computing=True,
            enable_caching_clusters=True,
            enable_queue_management=True,
            max_workers=16,
            max_processes=8,
            memory_mapping_threshold=1024 * 1024,  # 1MB
            gpu_memory_limit=(2 * 1024 * 1024 * 1024),  # 2GB
            async_buffer_size=16384,
            coroutine_batch_size=200,
        )

        # Supply Chain - Maximum security
        supply_chain_config = SupplyChainConfig(
            security_level="critical",
            enable_dependency_scanning=True,
            enable_build_analysis=True,
            enable_package_verification=True,
            enable_typosquatting_detection=True,
            enable_license_checking=True,
            checksum_verification=True,
            gpg_verification=True,
            enable_ci_cd_analysis=True,
            enable_credential_scanning=True,
            enable_unsafe_command_detection=True,
        )

        # Runtime Security - High security
        runtime_security_config = RuntimeSecurityConfig(
            security_level="high",
            enable_memory_protection=True,
            enable_race_detection=True,
            enable_resource_monitoring=True,
            enable_buffer_overflow_detection=True,
            enable_memory_leak_detection=True,
            enable_thread_safety_analysis=True,
            enable_dos_protection=True,
            memory_threshold_mb=2048,  # 2GB
            cpu_threshold_percent=85.0,
            file_descriptor_limit=2000,
            thread_limit=200,
            stack_size_limit_mb=16,
            heap_size_limit_mb=1024,
            monitoring_interval=0.5,  # 500ms
            alert_threshold=3,
        )

        # Network Security - High security
        network_security_config = NetworkSecurityConfig(
            security_level="high",
            enable_protocol_analysis=True,
            enable_tls_analysis=True,
            enable_network_monitoring=True,
            enable_intrusion_detection=True,
            enable_traffic_analysis=True,
            enable_firewall_rules=True,
            enable_network_segmentation=True,
            monitoring_interval=1.0,
            alert_threshold=5,
            max_connections_per_ip=100,
            suspicious_patterns=[
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
                r"(<script|javascript:|vbscript:|onload=|onerror=)",
                r"(\.\.\/|\.\.\\)",
                r"(\b(cmd|powershell|bash|sh|exec|system)\b)",
            ],
        )

        # Data Security - High security
        data_security_config = DataSecurityConfig(
            security_level="high",
            enable_encryption=True,
            enable_data_sanitization=True,
            enable_audit_logging=True,
            enable_data_classification=True,
            enable_data_masking=True,
            audit_log_path="logs/data_security.log",
            max_log_size_mb=200,
            log_retention_days=730,  # 2 years
        )

        return {
            "container": container_config,
            "zero_trust": zero_trust_config,
            "performance": performance_config,
            "supply_chain": supply_chain_config,
            "runtime": runtime_security_config,
            "network": network_security_config,
            "data": data_security_config,
        }

    async def initialize_managers(self):
        """Initialize all security and performance managers"""
        logger.info("Initializing security and performance managers...")

        try:
            # Initialize container security manager
            self.managers["container"] = get_container_security_manager(
                self.configs["container"]
            )
            logger.info("✓ Container security manager initialized")

            # Initialize zero-trust manager
            self.managers["zero_trust"] = get_zero_trust_manager(
                self.configs["zero_trust"]
            )
            logger.info("✓ Zero-trust manager initialized")

            # Initialize performance manager
            self.managers["performance"] = get_advanced_performance_manager(
                self.configs["performance"]
            )
            logger.info("✓ Performance manager initialized")

            # Initialize supply chain manager
            self.managers["supply_chain"] = get_supply_chain_manager(
                self.configs["supply_chain"]
            )
            logger.info("✓ Supply chain manager initialized")

            # Initialize runtime security manager
            self.managers["runtime"] = get_runtime_security_manager(
                self.configs["runtime"]
            )
            logger.info("✓ Runtime security manager initialized")

            # Initialize network security manager
            self.managers["network"] = get_network_security_manager(
                self.configs["network"]
            )
            logger.info("✓ Network security manager initialized")

            # Initialize data security manager
            self.managers["data"] = get_data_security_manager(self.configs["data"])
            logger.info("✓ Data security manager initialized")

        except Exception as e:
            logger.error(f"Failed to initialize managers: {e}")
            raise

    async def demo_container_security(self):
        """Demonstrate container security features"""
        logger.info("\n🔒 Demonstrating Container Security Features...")

        try:
            manager = self.managers["container"]

            # Scan a sample image for vulnerabilities
            logger.info("Scanning sample image for vulnerabilities...")
            scan_result = await manager.scanner.scan_image_async("python:3.9-slim")

            if "error" not in scan_result:
                logger.info(f"✓ Image scan completed")
                logger.info(
                    f"  Security score: {scan_result.get('security_score', 'N/A')}"
                )
                logger.info(
                    f"  Vulnerabilities found: {scan_result.get('vulnerability_count', 0)}"
                )

                if scan_result.get("recommendations"):
                    logger.info("  Recommendations:")
                    for rec in scan_result["recommendations"][:3]:  # Show first 3
                        logger.info(f"    - {rec}")
            else:
                logger.warning(f"Image scan failed: {scan_result['error']}")

            # Create a secure container
            logger.info("Creating secure container...")
            container_result = await manager.secure_container(
                "python:3.9-slim", container_name="demo-secure-container"
            )

            if "error" not in container_result:
                logger.info(
                    f"✓ Secure container created: {container_result['container_id']}"
                )

                # Get container security status
                status = manager.get_container_security_status(
                    container_result["container_id"]
                )
                logger.info(
                    f"  Security level: {status.get('security_config', {}).get('security_level')}"
                )
                logger.info(
                    f"  Isolation type: {status.get('security_config', {}).get('isolation_type')}"
                )

                # Clean up
                stop_result = manager.stop_container(container_result["container_id"])
                if "error" not in stop_result:
                    logger.info("✓ Container stopped and cleaned up")
            else:
                logger.warning(
                    f"Container creation failed: {container_result['error']}"
                )

        except Exception as e:
            logger.error(f"Container security demo failed: {e}")

    async def demo_zero_trust(self):
        """Demonstrate zero-trust architecture features"""
        logger.info("\n🛡️ Demonstrating Zero-Trust Architecture...")

        try:
            manager = self.managers["zero_trust"]

            # Register a demo service
            logger.info("Registering demo service in zero-trust system...")
            service_result = manager.register_service(
                service_id="demo-api-service",
                service_name="Demo API Service",
                trust_level=TrustLevel.HIGH,
                capabilities=["read", "write", "admin"],
            )

            if service_result.get("success"):
                logger.info("✓ Service registered successfully")
                logger.info(
                    f"  API Key: {service_result.get('api_key', 'N/A')[:20]}..."
                )
                logger.info(
                    f"  JWT Token: {service_result.get('jwt_token', 'N/A')[:20]}..."
                )

                # Get service certificates
                certs = manager.get_service_certificates("demo-api-service")
                if certs:
                    logger.info("✓ Service certificates generated")
                    logger.info(
                        f"  Certificate valid until: {certs.get('expires_at', 'N/A')}"
                    )
            else:
                logger.warning(
                    f"Service registration failed: {service_result.get('error')}"
                )

            # Demonstrate API gateway authentication
            logger.info("Testing API gateway authentication...")
            request_headers = {
                "X-API-Key": service_result.get("api_key", ""),
                "Authorization": f"Bearer {service_result.get('jwt_token', '')}",
            }

            auth_result = manager.authenticate_request(
                request_headers, "/api/v1/instances"
            )

            if auth_result.get("authenticated"):
                logger.info("✓ Request authenticated successfully")
                logger.info(f"  Trust level: {auth_result.get('trust_level')}")
                logger.info(f"  Capabilities: {auth_result.get('capabilities', [])}")
            else:
                logger.warning(f"Authentication failed: {auth_result.get('error')}")

        except Exception as e:
            logger.error(f"Zero-trust demo failed: {e}")

    async def demo_performance_optimization(self):
        """Demonstrate advanced performance optimization features"""
        logger.info("\n⚡ Demonstrating Performance Optimization Features...")

        try:
            manager = self.managers["performance"]

            # Test GPU acceleration
            logger.info("Testing GPU acceleration...")
            import numpy as np

            # Create test data
            test_data = np.random.random((1000, 1000)).astype(np.float32)
            logger.info(f"  Test data shape: {test_data.shape}")

            # Test computation optimization
            result = manager.optimize_computation(
                test_data, "matrix_multiply", matrix_b=test_data.T
            )
            logger.info(f"✓ Computation optimized")
            logger.info(f"  Result shape: {result.shape}")

            # Test async operation optimization
            logger.info("Testing async operation optimization...")

            async def sample_coroutine():
                await asyncio.sleep(0.1)
                return "async operation completed"

            async_result = await manager.optimize_async_operation(
                sample_coroutine, priority=1, timeout=5.0
            )
            logger.info(f"✓ Async operation optimized: {async_result}")

            # Test file operations optimization
            logger.info("Testing file operations optimization...")
            test_file = Path("test_performance_data.bin")
            test_data_bytes = test_data.tobytes()

            # Write test file
            with open(test_file, "wb") as f:
                f.write(test_data_bytes)

            # Test optimized read
            read_result = manager.optimize_file_operations(str(test_file), "read")

            if read_result:
                logger.info(f"✓ File operations optimized")
                logger.info(f"  Read {len(read_result)} bytes")

            # Clean up
            test_file.unlink(missing_ok=True)

            # Get performance summary
            summary = manager.get_performance_summary()
            logger.info("Performance Summary:")
            logger.info(f"  Total operations: {summary.get('total_operations', 0)}")
            logger.info(
                f"  Average response time: {summary.get('avg_response_time', 0):.3f}s"
            )
            logger.info(f"  Cache hit rate: {summary.get('cache_hit_rate', 0):.1f}%")

        except Exception as e:
            logger.error(f"Performance optimization demo failed: {e}")

    async def demo_supply_chain_security(self):
        """Demonstrate supply chain security features"""
        logger.info("\n🔐 Demonstrating Supply Chain Security...")

        try:
            manager = self.managers["supply_chain"]

            # Scan current project dependencies
            logger.info("Scanning project dependencies for security issues...")
            scan_result = manager.scan_dependencies()

            if scan_result.get("success"):
                logger.info("✓ Dependency scan completed")
                logger.info(
                    f"  Dependencies scanned: {scan_result.get('total_dependencies', 0)}"
                )
                logger.info(
                    f"  Vulnerabilities found: {scan_result.get('vulnerability_count', 0)}"
                )
                logger.info(
                    f"  Security score: {scan_result.get('overall_security_score', 0):.1f}/100"
                )

                if scan_result.get("critical_issues"):
                    logger.warning("  Critical issues found:")
                    for issue in scan_result["critical_issues"][:3]:
                        logger.warning(f"    - {issue}")

                if scan_result.get("recommendations"):
                    logger.info("  Recommendations:")
                    for rec in scan_result["recommendations"][:3]:
                        logger.info(f"    - {rec}")
            else:
                logger.warning(f"Dependency scan failed: {scan_result.get('error')}")

            # Test typosquatting detection
            logger.info("Testing typosquatting detection...")
            typosquatting_result = manager.detect_typosquatting(
                ["numpy", "pandas", "requests", "flask", "django"]
            )

            if typosquatting_result.get("suspicious_packages"):
                logger.warning("  Suspicious packages detected:")
                for pkg in typosquatting_result["suspicious_packages"][:3]:
                    logger.warning(
                        f"    - {pkg['name']} (similarity: {pkg['similarity']:.1f})"
                    )
            else:
                logger.info("✓ No typosquatting detected")

            # Test package verification
            logger.info("Testing package verification...")
            verification_result = manager.verify_package_integrity("numpy")

            if verification_result.get("verified"):
                logger.info("✓ Package verification completed")
                logger.info(
                    f"  Checksum verified: {verification_result.get('checksum_verified')}"
                )
                logger.info(
                    f"  Signature verified: {verification_result.get('signature_verified')}"
                )
            else:
                logger.warning(
                    f"Package verification failed: {verification_result.get('error')}"
                )

        except Exception as e:
            logger.error(f"Supply chain security demo failed: {e}")

    async def demo_runtime_security(self):
        """Demonstrate runtime security features"""
        logger.info("\n🔄 Demonstrating Runtime Security...")

        try:
            manager = self.managers["runtime"]

            # Start runtime protection
            logger.info("Starting runtime security protection...")
            manager.start_protection()
            logger.info("✓ Runtime protection started")

            # Test memory protection
            logger.info("Testing memory protection...")
            memory_status = manager.memory_protector.get_memory_status()
            logger.info(f"✓ Memory protection active")
            logger.info(
                f"  Current usage: {memory_status.get('current_usage_mb', 0):.1f} MB"
            )
            logger.info(f"  Peak usage: {memory_status.get('peak_usage_mb', 0):.1f} MB")
            logger.info(
                f"  Memory violations: {len(memory_status.get('violations', []))}"
            )

            # Test race condition detection
            logger.info("Testing race condition detection...")
            race_status = manager.race_detector.get_race_condition_status()
            logger.info(f"✓ Race condition detection active")
            logger.info(
                f"  Threads monitored: {race_status.get('threads_monitored', 0)}"
            )
            logger.info(
                f"  Race conditions detected: {len(race_status.get('race_conditions', []))}"
            )

            # Test resource monitoring
            logger.info("Testing resource monitoring...")
            resource_status = manager.resource_monitor.get_resource_status()
            logger.info(f"✓ Resource monitoring active")
            logger.info(
                f"  CPU usage: {resource_status.get('cpu_usage_percent', 0):.1f}%"
            )
            logger.info(
                f"  Memory usage: {resource_status.get('memory_usage_mb', 0):.1f} MB"
            )
            logger.info(
                f"  File descriptors: {resource_status.get('file_descriptors', 0)}"
            )

            # Test DoS protection
            logger.info("Testing DoS protection...")
            dos_status = manager.dos_protector.get_dos_status()
            logger.info(f"✓ DoS protection active")
            logger.info(f"  Attack attempts: {dos_status.get('attack_attempts', 0)}")
            logger.info(f"  Blocked IPs: {len(dos_status.get('blocked_ips', []))}")

            # Get overall security status
            security_status = manager.get_security_status()
            logger.info("Runtime Security Status:")
            logger.info(
                f"  Overall score: {security_status.get('overall_score', 0):.1f}/100"
            )
            logger.info(
                f"  Active threats: {len(security_status.get('active_threats', []))}"
            )
            logger.info(
                f"  Mitigation actions: {len(security_status.get('mitigation_actions', []))}"
            )

            # Stop protection
            manager.stop_protection()
            logger.info("✓ Runtime protection stopped")

        except Exception as e:
            logger.error(f"Runtime security demo failed: {e}")

    async def demo_network_security(self):
        """Demonstrate network security features"""
        logger.info("\n🌐 Demonstrating Network Security...")

        try:
            manager = self.managers["network"]

            # Start network monitoring
            logger.info("Starting network security monitoring...")
            manager.start_monitoring()
            logger.info("✓ Network monitoring started")

            # Test protocol analysis
            logger.info("Testing protocol vulnerability analysis...")
            protocol_result = manager.analyze_protocol_vulnerabilities()
            logger.info(f"✓ Protocol analysis completed")
            logger.info(
                f"  Protocols analyzed: {len(protocol_result.get('protocols', []))}"
            )
            logger.info(
                f"  Vulnerabilities found: {len(protocol_result.get('vulnerabilities', []))}"
            )

            # Test TLS configuration analysis
            logger.info("Testing TLS configuration analysis...")
            tls_result = manager.analyze_tls_configuration("https://api.morphcloud.com")
            logger.info(f"✓ TLS analysis completed")
            logger.info(f"  TLS version: {tls_result.get('tls_version', 'N/A')}")
            logger.info(f"  Cipher suite: {tls_result.get('cipher_suite', 'N/A')}")
            logger.info(
                f"  Certificate valid: {tls_result.get('certificate_valid', False)}"
            )

            # Test network traffic analysis
            logger.info("Testing network traffic analysis...")
            traffic_result = manager.analyze_network_traffic()
            logger.info(f"✓ Traffic analysis completed")
            logger.info(
                f"  Connections monitored: {traffic_result.get('connections_monitored', 0)}"
            )
            logger.info(
                f"  Suspicious patterns: {len(traffic_result.get('suspicious_patterns', []))}"
            )

            # Test firewall rules
            logger.info("Testing firewall rules...")
            firewall_result = manager.get_firewall_status()
            logger.info(f"✓ Firewall status retrieved")
            logger.info(
                f"  Rules active: {len(firewall_result.get('active_rules', []))}"
            )
            logger.info(f"  Blocked IPs: {len(firewall_result.get('blocked_ips', []))}")

            # Get network security summary
            summary = manager.get_security_summary()
            logger.info("Network Security Summary:")
            logger.info(f"  Overall score: {summary.get('overall_score', 0):.1f}/100")
            logger.info(f"  Threats detected: {len(summary.get('threats', []))}")
            logger.info(
                f"  Network segments: {len(summary.get('network_segments', []))}"
            )

            # Stop monitoring
            manager.stop_monitoring()
            logger.info("✓ Network monitoring stopped")

        except Exception as e:
            logger.error(f"Network security demo failed: {e}")

    async def demo_data_security(self):
        """Demonstrate data security features"""
        logger.info("\n📊 Demonstrating Data Security...")

        try:
            manager = self.managers["data"]

            # Start data protection
            logger.info("Starting data security protection...")
            manager.start_protection()
            logger.info("✓ Data protection started")

            # Test data leakage detection
            logger.info("Testing data leakage detection...")
            test_data = "User email: john.doe@example.com, SSN: 123-45-6789"
            leakage_result = manager.scan_for_leakage(test_data, "test_data")

            if leakage_result.get("leakage_detected"):
                logger.warning("  Data leakage detected:")
                for leak in leakage_result.get("leakage_details", []):
                    logger.warning(f"    - {leak['type']}: {leak['description']}")
            else:
                logger.info("✓ No data leakage detected")

            # Test data encryption
            logger.info("Testing data encryption...")
            sensitive_data = "super-secret-password-123"
            encryption_result = manager.encrypt_data(sensitive_data)

            if encryption_result.get("success"):
                logger.info("✓ Data encrypted successfully")
                logger.info(
                    f"  Encryption type: {encryption_result.get('encryption_type')}"
                )
                logger.info(f"  Key ID: {encryption_result.get('key_id')}")

                # Test decryption
                decryption_result = manager.decrypt_data(encryption_result)
                if decryption_result == sensitive_data:
                    logger.info("✓ Data decrypted successfully")
                else:
                    logger.warning("Data decryption failed")
            else:
                logger.warning(
                    f"Data encryption failed: {encryption_result.get('error')}"
                )

            # Test data sanitization
            logger.info("Testing data sanitization...")
            malicious_input = "<script>alert('xss')</script>"
            sanitization_result = manager.sanitize_input(malicious_input, "html")

            if sanitization_result.get("sanitized"):
                logger.info("✓ Data sanitized successfully")
                logger.info(f"  Original: {malicious_input}")
                logger.info(f"  Sanitized: {sanitization_result.get('sanitized_data')}")
            else:
                logger.warning(
                    f"Data sanitization failed: {sanitization_result.get('error')}"
                )

            # Test file upload validation
            logger.info("Testing file upload validation...")
            test_file = Path("test_upload.txt")
            test_file.write_text("This is a test file for upload validation")

            validation_result = manager.validate_file_upload(
                str(test_file), [".txt", ".pdf", ".doc"]
            )

            if validation_result.get("valid"):
                logger.info("✓ File upload validation passed")
                logger.info(f"  File type: {validation_result.get('file_type')}")
                logger.info(
                    f"  File size: {validation_result.get('file_size_mb', 0):.3f} MB"
                )
            else:
                logger.warning(
                    f"File upload validation failed: {validation_result.get('error')}"
                )

            # Clean up
            test_file.unlink(missing_ok=True)

            # Get data security summary
            summary = manager.get_security_status()
            logger.info("Data Security Summary:")
            logger.info(f"  Overall score: {summary.get('overall_score', 0):.1f}/100")
            logger.info(f"  Events recorded: {len(summary.get('security_events', []))}")
            logger.info(f"  Encryption keys: {summary.get('encryption_keys_count', 0)}")

            # Stop protection
            manager.stop_protection()
            logger.info("✓ Data protection stopped")

        except Exception as e:
            logger.error(f"Data security demo failed: {e}")

    async def run_comprehensive_demo(self):
        """Run all security and performance demonstrations"""
        logger.info("🚀 Starting Comprehensive Security & Performance Demo")
        logger.info("=" * 60)

        try:
            # Initialize all managers
            await self.initialize_managers()

            # Run all demos
            await self.demo_container_security()
            await self.demo_zero_trust()
            await self.demo_performance_optimization()
            await self.demo_supply_chain_security()
            await self.demo_runtime_security()
            await self.demo_network_security()
            await self.demo_data_security()

            logger.info("\n" + "=" * 60)
            logger.info("🎉 Comprehensive Demo Completed Successfully!")
            logger.info("All advanced security and performance features demonstrated.")

        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
        finally:
            # Cleanup
            await self.cleanup()

    async def cleanup(self):
        """Clean up resources"""
        logger.info("\n🧹 Cleaning up resources...")

        try:
            # Stop all managers
            for name, manager in self.managers.items():
                if hasattr(manager, "cleanup"):
                    manager.cleanup()
                elif hasattr(manager, "stop_protection"):
                    manager.stop_protection()
                elif hasattr(manager, "stop_monitoring"):
                    manager.stop_monitoring()
                logger.info(f"✓ {name} manager cleaned up")

            logger.info("✓ All resources cleaned up")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Advanced Security & Performance Demo")
    parser.add_argument(
        "--demo-type",
        choices=[
            "comprehensive",
            "container",
            "zero-trust",
            "performance",
            "supply-chain",
            "runtime",
            "network",
            "data",
        ],
        default="comprehensive",
        help="Type of demo to run",
    )
    parser.add_argument("--config-file", type=str, help="Path to configuration file")

    args = parser.parse_args()

    try:
        demo = AdvancedSecurityDemo(args.config_file)

        if args.demo_type == "comprehensive":
            await demo.run_comprehensive_demo()
        else:
            # Run specific demo
            await demo.initialize_managers()

            if args.demo_type == "container":
                await demo.demo_container_security()
            elif args.demo_type == "zero-trust":
                await demo.demo_zero_trust()
            elif args.demo_type == "performance":
                await demo.demo_performance_optimization()
            elif args.demo_type == "supply-chain":
                await demo.demo_supply_chain_security()
            elif args.demo_type == "runtime":
                await demo.demo_runtime_security()
            elif args.demo_type == "network":
                await demo.demo_network_security()
            elif args.demo_type == "data":
                await demo.demo_data_security()

            await demo.cleanup()

    except KeyboardInterrupt:
        logger.info("\n⚠️ Demo interrupted by user")
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
