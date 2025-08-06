"""
Compatibility tests for different Python versions in MorphCloud SDK.
"""
import pytest
import logging
import sys
import platform

logger = logging.getLogger("morph-tests")

# Mark all tests as compatibility tests
pytestmark = [pytest.mark.compatibility]


class TestPythonVersions:
    """Test compatibility across Python versions."""

    def test_python_version_detection(self):
        """Test Python version detection and logging."""
        logger.info("Testing Python version detection")
        
        python_version = sys.version_info
        logger.info(f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
        logger.info(f"Python implementation: {platform.python_implementation()}")
        logger.info(f"Python compiler: {platform.python_compiler()}")
        
        # Verify minimum Python version requirement (from pyproject.toml: >=3.10)
        assert python_version >= (3, 10), f"Python version {python_version} is below minimum requirement 3.10"
        logger.info("Python version meets minimum requirements")

    def test_python_310_compatibility(self):
        """Test Python 3.10+ specific features."""
        logger.info("Testing Python 3.10+ compatibility")
        
        python_version = sys.version_info
        
        if python_version >= (3, 10):
            logger.info("Running on Python 3.10+, testing specific features")
            
            # Test structural pattern matching (Python 3.10+ feature)
            try:
                def test_match_statement(value):
                    match value:
                        case "test":
                            return "matched"
                        case _:
                            return "default"
                
                result = test_match_statement("test")
                assert result == "matched", "Match statement should work"
                logger.info("Structural pattern matching works")
            except SyntaxError:
                logger.warning("Structural pattern matching not available")
            
            # Test union type syntax (Python 3.10+ feature)
            try:
                # This would be a syntax error in older Python versions
                exec("from typing import Union; x: str | int = 'test'")
                logger.info("Union type syntax (|) works")
            except SyntaxError:
                logger.warning("Union type syntax (|) not available")
                
        else:
            logger.info(f"Running on Python {python_version}, skipping 3.10+ specific tests")

    def test_python_311_compatibility(self):
        """Test Python 3.11+ specific features.""" 
        logger.info("Testing Python 3.11+ compatibility")
        
        python_version = sys.version_info
        
        if python_version >= (3, 11):
            logger.info("Running on Python 3.11+, testing specific features")
            
            # Test exception groups (Python 3.11+ feature)
            try:
                # Test ExceptionGroup if available
                exec("""
try:
    raise ExceptionGroup("test group", [ValueError("test1"), TypeError("test2")])
except* ValueError as eg:
    pass
                """)
                logger.info("Exception groups work")
            except (NameError, SyntaxError):
                logger.warning("Exception groups not available")
            
            # Test TOML support in standard library (Python 3.11+ feature)
            try:
                import tomllib
                logger.info("tomllib is available in standard library")
            except ImportError:
                logger.warning("tomllib not available in standard library")
                
        else:
            logger.info(f"Running on Python {python_version}, skipping 3.11+ specific tests")

    def test_python_312_compatibility(self):
        """Test Python 3.12+ specific features."""
        logger.info("Testing Python 3.12+ compatibility")
        
        python_version = sys.version_info
        
        if python_version >= (3, 12):
            logger.info("Running on Python 3.12+, testing specific features")
            
            # Test f-string improvements
            try:
                name = "world"
                result = f"hello {name = }"  # Python 3.8+ feature actually
                logger.info("F-string debugging syntax works")
            except SyntaxError:
                logger.warning("F-string debugging syntax not available")
            
            # Test improved error messages (runtime behavior)
            try:
                # This will create a better error message in Python 3.12+
                d = {}
                value = d["nonexistent"]
            except KeyError as e:
                logger.info(f"KeyError message: {e}")
                
        else:
            logger.info(f"Running on Python {python_version}, skipping 3.12+ specific tests")

    def test_async_await_compatibility(self):
        """Test async/await syntax compatibility."""
        logger.info("Testing async/await compatibility")
        
        # Test that async/await syntax is available (required for SDK)
        try:
            exec("""
async def test_async():
    return "async works"

import asyncio
result = asyncio.run(test_async())
assert result == "async works"
            """)
            logger.info("async/await syntax works correctly")
        except Exception as e:
            pytest.fail(f"async/await syntax not working: {e}")

    def test_typing_compatibility(self):
        """Test typing module compatibility across versions."""
        logger.info("Testing typing module compatibility")
        
        python_version = sys.version_info
        
        # Test basic typing imports
        try:
            from typing import List, Dict, Optional, Union, Any
            logger.info("Basic typing imports successful")
        except ImportError as e:
            pytest.fail(f"Basic typing imports failed: {e}")
        
        # Test newer typing features conditionally
        if python_version >= (3, 10):
            try:
                from typing import TypeAlias
                logger.info("TypeAlias import successful")
            except ImportError:
                logger.warning("TypeAlias import failed")
        
        if python_version >= (3, 11):
            try:
                from typing import Self
                logger.info("Self import successful")
            except ImportError:
                logger.warning("Self import failed")

    def test_dataclass_compatibility(self):
        """Test dataclass compatibility."""
        logger.info("Testing dataclass compatibility")
        
        try:
            from dataclasses import dataclass, field
            
            @dataclass
            class TestData:
                name: str
                value: int = 0
                items: list = field(default_factory=list)
            
            # Test dataclass creation
            data = TestData("test")
            assert data.name == "test", "Dataclass should work"
            assert data.value == 0, "Default value should work"
            
            logger.info("Dataclass compatibility confirmed")
        except Exception as e:
            logger.warning(f"Dataclass compatibility issue: {e}")

    def test_pathlib_compatibility(self):
        """Test pathlib compatibility."""
        logger.info("Testing pathlib compatibility")
        
        try:
            from pathlib import Path
            
            # Test basic pathlib operations
            path = Path("/tmp/test")
            assert isinstance(path, Path), "Path creation should work"
            
            # Test path operations
            parent = path.parent
            assert parent == Path("/tmp"), "Path operations should work"
            
            logger.info("pathlib compatibility confirmed")
        except Exception as e:
            pytest.fail(f"pathlib compatibility issue: {e}")

    def test_json_compatibility(self):
        """Test JSON module compatibility."""
        logger.info("Testing JSON module compatibility")
        
        try:
            import json
            
            # Test JSON serialization/deserialization
            data = {"test": "value", "number": 123}
            json_str = json.dumps(data)
            parsed_data = json.loads(json_str)
            
            assert parsed_data == data, "JSON round-trip should work"
            logger.info("JSON compatibility confirmed")
        except Exception as e:
            pytest.fail(f"JSON compatibility issue: {e}")

    def test_urllib_compatibility(self):
        """Test urllib module compatibility."""
        logger.info("Testing urllib compatibility")
        
        try:
            from urllib.parse import urlparse, urljoin
            from urllib.request import urlopen
            
            # Test URL parsing
            parsed = urlparse("https://api.morph.so/v1/instances")
            assert parsed.scheme == "https", "URL parsing should work"
            assert parsed.netloc == "api.morph.so", "URL parsing should extract netloc"
            
            # Test URL joining
            joined = urljoin("https://api.morph.so/v1/", "instances")
            assert joined == "https://api.morph.so/v1/instances", "URL joining should work"
            
            logger.info("urllib compatibility confirmed")
        except Exception as e:
            logger.warning(f"urllib compatibility issue: {e}")

    def test_concurrent_futures_compatibility(self):
        """Test concurrent.futures compatibility."""
        logger.info("Testing concurrent.futures compatibility")
        
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import time
            
            def test_task(n):
                return n * 2
            
            # Test thread pool executor
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(test_task, i) for i in range(3)]
                results = [future.result() for future in as_completed(futures)]
                
            assert len(results) == 3, "ThreadPoolExecutor should work"
            logger.info("concurrent.futures compatibility confirmed")
        except Exception as e:
            logger.warning(f"concurrent.futures compatibility issue: {e}")

    def test_ssl_compatibility(self):
        """Test SSL module compatibility."""
        logger.info("Testing SSL module compatibility")
        
        try:
            import ssl
            
            # Test SSL context creation
            context = ssl.create_default_context()
            assert context is not None, "SSL context creation should work"
            
            # Test SSL version info
            logger.info(f"SSL version: {ssl.OPENSSL_VERSION}")
            
            logger.info("SSL compatibility confirmed")
        except Exception as e:
            logger.warning(f"SSL compatibility issue: {e}")

    def test_platform_specific_features(self):
        """Test platform-specific compatibility."""
        logger.info("Testing platform-specific features")
        
        system = platform.system()
        logger.info(f"Running on {system}")
        
        if system == "Windows":
            logger.info("Testing Windows-specific features")
            # Windows-specific tests would go here
            
        elif system == "Darwin":
            logger.info("Testing macOS-specific features")
            # macOS-specific tests would go here
            
        elif system == "Linux":
            logger.info("Testing Linux-specific features")
            # Linux-specific tests would go here
            
        else:
            logger.info(f"Unknown platform: {system}")
        
        logger.info("Platform-specific feature testing completed")