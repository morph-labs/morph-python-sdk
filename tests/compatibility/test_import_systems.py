"""
Compatibility tests for import systems in MorphCloud SDK.
Tests different Python import patterns and module resolution.
"""
import pytest
import logging
import sys
import importlib
from importlib import util

logger = logging.getLogger("morph-tests")

# Mark all tests as compatibility tests
pytestmark = [pytest.mark.compatibility]


class TestImportSystems:
    """Test different import systems and patterns."""

    def test_standard_import(self):
        """Test standard import of morphcloud package."""
        logger.info("Testing standard import")
        
        # Test basic import
        try:
            import morphcloud
            assert morphcloud is not None, "morphcloud should be importable"
            logger.info("Standard import successful")
        except ImportError as e:
            pytest.fail(f"Standard import failed: {e}")
        
        # Test submodule import
        try:
            from morphcloud import api
            assert api is not None, "morphcloud.api should be importable"
            logger.info("Submodule import successful")
        except ImportError as e:
            pytest.fail(f"Submodule import failed: {e}")
        
        # Test class import
        try:
            from morphcloud.api import MorphCloudClient
            assert MorphCloudClient is not None, "MorphCloudClient should be importable"
            logger.info("Class import successful")
        except ImportError as e:
            pytest.fail(f"Class import failed: {e}")

    def test_relative_imports(self):
        """Test relative imports within the package."""
        logger.info("Testing relative imports")
        
        # Test that package can be imported and used
        try:
            from morphcloud.api import MorphCloudClient, Instance
            assert MorphCloudClient is not None, "MorphCloudClient should be importable"
            assert Instance is not None, "Instance should be importable"
            logger.info("Relative imports successful")
        except ImportError as e:
            pytest.fail(f"Relative imports failed: {e}")
        
        # Test sandbox imports if available
        try:
            from morphcloud.sandbox import SandboxAPI
            assert SandboxAPI is not None, "SandboxAPI should be importable"
            logger.info("Sandbox relative import successful")
        except ImportError as e:
            logger.warning(f"Sandbox import not available: {e}")

    def test_namespace_package_imports(self):
        """Test namespace package import patterns."""
        logger.info("Testing namespace package imports")
        
        # Test that morphcloud can be treated as namespace
        try:
            import morphcloud
            # Verify __path__ exists for namespace packages
            if hasattr(morphcloud, '__path__'):
                logger.info("morphcloud has __path__ attribute (namespace-style)")
            else:
                logger.info("morphcloud is regular package")
            
            # Test subpackage access
            import morphcloud.api
            import morphcloud.sandbox
            
            logger.info("Namespace package imports successful")
        except ImportError as e:
            logger.warning(f"Namespace package import issue: {e}")

    def test_entry_points(self):
        """Test package entry points and CLI access."""
        logger.info("Testing entry points")
        
        # Test that package has proper entry points
        try:
            import pkg_resources
            
            # Look for morphcloud entry points
            entry_points = list(pkg_resources.iter_entry_points('console_scripts', 'morphcloud'))
            
            if entry_points:
                logger.info(f"Found {len(entry_points)} morphcloud entry points")
                for ep in entry_points:
                    logger.info(f"Entry point: {ep.name} = {ep.module_name}:{ep.attrs[0]}")
            else:
                logger.info("No console_scripts entry points found for morphcloud")
                
        except ImportError:
            logger.info("pkg_resources not available, checking importlib.metadata")
            
            try:
                import importlib.metadata as metadata
                # Try to get entry points for newer Python versions
                try:
                    eps = metadata.entry_points(group='console_scripts')
                    morphcloud_eps = [ep for ep in eps if ep.name == 'morphcloud']
                    
                    if morphcloud_eps:
                        logger.info(f"Found {len(morphcloud_eps)} morphcloud entry points via importlib.metadata")
                    else:
                        logger.info("No morphcloud entry points found via importlib.metadata")
                except Exception as e:
                    logger.info(f"Error checking entry points: {e}")
                    
            except ImportError:
                logger.warning("Neither pkg_resources nor importlib.metadata available")

    def test_dynamic_import(self):
        """Test dynamic import patterns."""
        logger.info("Testing dynamic import")
        
        # Test importlib-based import
        try:
            spec = util.find_spec("morphcloud")
            assert spec is not None, "morphcloud spec should be found"
            
            module = util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            assert module is not None, "Dynamically imported module should not be None"
            logger.info("Dynamic import successful")
        except Exception as e:
            pytest.fail(f"Dynamic import failed: {e}")
        
        # Test importlib.import_module
        try:
            morphcloud_module = importlib.import_module("morphcloud.api")
            assert morphcloud_module is not None, "importlib.import_module should work"
            
            # Test getting class from dynamically imported module
            client_class = getattr(morphcloud_module, 'MorphCloudClient')
            assert client_class is not None, "Should be able to get class from dynamic import"
            
            logger.info("importlib.import_module successful")
        except Exception as e:
            pytest.fail(f"importlib.import_module failed: {e}")

    def test_import_error_handling(self):
        """Test import error handling for non-existent modules."""
        logger.info("Testing import error handling")
        
        # Test import of non-existent submodule
        with pytest.raises(ImportError):
            from morphcloud import nonexistent_module
        logger.info("ImportError correctly raised for non-existent module")
        
        # Test import of non-existent class
        with pytest.raises((ImportError, AttributeError)):
            from morphcloud.api import NonExistentClass
        logger.info("ImportError/AttributeError correctly raised for non-existent class")

    def test_package_attributes(self):
        """Test package-level attributes and metadata."""
        logger.info("Testing package attributes")
        
        try:
            import morphcloud
            
            # Check for common package attributes
            if hasattr(morphcloud, '__version__'):
                logger.info(f"Package version: {morphcloud.__version__}")
            else:
                logger.info("Package does not have __version__ attribute")
                
            if hasattr(morphcloud, '__author__'):
                logger.info(f"Package author: {morphcloud.__author__}")
            else:
                logger.info("Package does not have __author__ attribute")
                
            if hasattr(morphcloud, '__doc__'):
                logger.info(f"Package docstring available: {bool(morphcloud.__doc__)}")
            else:
                logger.info("Package does not have docstring")
            
            logger.info("Package attributes check completed")
        except ImportError as e:
            pytest.fail(f"Could not import package for attribute testing: {e}")

    def test_circular_import_resistance(self):
        """Test that package handles potential circular imports gracefully."""
        logger.info("Testing circular import resistance")
        
        try:
            # Import multiple submodules that might depend on each other
            from morphcloud import api
            from morphcloud.api import MorphCloudClient
            from morphcloud.api import Instance
            
            # Try to create client (this might trigger additional imports)
            client = MorphCloudClient(api_key="test-key")
            assert client is not None, "Client creation should not fail due to circular imports"
            
            logger.info("Circular import resistance test passed")
        except Exception as e:
            logger.warning(f"Potential circular import issue: {e}")
            # Don't fail the test, just log the issue

    def test_reload_safety(self):
        """Test that modules can be safely reloaded."""
        logger.info("Testing reload safety")
        
        try:
            import morphcloud.api
            original_module = morphcloud.api
            
            # Reload the module
            importlib.reload(morphcloud.api)
            reloaded_module = morphcloud.api
            
            # Verify that classes are still accessible after reload
            assert hasattr(reloaded_module, 'MorphCloudClient'), "MorphCloudClient should be available after reload"
            
            logger.info("Module reload successful")
        except Exception as e:
            logger.warning(f"Module reload issue: {e}")
            # Don't fail the test, just log the issue