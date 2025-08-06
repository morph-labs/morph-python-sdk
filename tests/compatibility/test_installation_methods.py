"""
Compatibility tests for different installation methods in MorphCloud SDK.
"""
import pytest
import logging
import subprocess
import sys
import os
from pathlib import Path

logger = logging.getLogger("morph-tests")

# Mark all tests as compatibility tests  
pytestmark = [pytest.mark.compatibility]


class TestInstallationMethods:
    """Test different installation methods and package managers."""

    def test_pip_installation_compatibility(self):
        """Test pip installation compatibility."""
        logger.info("Testing pip installation compatibility")
        
        # Check if pip is available
        try:
            import pip
            logger.info(f"pip is available: {pip.__version__}")
        except ImportError:
            logger.warning("pip is not available as a module")
        
        # Test pip show for the package (if installed)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", "morphcloud"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info("morphcloud package found via pip show")
                logger.info(f"Package info:\n{result.stdout}")
            else:
                logger.warning("morphcloud package not found via pip show")
                
        except subprocess.TimeoutExpired:
            logger.warning("pip show command timed out")
        except Exception as e:
            logger.warning(f"Error running pip show: {e}")

    def test_poetry_installation_compatibility(self):
        """Test poetry installation compatibility."""
        logger.info("Testing poetry installation compatibility")
        
        # Check if poetry is available
        try:
            result = subprocess.run(
                ["poetry", "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"poetry is available: {result.stdout.strip()}")
                
                # Check for pyproject.toml in package directory
                package_dir = Path(__file__).parent.parent.parent
                pyproject_path = package_dir / "pyproject.toml"
                
                if pyproject_path.exists():
                    logger.info("pyproject.toml found - poetry compatible")
                    
                    # Try to validate the pyproject.toml
                    try:
                        import toml
                        with open(pyproject_path) as f:
                            pyproject_data = toml.load(f)
                        
                        if "tool" in pyproject_data and "poetry" in pyproject_data["tool"]:
                            logger.info("pyproject.toml has poetry configuration")
                        else:
                            logger.info("pyproject.toml exists but no poetry config found")
                            
                    except ImportError:
                        logger.warning("toml module not available for parsing pyproject.toml")
                    except Exception as e:
                        logger.warning(f"Error parsing pyproject.toml: {e}")
                        
                else:
                    logger.warning("pyproject.toml not found")
                    
            else:
                logger.warning("poetry is not available")
                
        except FileNotFoundError:
            logger.warning("poetry command not found")
        except subprocess.TimeoutExpired:
            logger.warning("poetry --version command timed out")
        except Exception as e:
            logger.warning(f"Error checking poetry: {e}")

    def test_conda_installation_compatibility(self):
        """Test conda installation compatibility."""
        logger.info("Testing conda installation compatibility")
        
        # Check if conda is available
        try:
            result = subprocess.run(
                ["conda", "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"conda is available: {result.stdout.strip()}")
                
                # Check current conda environment
                conda_env = os.environ.get("CONDA_DEFAULT_ENV")
                if conda_env:
                    logger.info(f"Running in conda environment: {conda_env}")
                
                # Check if package is available via conda
                try:
                    search_result = subprocess.run(
                        ["conda", "search", "morphcloud"],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    
                    if search_result.returncode == 0 and "morphcloud" in search_result.stdout:
                        logger.info("morphcloud package found in conda repositories")
                    else:
                        logger.info("morphcloud package not found in conda repositories")
                        
                except subprocess.TimeoutExpired:
                    logger.warning("conda search command timed out")
                except Exception as e:
                    logger.warning(f"Error searching conda repositories: {e}")
                    
            else:
                logger.warning("conda is not available")
                
        except FileNotFoundError:
            logger.warning("conda command not found")
        except subprocess.TimeoutExpired:
            logger.warning("conda --version command timed out")
        except Exception as e:
            logger.warning(f"Error checking conda: {e}")

    def test_package_distribution_format(self):
        """Test package distribution format compatibility."""
        logger.info("Testing package distribution format")
        
        # Check if package is installed and find its location
        try:
            import morphcloud
            package_path = Path(morphcloud.__file__).parent
            logger.info(f"Package location: {package_path}")
            
            # Check if it's a wheel installation
            if package_path.name.endswith(".egg-info") or any(p.suffix == ".dist-info" for p in package_path.parent.iterdir()):
                logger.info("Package appears to be installed from wheel/egg")
            else:
                logger.info("Package appears to be installed in development mode")
                
            # Check for py.typed file (PEP 561 compliance)
            py_typed_path = package_path / "py.typed"
            if py_typed_path.exists():
                logger.info("Package includes py.typed file (type hints available)")
            else:
                logger.info("Package does not include py.typed file")
                
        except ImportError:
            logger.warning("morphcloud package not importable for distribution format testing")
        except Exception as e:
            logger.warning(f"Error checking package distribution format: {e}")

    def test_virtual_environment_compatibility(self):
        """Test virtual environment compatibility."""
        logger.info("Testing virtual environment compatibility")
        
        # Check if running in virtual environment
        in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        
        if in_venv:
            logger.info("Running in virtual environment")
            logger.info(f"Python prefix: {sys.prefix}")
            logger.info(f"Python base prefix: {getattr(sys, 'base_prefix', 'N/A')}")
        else:
            logger.info("Running in system Python")
            logger.info(f"Python prefix: {sys.prefix}")
        
        # Check VIRTUAL_ENV environment variable
        virtual_env = os.environ.get("VIRTUAL_ENV")
        if virtual_env:
            logger.info(f"VIRTUAL_ENV set to: {virtual_env}")
        else:
            logger.info("VIRTUAL_ENV not set")
        
        # Check if pip is using virtual environment
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                packages = result.stdout.split('\n')
                logger.info(f"Found {len(packages)} packages in current environment")
                
                # Check if morphcloud is in the list
                morphcloud_found = any("morphcloud" in pkg.lower() for pkg in packages)
                if morphcloud_found:
                    logger.info("morphcloud package found in current environment")
                else:
                    logger.info("morphcloud package not found in current environment")
                    
            else:
                logger.warning("Could not list packages in current environment")
                
        except subprocess.TimeoutExpired:
            logger.warning("pip list command timed out")
        except Exception as e:
            logger.warning(f"Error checking packages in virtual environment: {e}")

    def test_editable_installation_compatibility(self):
        """Test editable installation compatibility."""
        logger.info("Testing editable installation compatibility")
        
        try:
            import morphcloud
            package_file = morphcloud.__file__
            package_path = Path(package_file)
            
            # Check if this looks like an editable installation
            # In editable installs, the package usually points to the source directory
            source_indicators = [
                "setup.py" in [p.name for p in package_path.parent.iterdir()],
                "pyproject.toml" in [p.name for p in package_path.parent.iterdir()],
                ".git" in [p.name for p in package_path.parent.iterdir()],
                package_path.parent.name == "src"  # Common src layout
            ]
            
            if any(source_indicators):
                logger.info("Package appears to be installed in editable mode")
                logger.info(f"Package source directory: {package_path.parent}")
            else:
                logger.info("Package appears to be installed normally (not editable)")
            
            # Check for .egg-link file (pip editable installs)
            site_packages = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
            egg_link = site_packages / "morphcloud.egg-link"
            
            if egg_link.exists():
                logger.info("Found .egg-link file indicating editable installation")
                try:
                    with open(egg_link) as f:
                        egg_link_content = f.read().strip()
                        logger.info(f"Egg-link points to: {egg_link_content}")
                except Exception as e:
                    logger.warning(f"Could not read egg-link file: {e}")
            else:
                logger.info("No .egg-link file found")
                
        except ImportError:
            logger.warning("morphcloud package not importable for editable installation testing")
        except Exception as e:
            logger.warning(f"Error checking editable installation: {e}")

    def test_dependency_resolution(self):
        """Test dependency resolution compatibility."""
        logger.info("Testing dependency resolution")
        
        try:
            # Check if all required dependencies are available
            required_deps = [
                "requests", "tqdm", "httpx", "pydantic", "psutil", 
                "anthropic", "click", "paramiko", "pathspec", 
                "rich", "packaging", "toml", "websocket-client", 
                "mcp", "pyyaml"
            ]
            
            available_deps = []
            missing_deps = []
            
            for dep in required_deps:
                try:
                    __import__(dep)
                    available_deps.append(dep)
                except ImportError:
                    missing_deps.append(dep)
            
            logger.info(f"Available dependencies ({len(available_deps)}): {available_deps}")
            if missing_deps:
                logger.warning(f"Missing dependencies ({len(missing_deps)}): {missing_deps}")
            else:
                logger.info("All required dependencies are available")
                
            # Check optional dependencies
            optional_deps = ["playwright"]  # from [computer] group
            
            for dep in optional_deps:
                try:
                    __import__(dep)
                    logger.info(f"Optional dependency available: {dep}")
                except ImportError:
                    logger.info(f"Optional dependency not available: {dep}")
                    
        except Exception as e:
            logger.warning(f"Error checking dependency resolution: {e}")

    def test_import_after_installation(self):
        """Test that package imports correctly after various installation methods."""
        logger.info("Testing import after installation")
        
        # Test basic import
        try:
            import morphcloud
            logger.info("Basic import successful")
        except ImportError as e:
            pytest.fail(f"Basic import failed: {e}")
        
        # Test submodule imports
        try:
            from morphcloud.api import MorphCloudClient
            from morphcloud.sandbox import SandboxAPI
            logger.info("Submodule imports successful")
        except ImportError as e:
            logger.warning(f"Some submodule imports failed: {e}")
        
        # Test that imported classes can be instantiated
        try:
            from morphcloud.api import MorphCloudClient
            client = MorphCloudClient(api_key="test-key")
            logger.info("Class instantiation successful")
        except Exception as e:
            logger.warning(f"Class instantiation issue: {e}")
        
        logger.info("Import after installation testing completed")