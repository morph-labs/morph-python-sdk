"""
Function-scoped tests for Sandbox functionality in MorphCloud SDK.
"""
import pytest
import logging
import uuid
import os
import pytest_asyncio

from morphcloud.api import MorphCloudClient
from morphcloud.sandbox import Sandbox, SandboxAPI

logger = logging.getLogger("morph-tests")

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio

# Configure pytest-asyncio
def pytest_configure(config):
    config.option.asyncio_default_fixture_loop_scope = "function"


@pytest.fixture
def api_key():
    """Get API key from environment variable."""
    key = os.environ.get("MORPH_API_KEY")
    if not key:
        pytest.fail("MORPH_API_KEY environment variable must be set")
    return key


@pytest.fixture
def base_url():
    """Get base URL from environment variable."""
    return os.environ.get("MORPH_BASE_URL")


@pytest_asyncio.fixture
async def client(api_key, base_url):
    """Create a MorphCloudClient."""
    client = MorphCloudClient(api_key=api_key, base_url=base_url)
    logger.info("Created MorphCloud client")
    return client


@pytest_asyncio.fixture
async def sandbox_api(client):
    """Create a SandboxAPI instance."""
    api = SandboxAPI(client)
    logger.info("Created SandboxAPI")
    return api


async def test_sandbox_creation_and_connection(client):
    """Test basic sandbox creation and connection."""
    logger.info("Testing sandbox creation and connection")
    
    try:
        # Create a new sandbox
        sandbox = Sandbox.new(client=client, ttl_seconds=600)
        logger.info(f"Created sandbox: {sandbox._instance.id}")
        
        # Connect to the sandbox
        sandbox.connect()
        logger.info("Connected to sandbox successfully")
        
        # Verify sandbox properties
        assert sandbox._instance.id.startswith("morphvm_"), "Sandbox ID should start with 'morphvm_'"
        assert sandbox.jupyter_url is not None, "Sandbox should have a Jupyter URL"
        assert isinstance(sandbox._kernel_ids, dict), "Sandbox should have kernel_ids dictionary"
        
        logger.info("Sandbox creation and connection test passed")
        
    finally:
        # Clean up
        if 'sandbox' in locals():
            try:
                logger.info(f"Cleaning up sandbox {sandbox._instance.id}")
                sandbox.close()
                sandbox.shutdown()
                logger.info("Sandbox cleaned up successfully")
            except Exception as e:
                logger.error(f"Error cleaning up sandbox: {e}")


async def test_sandbox_code_execution(client):
    """Test code execution in sandbox."""
    logger.info("Testing sandbox code execution")
    
    try:
        # Create and connect to sandbox
        sandbox = Sandbox.new(client=client, ttl_seconds=600)
        sandbox.connect()
        logger.info(f"Created and connected to sandbox: {sandbox._instance.id}")
        
        # Test Python code execution
        test_value = uuid.uuid4().hex[:8]
        result = sandbox.run_code(f"test_var = '{test_value}'", language="python")
        assert result.success, f"Python code execution failed: {result.error}"
        logger.info("Python variable assignment successful")
        
        # Verify the variable was set
        result = sandbox.run_code("print(test_var)", language="python")
        assert result.success, f"Python variable retrieval failed: {result.error}"
        assert test_value in result.text, f"Expected '{test_value}' in output, got: {result.text}"
        logger.info("Python variable retrieval successful")
        
        # Test JavaScript code execution
        result = sandbox.run_code("console.log('hello from js');", language="javascript")
        assert result.success, f"JavaScript code execution failed: {result.error}"
        assert "hello from js" in result.text, f"Expected 'hello from js' in output, got: {result.text}"
        logger.info("JavaScript code execution successful")
        
        logger.info("Sandbox code execution test passed")
        
    finally:
        if 'sandbox' in locals():
            try:
                sandbox.close()
                sandbox.shutdown()
            except Exception as e:
                logger.error(f"Error cleaning up sandbox: {e}")


async def test_kernel_persistence_across_get_calls(client, sandbox_api):
    """Test that kernel state persists when using .get() to retrieve a sandbox."""
    logger.info("Testing kernel persistence across .get() calls")
    
    try:
        # Create and connect to first sandbox instance
        sandbox1 = Sandbox.new(client=client, ttl_seconds=600)
        sandbox1.connect()
        logger.info(f"Created sandbox1: {sandbox1._instance.id}")
        
        # Set a variable in Python
        test_value = f"kernel_test_{uuid.uuid4().hex[:8]}"
        result1 = sandbox1.run_code(f"persistent_var = '{test_value}'", language="python")
        assert result1.success, f"Failed to set variable: {result1.error}"
        logger.info(f"Set persistent_var to '{test_value}'")
        
        # Get the kernel ID for verification
        original_kernel_id = sandbox1._kernel_ids.get("python")
        assert original_kernel_id is not None, "No Python kernel ID found"
        logger.info(f"Original Python kernel ID: {original_kernel_id}")
        
        # Retrieve the same sandbox using .get()
        sandbox2 = sandbox_api.get(sandbox1._instance.id)
        sandbox2.connect()
        logger.info(f"Retrieved sandbox2 via .get(): {sandbox2._instance.id}")
        
        # Verify kernel ID is preserved
        retrieved_kernel_id = sandbox2._kernel_ids.get("python")
        assert retrieved_kernel_id == original_kernel_id, (
            f"Kernel IDs don't match: original={original_kernel_id}, "
            f"retrieved={retrieved_kernel_id}"
        )
        logger.info("Kernel ID preservation verified")
        
        # Verify variable state is preserved
        result2 = sandbox2.run_code("print(persistent_var)", language="python")
        assert result2.success, f"Failed to access persistent variable: {result2.error}"
        assert test_value in result2.text, (
            f"Persistent variable not found. Expected '{test_value}' in output: {result2.text}"
        )
        logger.info("Variable state preservation verified")
        
        logger.info("Kernel persistence test passed")
        
    finally:
        # Clean up
        for i, sandbox in enumerate([s for s in [locals().get('sandbox1'), locals().get('sandbox2')] if s]):
            try:
                logger.info(f"Cleaning up sandbox{i+1}: {sandbox._instance.id}")
                sandbox.close()
                if i == 0:  # Only shutdown once
                    sandbox.shutdown()
            except Exception as e:
                logger.error(f"Error cleaning up sandbox{i+1}: {e}")


async def test_multiple_language_kernel_persistence(client, sandbox_api):
    """Test kernel persistence works for multiple programming languages."""
    logger.info("Testing multiple language kernel persistence")
    
    try:
        # Create and connect to sandbox
        sandbox1 = Sandbox.new(client=client, ttl_seconds=600)
        sandbox1.connect()
        logger.info(f"Created sandbox1: {sandbox1._instance.id}")
        
        # Set variables in different languages
        python_value = f"py_{uuid.uuid4().hex[:8]}"
        js_value = f"js_{uuid.uuid4().hex[:8]}"
        
        python_result = sandbox1.run_code(f"py_var = '{python_value}'", language="python")
        assert python_result.success, f"Python execution failed: {python_result.error}"
        
        js_result = sandbox1.run_code(f"var js_var = '{js_value}';", language="javascript")
        assert js_result.success, f"JavaScript execution failed: {js_result.error}"
        
        logger.info(f"Set variables - Python: {python_value}, JavaScript: {js_value}")
        
        # Store original kernel IDs
        original_kernels = sandbox1._kernel_ids.copy()
        logger.info(f"Original kernel IDs: {original_kernels}")
        
        # Retrieve sandbox and verify all kernels are preserved
        sandbox2 = sandbox_api.get(sandbox1._instance.id)
        sandbox2.connect()
        logger.info(f"Retrieved sandbox2: {sandbox2._instance.id}")
        logger.info(f"Retrieved kernel IDs: {sandbox2._kernel_ids}")
        
        # Check that kernel IDs match for all languages
        for language, kernel_id in original_kernels.items():
            retrieved_kernel_id = sandbox2._kernel_ids.get(language)
            assert retrieved_kernel_id == kernel_id, (
                f"Kernel ID mismatch for {language}: "
                f"original={kernel_id}, retrieved={retrieved_kernel_id}"
            )
        
        # Verify variables are accessible
        py_check = sandbox2.run_code("print(py_var)", language="python")
        assert py_check.success and python_value in py_check.text, (
            f"Python variable not preserved: {py_check.text}"
        )
        
        js_check = sandbox2.run_code("console.log(js_var);", language="javascript")
        assert js_check.success and js_value in js_check.text, (
            f"JavaScript variable not preserved: {js_check.text}"
        )
        
        logger.info("Multiple language kernel persistence test passed")
        
    finally:
        # Clean up
        for i, sandbox in enumerate([s for s in [locals().get('sandbox1'), locals().get('sandbox2')] if s]):
            try:
                sandbox.close()
                if i == 0:  # Only shutdown once
                    sandbox.shutdown()
            except Exception as e:
                logger.error(f"Error cleaning up sandbox{i+1}: {e}")


async def test_kernel_discovery_with_fresh_sandbox(client, sandbox_api):
    """Test that kernel discovery handles fresh sandboxes correctly."""
    logger.info("Testing kernel discovery with fresh sandbox")
    
    try:
        # Create sandbox but don't connect yet
        sandbox1 = Sandbox.new(client=client, ttl_seconds=600)
        logger.info(f"Created fresh sandbox: {sandbox1._instance.id}")
        
        # Get the sandbox without any prior kernel creation
        sandbox2 = sandbox_api.get(sandbox1._instance.id)
        sandbox2.connect()
        logger.info("Connected to fresh sandbox via .get()")
        
        # Should be able to run code (will create new kernel)
        test_value = f"fresh_{uuid.uuid4().hex[:8]}"
        result = sandbox2.run_code(f"print('{test_value}')", language="python")
        assert result.success, f"Failed to run code on fresh sandbox: {result.error}"
        assert test_value in result.text, f"Expected '{test_value}' in output: {result.text}"
        
        logger.info("Fresh sandbox kernel discovery test passed")
        
    finally:
        # Clean up
        for sandbox in [locals().get('sandbox1'), locals().get('sandbox2')]:
            if sandbox:
                try:
                    sandbox.close()
                    sandbox.shutdown()
                    break  # Only shutdown once
                except Exception as e:
                    logger.error(f"Error cleaning up sandbox: {e}")


async def test_sandbox_error_handling(client):
    """Test error handling in sandbox operations."""
    logger.info("Testing sandbox error handling")
    
    try:
        # Create and connect to sandbox
        sandbox = Sandbox.new(client=client, ttl_seconds=600)
        sandbox.connect()
        logger.info(f"Created sandbox: {sandbox._instance.id}")
        
        # Test code with syntax error
        result = sandbox.run_code("print('missing quote)", language="python")
        assert not result.success, "Code with syntax error should fail"
        assert result.error is not None, "Failed code should have error message"
        logger.info("Syntax error handling verified")
        
        # Test unsupported language
        result = sandbox.run_code("print('test')", language="unsupported")
        assert not result.success, "Unsupported language should fail"
        assert "Unsupported language" in result.error, f"Expected unsupported language error: {result.error}"
        logger.info("Unsupported language handling verified")
        
        # Verify sandbox is still functional after errors
        result = sandbox.run_code("print('still works')", language="python")
        assert result.success, "Sandbox should remain functional after errors"
        assert "still works" in result.text, f"Expected 'still works' in output: {result.text}"
        logger.info("Sandbox resilience after errors verified")
        
        logger.info("Sandbox error handling test passed")
        
    finally:
        if 'sandbox' in locals():
            try:
                sandbox.close()
                sandbox.shutdown()
            except Exception as e:
                logger.error(f"Error cleaning up sandbox: {e}")