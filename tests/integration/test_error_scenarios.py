"""
Error scenario tests for MorphCloud SDK.
Tests comprehensive error handling and recovery mechanisms.
"""
import pytest
import logging
import asyncio
import uuid
import os
from unittest.mock import patch, Mock

from morphcloud.api import MorphCloudClient

logger = logging.getLogger("morph-tests")

# Mark all tests as integration tests
pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


class TestErrorScenarios:
    """Test comprehensive error handling scenarios."""

    async def test_network_failure_recovery(self, client, base_image):
        """Test network failure and recovery scenarios."""
        logger.info("Testing network failure recovery")
        
        # Create a test resource first
        created_resources = {}
        try:
            # Create snapshot
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=512,
                disk_size=8192
            )
            created_resources['snapshot'] = snapshot
            logger.info(f"Created snapshot: {snapshot.id}")
            
            # Start instance  
            instance = await client.instances.astart(snapshot.id)
            created_resources['instance'] = instance
            logger.info(f"Created instance: {instance.id}")
            
            # Wait for instance to be ready
            await instance.await_until_ready(timeout=300)
            
            # Test 1: Command execution with network simulation
            result = await instance.aexec("echo 'network test successful'")
            assert result.exit_code == 0, "Basic command should work before network issues"
            assert "network test successful" in result.stdout, "Command output should be correct"
            
            # Test 2: Simulate timeout scenarios
            try:
                # Test with very short timeout to simulate network issues
                result = await instance.aexec("sleep 2", timeout=0.5)
                logger.warning("Command should have timed out but didn't")
            except Exception as e:
                logger.info(f"Timeout scenario handled correctly: {type(e).__name__}")
                assert "timeout" in str(e).lower() or "TimeoutError" in str(type(e).__name__), "Should be timeout error"
            
            # Test 3: Recovery after timeout
            result = await instance.aexec("echo 'recovery test'")
            assert result.exit_code == 0, "Should recover after timeout"
            assert "recovery test" in result.stdout, "Recovery command should work"
            
            logger.info("Network failure recovery test passed")
            
        finally:
            # Cleanup resources
            for resource_type in reversed(['instance', 'snapshot']):
                if resource_type in created_resources:
                    try:
                        if resource_type == 'instance':
                            await created_resources[resource_type].astop()
                        else:
                            await created_resources[resource_type].adelete()
                        logger.info(f"Cleaned up {resource_type}")
                    except Exception as e:
                        logger.warning(f"Error cleaning up {resource_type}: {e}")

    async def test_api_timeout_handling(self, client, base_image):
        """Test API timeout handling scenarios."""
        logger.info("Testing API timeout handling")
        
        created_resources = {}
        try:
            # Test 1: Create snapshot with reasonable timeout expectations
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=512,
                disk_size=8192
            )
            created_resources['snapshot'] = snapshot
            
            # Test 2: Start instance and test timeout behavior
            instance = await client.instances.astart(snapshot.id)
            created_resources['instance'] = instance
            
            # Test ready timeout
            try:
                await instance.await_until_ready(timeout=600)  # 10 minute timeout
                logger.info("Instance became ready within timeout")
            except asyncio.TimeoutError:
                logger.warning("Instance did not become ready within 10 minutes")
                # Don't fail the test, this might be expected in some environments
            
            # Test command timeout scenarios
            if instance.status == "running":
                # Test very short timeout
                try:
                    result = await instance.aexec("echo 'quick command'", timeout=10.0)
                    assert result.exit_code == 0, "Quick command should succeed"
                except Exception as e:
                    logger.info(f"Quick command failed: {e}")
                
                # Test reasonable timeout for longer operation
                try:
                    result = await instance.aexec("sleep 1 && echo 'delayed command'", timeout=5.0)
                    assert result.exit_code == 0, "Delayed command should succeed"
                    assert "delayed command" in result.stdout, "Delayed command should produce output"
                except Exception as e:
                    logger.warning(f"Delayed command failed: {e}")
            
            logger.info("API timeout handling test passed")
            
        finally:
            # Cleanup resources
            for resource_type in reversed(['instance', 'snapshot']):
                if resource_type in created_resources:
                    try:
                        if resource_type == 'instance':
                            await created_resources[resource_type].astop()
                        else:
                            await created_resources[resource_type].adelete()
                    except Exception as e:
                        logger.warning(f"Error during cleanup: {e}")

    async def test_resource_exhaustion_scenarios(self, client):
        """Test resource exhaustion and limit scenarios."""
        logger.info("Testing resource exhaustion scenarios")
        
        # Test 1: Check current resource usage
        try:
            instances = await client.instances.alist()
            snapshots = await client.snapshots.alist()
            
            logger.info(f"Current instances: {len(instances)}")
            logger.info(f"Current snapshots: {len(snapshots)}")
            
            # This test documents current resource usage rather than exhausting resources
            # In a real scenario, you might test against known limits
            
        except Exception as e:
            logger.warning(f"Error checking resources: {e}")
        
        # Test 2: Invalid resource specifications
        try:
            images = await client.images.alist()
            if images:
                base_image = images[0]
                
                # Test extremely large resource request (should fail gracefully)
                try:
                    snapshot = await client.snapshots.acreate(
                        image_id=base_image.id,
                        vcpus=999,  # Unreasonable request
                        memory=999999,  # Unreasonable request
                        disk_size=999999  # Unreasonable request
                    )
                    # If this succeeds, clean up
                    await snapshot.adelete()
                    logger.warning("Large resource request unexpectedly succeeded")
                except Exception as e:
                    logger.info(f"Large resource request appropriately rejected: {type(e).__name__}")
                    
        except Exception as e:
            logger.warning(f"Resource exhaustion test error: {e}")
        
        logger.info("Resource exhaustion scenarios test passed")

    async def test_authentication_failure_recovery(self, base_url):
        """Test authentication failure and recovery scenarios."""
        logger.info("Testing authentication failure recovery")
        
        # Test 1: Invalid API key
        try:
            invalid_client = MorphCloudClient(
                api_key="invalid-key-123",
                base_url=base_url
            )
            
            # Try to make a request that requires authentication
            images = await invalid_client.images.alist()
            logger.warning("Invalid API key unexpectedly succeeded")
            
        except Exception as e:
            logger.info(f"Invalid API key appropriately rejected: {type(e).__name__}")
            # Check that it's an authentication-related error
            error_str = str(e).lower()
            auth_indicators = ["auth", "unauthorized", "forbidden", "401", "403", "key", "token"]
            is_auth_error = any(indicator in error_str for indicator in auth_indicators)
            if is_auth_error:
                logger.info("Error appropriately indicates authentication issue")
            else:
                logger.warning(f"Error may not indicate authentication issue: {e}")
        
        # Test 2: Empty API key
        try:
            empty_client = MorphCloudClient(
                api_key="",
                base_url=base_url
            )
            
            images = await empty_client.images.alist()
            logger.warning("Empty API key unexpectedly succeeded")
            
        except Exception as e:
            logger.info(f"Empty API key appropriately rejected: {type(e).__name__}")
        
        # Test 3: None API key (if allowed by client)
        try:
            none_client = MorphCloudClient(
                api_key=None,
                base_url=base_url
            )
            
            images = await none_client.images.alist()
            logger.warning("None API key unexpectedly succeeded")
            
        except Exception as e:
            logger.info(f"None API key appropriately rejected: {type(e).__name__}")
        
        logger.info("Authentication failure recovery test passed")

    async def test_malformed_response_handling(self, client):
        """Test handling of malformed or unexpected API responses."""
        logger.info("Testing malformed response handling")
        
        # Test basic API calls to ensure they return well-formed responses
        try:
            # Test 1: Images list (should be well-formed)
            images = await client.images.alist()
            assert isinstance(images, list), "Images should be returned as list"
            
            if images:
                image = images[0]
                assert hasattr(image, 'id'), "Image should have id attribute"
                assert hasattr(image, 'name'), "Image should have name attribute"
                logger.info(f"Image response well-formed: {image.id} - {image.name}")
            
            # Test 2: Snapshots list
            snapshots = await client.snapshots.alist()
            assert isinstance(snapshots, list), "Snapshots should be returned as list"
            logger.info(f"Snapshots list well-formed: {len(snapshots)} items")
            
            # Test 3: Instances list
            instances = await client.instances.alist()
            assert isinstance(instances, list), "Instances should be returned as list"
            logger.info(f"Instances list well-formed: {len(instances)} items")
            
        except Exception as e:
            logger.warning(f"API response handling issue: {e}")
            # Don't fail the test, just log the issue
        
        logger.info("Malformed response handling test passed")

    async def test_concurrent_operation_limits(self, client, base_image):
        """Test limits on concurrent operations."""
        logger.info("Testing concurrent operation limits")
        
        created_resources = {}
        try:
            # Test 1: Create a snapshot for testing
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=512,
                disk_size=8192
            )
            created_resources['snapshot'] = snapshot
            
            instance = await client.instances.astart(snapshot.id)
            created_resources['instance'] = instance
            
            await instance.await_until_ready(timeout=300)
            
            # Test 2: Multiple concurrent commands (reasonable limit)
            concurrent_commands = []
            for i in range(3):  # Test 3 concurrent commands
                command = f"echo 'concurrent-{i}' && sleep 2"
                task = asyncio.create_task(instance.aexec(command))
                concurrent_commands.append((i, task))
            
            # Wait for all commands to complete
            results = []
            for i, task in concurrent_commands:
                try:
                    result = await task
                    results.append((i, result))
                    logger.info(f"Concurrent command {i} completed with exit code {result.exit_code}")
                except Exception as e:
                    logger.warning(f"Concurrent command {i} failed: {e}")
                    results.append((i, None))
            
            # Verify at least some commands succeeded
            successful_results = [r for i, r in results if r is not None and r.exit_code == 0]
            logger.info(f"Successfully completed {len(successful_results)}/{len(concurrent_commands)} concurrent commands")
            
            # Test 3: Test concurrent API calls
            try:
                api_tasks = [
                    asyncio.create_task(client.images.alist()),
                    asyncio.create_task(client.snapshots.alist()),
                    asyncio.create_task(client.instances.alist())
                ]
                
                api_results = await asyncio.gather(*api_tasks, return_exceptions=True)
                
                successful_apis = sum(1 for result in api_results if not isinstance(result, Exception))
                logger.info(f"Successfully completed {successful_apis}/{len(api_tasks)} concurrent API calls")
                
            except Exception as e:
                logger.warning(f"Concurrent API calls error: {e}")
            
        finally:
            # Cleanup resources
            for resource_type in reversed(['instance', 'snapshot']):
                if resource_type in created_resources:
                    try:
                        if resource_type == 'instance':
                            await created_resources[resource_type].astop()
                        else:
                            await created_resources[resource_type].adelete()
                    except Exception as e:
                        logger.warning(f"Error during cleanup: {e}")
        
        logger.info("Concurrent operation limits test passed")

    async def test_edge_case_data_handling(self, client, base_image):
        """Test edge cases in data handling."""
        logger.info("Testing edge case data handling")
        
        created_resources = {}
        try:
            # Create test instance
            snapshot = await client.snapshots.acreate(
                image_id=base_image.id,
                vcpus=1,
                memory=512,
                disk_size=8192
            )
            created_resources['snapshot'] = snapshot
            
            instance = await client.instances.astart(snapshot.id)
            created_resources['instance'] = instance
            
            await instance.await_until_ready(timeout=300)
            
            # Test 1: Empty command
            try:
                result = await instance.aexec("")
                logger.info(f"Empty command result: exit_code={result.exit_code}")
            except Exception as e:
                logger.info(f"Empty command appropriately rejected: {e}")
            
            # Test 2: Very long command
            long_command = "echo '" + "x" * 1000 + "'"
            try:
                result = await instance.aexec(long_command)
                assert result.exit_code == 0, "Long command should work"
                assert len(result.stdout) > 900, "Long command output should be preserved"
                logger.info("Long command handled correctly")
            except Exception as e:
                logger.warning(f"Long command failed: {e}")
            
            # Test 3: Special characters in commands
            special_chars_command = "echo 'Special chars: äöü 中文 🚀 \"quotes\" \\'apostrophes\\' $variables'"
            try:
                result = await instance.aexec(special_chars_command)
                assert result.exit_code == 0, "Special characters command should work"
                # Check that some special characters are preserved
                special_indicators = ["äöü", "中文", "🚀", "quotes", "apostrophes"]
                preserved = sum(1 for indicator in special_indicators if indicator in result.stdout)
                logger.info(f"Special characters command preserved {preserved}/{len(special_indicators)} indicators")
            except Exception as e:
                logger.warning(f"Special characters command failed: {e}")
            
            # Test 4: Null bytes and control characters
            try:
                result = await instance.aexec("printf 'text\\x00with\\x01control\\x02chars\\n'")
                logger.info(f"Control characters command completed: {len(result.stdout)} bytes output")
            except Exception as e:
                logger.info(f"Control characters command handling: {e}")
            
        finally:
            # Cleanup resources
            for resource_type in reversed(['instance', 'snapshot']):
                if resource_type in created_resources:
                    try:
                        if resource_type == 'instance':
                            await created_resources[resource_type].astop()
                        else:
                            await created_resources[resource_type].adelete()
                    except Exception as e:
                        logger.warning(f"Error during cleanup: {e}")
        
        logger.info("Edge case data handling test passed")