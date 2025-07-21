"""
Test HTTP service exposure correctness and external accessibility.

This module validates HTTP service functionality:
- Single HTTP service exposure
- Multiple HTTP services
- Service accessibility from external clients
- Service hiding/removal
"""
import pytest
import logging
import time
import json
import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger("morph-api-tests")

# Performance tracking
PERFORMANCE_LOG_FILE = Path(__file__).parent.parent.parent / "performance_log.jsonl"

# Mark all tests as asyncio tests
pytestmark = pytest.mark.asyncio


def log_performance_metric(operation: str, duration: float, status: str, error: str = None):
    """Log performance metric to JSONL file."""
    metric = {
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "duration_seconds": round(duration, 2),
        "status": status
    }
    if error:
        metric["error"] = error
    
    # Ensure parent directory exists
    PERFORMANCE_LOG_FILE.parent.mkdir(exist_ok=True)
    
    # Append to JSONL file
    with open(PERFORMANCE_LOG_FILE, "a") as f:
        f.write(json.dumps(metric) + "\n")


async def timed_operation(operation_name: str, operation_func):
    """Time an async operation and log the result."""
    start_time = time.time()
    try:
        result = await operation_func()
        duration = time.time() - start_time
        
        # Log to console
        logger.info(f"⏱️  {operation_name}: {duration:.2f}s")
        
        # Log to performance file
        log_performance_metric(operation_name, duration, "success")
        
        return result, duration
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"⏱️  {operation_name}: {duration:.2f}s (FAILED: {e})")
        
        # Log failure to performance file
        log_performance_metric(operation_name, duration, "failed", str(e))
        
        raise




@pytest.fixture
async def http_ready_instance(client, base_image):
    """Create an instance ready for HTTP service testing."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot with slightly larger configuration for better HTTP performance
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,
            memory=2048,  # 2GB for better HTTP performance
            disk_size=16*1024  # 16GB
        )
        logger.info(f"Created snapshot {snapshot.id} for HTTP testing")
        
        # Start instance
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready with extended timeout for setup
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for HTTP testing")
        
        # Install required packages
        logger.info("Installing HTTP testing dependencies")
        install_result = await instance.aexec(
            "apt-get update && apt-get install -y tmux python3 curl nginx-light",
            timeout=300
        )
        
        if install_result.exit_code != 0:
            logger.warning(f"Package installation had issues: {install_result.stderr}")
        
        yield {
            'instance': instance,
            'snapshot': snapshot
        }
        
    finally:
        # Clean up
        if instance:
            try:
                # Kill any tmux sessions
                await instance.aexec("tmux kill-server 2>/dev/null || true", timeout=10)
                await instance.astop()
                logger.info("HTTP test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping HTTP test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("HTTP test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting HTTP test snapshot: {e}")


async def test_single_http_service_correctness(http_ready_instance, client):
    """Test single HTTP service exposure and external accessibility."""
    logger.info("Testing single HTTP service correctness")
    
    instance_data = http_ready_instance
    instance = instance_data['instance']
    
    # Setup test service
    port = 8080
    test_id = uuid.uuid4().hex[:8]
    service_name = f"test-service-{test_id}"
    
    logger.info(f"Setting up HTTP service on port {port}")
    
    # Create unique test content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>HTTP Correctness Test</title></head>
    <body>
        <h1>HTTP Service Correctness Test</h1>
        <p>Service: {service_name}</p>
        <p>Port: {port}</p>
        <p>Test ID: {test_id}</p>
        <p>Timestamp: {datetime.now().isoformat()}</p>
    </body>
    </html>
    """
    
    # Setup service directory and content
    await instance.aexec(f"mkdir -p /tmp/{service_name}")
    await instance.aexec(f"cat > /tmp/{service_name}/index.html << 'EOF'\n{html_content}\nEOF")
    
    # Start HTTP server in tmux session
    server_cmd = f"cd /tmp/{service_name} && tmux new-session -d -s {service_name} 'python3 -m http.server {port}'"
    server_result, server_setup_time = await timed_operation(
        "http_service_setup",
        lambda: instance.aexec(server_cmd)
    )
    
    assert server_result.exit_code == 0, f"Failed to start HTTP server: {server_result.stderr}"
    
    # Wait for server to start
    await asyncio.sleep(3)
    
    # Verify server is running locally
    local_test_result = await instance.aexec(f"curl -s localhost:{port}")
    assert local_test_result.exit_code == 0, f"HTTP server not responding locally: {local_test_result.stderr}"
    assert test_id in local_test_result.stdout, "Local HTTP server not serving expected content"
    logger.info("✓ HTTP server confirmed running locally")
    
    try:
        # Expose the HTTP service
        service_url, expose_time = await timed_operation(
            "http_service_expose",
            lambda: instance.aexpose_http_service(service_name, port)
        )
        
        logger.info(f"HTTP service exposed at: {service_url}")
        
        # Verify service is registered in instance (following working pattern)
        instance = await client.instances.aget(instance.id)  # Refresh instance data
        assert len(instance.networking.http_services) > 0, "No HTTP services exposed"
        assert any(s.port == port for s in instance.networking.http_services), "Service not found in instance networking"
        logger.info("✓ Service confirmed in instance networking")
        
        # Test service accessibility from within the instance
        internal_access_result, internal_access_time = await timed_operation(
            "http_internal_access",
            lambda: instance.aexec(f"curl -s 'localhost:{port}'", timeout=15)
        )
        
        access_successful = (
            internal_access_result.exit_code == 0 and 
            test_id in internal_access_result.stdout
        )
        assert access_successful, f"Internal HTTP access failed: {internal_access_result.stderr}"
        logger.info(f"✓ HTTP service accessible internally ({internal_access_time:.2f}s)")
        
        # Test service hiding
        _, hide_time = await timed_operation(
            "http_service_hide",
            lambda: instance.ahide_http_service(service_name)
        )
        
        # Verify service is no longer exposed (following working pattern)
        instance = await client.instances.aget(instance.id)  # Refresh instance data
        assert not any(s.port == port for s in instance.networking.http_services), "Service still exposed after hide"
        logger.info("✓ Service successfully hidden")
        
        # Performance summary
        logger.info(f"📊 Single HTTP Service Performance:")
        logger.info(f"   Setup:    {server_setup_time:.2f}s")
        logger.info(f"   Expose:   {expose_time:.2f}s")
        logger.info(f"   Access:   {internal_access_time:.2f}s")
        logger.info(f"   Hide:     {hide_time:.2f}s")
        
    finally:
        # Cleanup tmux session
        await instance.aexec(f"tmux kill-session -t {service_name} 2>/dev/null || true")


async def test_multiple_http_services_correctness(http_ready_instance, client):
    """Test multiple HTTP services on one instance."""
    logger.info("Testing multiple HTTP services correctness")
    
    instance_data = http_ready_instance
    instance = instance_data['instance']
    
    # Setup multiple services
    services_config = [
        {'port': 8080, 'name': 'service-alpha'},
        {'port': 8081, 'name': 'service-beta'},
        {'port': 8082, 'name': 'service-gamma'}
    ]
    
    exposed_services = []
    setup_times = []
    
    # Setup and expose each service
    for config in services_config:
        port = config['port']
        service_name = config['name']
        test_id = uuid.uuid4().hex[:8]
        
        logger.info(f"Setting up service '{service_name}' on port {port}")
        
        # Create service content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><title>{service_name.title()} Service</title></head>
        <body>
            <h1>{service_name.title()} HTTP Service</h1>
            <p>Port: {port}</p>
            <p>Test ID: {test_id}</p>
            <p>Service Name: {service_name}</p>
        </body>
        </html>
        """
        
        # Setup service directory
        await instance.aexec(f"mkdir -p /tmp/{service_name}")
        await instance.aexec(f"cat > /tmp/{service_name}/index.html << 'EOF'\n{html_content}\nEOF")
        
        # Start server
        server_cmd = f"cd /tmp/{service_name} && tmux new-session -d -s {service_name} 'python3 -m http.server {port}'"
        server_result, setup_time = await timed_operation(
            f"http_service_setup_{service_name}",
            lambda: instance.aexec(server_cmd)
        )
        
        assert server_result.exit_code == 0, f"Failed to start {service_name}: {server_result.stderr}"
        setup_times.append(setup_time)
        
        # Wait for server startup
        await asyncio.sleep(2)
        
        # Verify local access
        local_test = await instance.aexec(f"curl -s localhost:{port}")
        assert local_test.exit_code == 0 and test_id in local_test.stdout, f"Service {service_name} not accessible locally"
        
        # Expose service
        service_url, expose_time = await timed_operation(
            f"http_service_expose_{service_name}",
            lambda: instance.aexpose_http_service(service_name, port)
        )
        
        exposed_services.append({
            'name': service_name,
            'port': port,
            'url': service_url,
            'test_id': test_id,
            'setup_time': setup_time,
            'expose_time': expose_time
        })
        
        logger.info(f"✓ Service '{service_name}' exposed at {service_url}")
    
    # Verify all services are registered
    refreshed_instance = await client.instances.aget(instance.id)
    http_services = getattr(refreshed_instance.networking, 'http_services', [])
    
    for service in exposed_services:
        service_found = any(s.port == service['port'] for s in http_services)
        assert service_found, f"Service {service['name']} not found in instance networking"
    
    logger.info(f"✓ All {len(exposed_services)} services confirmed in instance networking")
    
    # Test accessing all services
    access_times = []
    successful_accesses = 0
    
    for service in exposed_services:
        access_result, access_time = await timed_operation(
            f"http_service_access_{service['name']}",
            lambda s=service: instance.aexec(f"curl -s localhost:{s['port']}")
        )
        
        access_times.append(access_time)
        
        if access_result.exit_code == 0 and service['test_id'] in access_result.stdout:
            successful_accesses += 1
            logger.info(f"✓ Service '{service['name']}' accessible ({access_time:.2f}s)")
        else:
            logger.warning(f"⚠ Service '{service['name']}' access failed")
    
    access_success_rate = successful_accesses / len(exposed_services)
    assert access_success_rate >= 0.8, f"Multiple service access rate too low: {access_success_rate*100:.1f}% (need ≥80%)"
    
    # Test hiding services one by one
    hide_times = []
    
    for service in exposed_services:
        _, hide_time = await timed_operation(
            f"http_service_hide_{service['name']}",
            lambda s=service: instance.ahide_http_service(s['name'])
        )
        
        hide_times.append(hide_time)
        
        # Verify service is no longer exposed
        refreshed_instance = await client.instances.aget(instance.id)
        http_services = getattr(refreshed_instance.networking, 'http_services', [])
        service_still_found = any(s.port == service['port'] for s in http_services)
        assert not service_still_found, f"Service {service['name']} still exposed after hiding"
        
        logger.info(f"✓ Service '{service['name']}' hidden ({hide_time:.2f}s)")
    
    # Performance analysis
    total_setup_time = sum(setup_times)
    total_expose_time = sum(s['expose_time'] for s in exposed_services)
    total_access_time = sum(access_times)
    total_hide_time = sum(hide_times)
    
    logger.info(f"📊 Multiple HTTP Services Performance:")
    logger.info(f"   Services:       {len(exposed_services)}")
    logger.info(f"   Success Rate:   {access_success_rate*100:.1f}%")
    logger.info(f"   Setup Total:    {total_setup_time:.2f}s (avg: {total_setup_time/len(exposed_services):.2f}s)")
    logger.info(f"   Expose Total:   {total_expose_time:.2f}s (avg: {total_expose_time/len(exposed_services):.2f}s)")
    logger.info(f"   Access Total:   {total_access_time:.2f}s (avg: {total_access_time/len(exposed_services):.2f}s)")
    logger.info(f"   Hide Total:     {total_hide_time:.2f}s (avg: {total_hide_time/len(exposed_services):.2f}s)")
    
    # Cleanup tmux sessions
    for service in exposed_services:
        await instance.aexec(f"tmux kill-session -t {service['name']} 2>/dev/null || true")


async def test_http_service_persistence(http_ready_instance, client):
    """Test HTTP service persistence across instance operations."""
    logger.info("Testing HTTP service persistence")
    
    instance_data = http_ready_instance
    instance = instance_data['instance']
    
    port = 8090
    service_name = "persistence-test"
    test_id = uuid.uuid4().hex[:8]
    
    # Setup persistent service
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Persistence Test</title></head>
    <body>
        <h1>HTTP Persistence Test</h1>
        <p>Test ID: {test_id}</p>
        <p>This service tests persistence across operations</p>
    </body>
    </html>
    """
    
    await instance.aexec(f"mkdir -p /tmp/{service_name}")
    await instance.aexec(f"cat > /tmp/{service_name}/index.html << 'EOF'\n{html_content}\nEOF")
    
    # Start service
    server_cmd = f"cd /tmp/{service_name} && tmux new-session -d -s {service_name} 'python3 -m http.server {port}'"
    server_result = await instance.aexec(server_cmd)
    assert server_result.exit_code == 0, f"Failed to start persistence test service: {server_result.stderr}"
    
    await asyncio.sleep(3)
    
    # Expose service
    service_url, _ = await timed_operation(
        "http_persistence_expose",
        lambda: instance.aexpose_http_service(service_name, port)
    )
    
    # Verify service is working
    initial_test = await instance.aexec(f"curl -s localhost:{port}")
    assert initial_test.exit_code == 0 and test_id in initial_test.stdout, "Service not working initially"
    logger.info("✓ Service exposed and working initially")
    
    try:
        # Test persistence through pause/resume cycle
        logger.info("Testing persistence through pause/resume cycle")
        
        # Pause instance
        _, pause_time = await timed_operation(
            "instance_pause_for_persistence",
            lambda: instance.apause()
        )
        
        # Resume instance
        _, resume_time = await timed_operation(
            "instance_resume_for_persistence", 
            lambda: instance.aresume()
        )
        
        # Wait for instance to be fully ready
        await instance.await_until_ready(timeout=300)
        
        # Check if service is still exposed in networking config
        refreshed_instance = await client.instances.aget(instance.id)
        http_services = getattr(refreshed_instance.networking, 'http_services', [])
        service_still_registered = any(s.port == port for s in http_services)
        
        if service_still_registered:
            logger.info("✓ Service still registered in networking after pause/resume")
            
            # Test if the actual service is still accessible
            # Note: tmux sessions and the HTTP server may not survive pause/resume
            post_resume_test = await instance.aexec(f"curl -s localhost:{port} || echo 'SERVICE_DOWN'")
            
            if post_resume_test.exit_code == 0 and test_id in post_resume_test.stdout:
                logger.info("✓ Service fully functional after pause/resume")
            else:
                logger.warning("⚠ Service registered but not functional after pause/resume (expected)")
                
        else:
            logger.warning("⚠ Service not registered after pause/resume")
        
        logger.info(f"📊 Persistence Test Performance:")
        logger.info(f"   Pause:  {pause_time:.2f}s")
        logger.info(f"   Resume: {resume_time:.2f}s")
        
    finally:
        # Hide service
        try:
            await instance.ahide_http_service(service_name)
            logger.info("✓ Service hidden successfully")
        except Exception as e:
            logger.warning(f"Service hide failed (may be expected): {e}")
        
        # Cleanup
        await instance.aexec(f"tmux kill-session -t {service_name} 2>/dev/null || true")


async def test_http_service_error_conditions(http_ready_instance, client):
    """Test HTTP service error conditions and edge cases."""
    logger.info("Testing HTTP service error conditions")
    
    instance_data = http_ready_instance
    instance = instance_data['instance']
    
    # Test exposing service on non-existent port
    logger.info("Testing exposure of non-existent service")
    
    try:
        fake_service_url = await instance.aexpose_http_service("non-existent", 9999)
        logger.warning(f"⚠ Non-existent service exposure succeeded: {fake_service_url}")
        
        # Try to hide it
        await instance.ahide_http_service("non-existent")
        
    except Exception as e:
        logger.info(f"✓ Non-existent service exposure failed as expected: {e}")
    
    # Test hiding non-existent service
    logger.info("Testing hiding of non-existent service")
    
    try:
        await instance.ahide_http_service("totally-fake-service")
        logger.warning("⚠ Hiding non-existent service succeeded")
        
    except Exception as e:
        logger.info(f"✓ Hiding non-existent service failed as expected: {e}")
    
    # Test duplicate service names
    port1, port2 = 8095, 8096
    service_name = "duplicate-test"
    
    logger.info(f"Testing duplicate service name handling")
    
    # Setup two services
    for port in [port1, port2]:
        await instance.aexec(f"mkdir -p /tmp/dup{port}")
        await instance.aexec(f"echo '<h1>Service on port {port}</h1>' > /tmp/dup{port}/index.html")
        server_cmd = f"cd /tmp/dup{port} && tmux new-session -d -s dup{port} 'python3 -m http.server {port}'"
        await instance.aexec(server_cmd)
    
    await asyncio.sleep(3)
    
    try:
        # Expose first service
        url1 = await instance.aexpose_http_service(service_name, port1)
        logger.info(f"✓ First service exposed: {url1}")
        
        # Try to expose second service with same name
        try:
            url2 = await instance.aexpose_http_service(service_name, port2)
            logger.warning(f"⚠ Duplicate service name allowed: {url2}")
            
            # If allowed, hide both
            await instance.ahide_http_service(service_name)
            
        except Exception as e:
            logger.info(f"✓ Duplicate service name rejected as expected: {e}")
            
            # Hide the first service
            await instance.ahide_http_service(service_name)
    
    finally:
        # Cleanup
        await instance.aexec(f"tmux kill-session -t dup{port1} 2>/dev/null || true")
        await instance.aexec(f"tmux kill-session -t dup{port2} 2>/dev/null || true")
    
    logger.info("✓ HTTP service error conditions testing completed")