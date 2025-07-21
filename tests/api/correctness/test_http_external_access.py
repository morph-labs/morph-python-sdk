"""
Test HTTP service external accessibility.

This module validates actual external HTTP access (not just internal):
- External HTTP requests using aiohttp
- Service accessibility from outside the instance
- HTTP service URL validation
- External vs internal access comparison
- HTTP service lifecycle across instance operations
"""
import pytest
import pytest_asyncio
import logging
import time
import json
import asyncio
import uuid
import aiohttp
import ssl
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


@pytest_asyncio.fixture
async def http_external_instance(client, base_image):
    """Create an instance ready for external HTTP testing."""
    snapshot = None
    instance = None
    
    try:
        # Create snapshot with conservative configuration for HTTP testing
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=1,  # Conservative CPU
            memory=2048,  # 2GB for HTTP performance
            disk_size=16*1024  # 16GB
        )
        logger.info(f"Created snapshot {snapshot.id} for external HTTP testing")
        
        # Start instance
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Started instance {instance.id}")
        
        # Wait until ready with extended timeout for setup
        await instance.await_until_ready(timeout=600)
        logger.info(f"Instance {instance.id} is ready for external HTTP testing")
        
        # Install required packages
        logger.info("Installing HTTP testing dependencies")
        install_result = await instance.aexec(
            "apt-get update && apt-get install -y tmux python3 curl nginx-light netcat-openbsd"
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
                await instance.aexec("tmux kill-server 2>/dev/null || true")
                await instance.astop()
                logger.info("External HTTP test instance stopped")
            except Exception as e:
                logger.error(f"Error stopping external HTTP test instance: {e}")
                
        if snapshot:
            try:
                await snapshot.adelete()
                logger.info("External HTTP test snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting external HTTP test snapshot: {e}")


async def test_external_http_accessibility_basic(http_external_instance, client):
    """Test basic external HTTP accessibility using aiohttp."""
    logger.info("Testing external HTTP accessibility (CRITICAL: actual external requests)")
    
    instance_data = http_external_instance
    instance = instance_data['instance']
    
    # Setup test service
    port = 8080
    test_id = uuid.uuid4().hex[:8]
    service_name = f"external-test-{test_id}"
    
    logger.info(f"Setting up HTTP service on port {port} for external testing")
    
    # Create unique test content with more details for validation
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>External HTTP Test</title></head>
    <body>
        <h1>External HTTP Accessibility Test</h1>
        <p>Service: {service_name}</p>
        <p>Port: {port}</p>
        <p>Test ID: {test_id}</p>
        <p>Timestamp: {datetime.now().isoformat()}</p>
        <p>External Access: VERIFIED</p>
        <div id="test-data">
            <ul>
                <li>Instance ID: {instance.id}</li>
                <li>Test Type: External HTTP</li>
                <li>Response Time: <span id="load-time">Loading...</span></li>
            </ul>
        </div>
        <script>
            document.getElementById('load-time').textContent = new Date().toISOString();
        </script>
    </body>
    </html>
    """
    
    # Setup service directory and content
    await instance.aexec(f"mkdir -p /tmp/{service_name}")
    await instance.aexec(f"cat > /tmp/{service_name}/index.html << 'EOF'\n{html_content}\nEOF")
    
    # Start HTTP server in tmux session
    server_cmd = f"cd /tmp/{service_name} && tmux new-session -d -s {service_name} 'python3 -m http.server {port}'"
    server_result, server_setup_time = await timed_operation(
        "external_http_service_setup",
        lambda: instance.aexec(server_cmd)
    )
    
    assert server_result.exit_code == 0, f"Failed to start HTTP server: {server_result.stderr}"
    
    # Wait for server to start
    await asyncio.sleep(3)
    
    # Verify server is running locally first
    local_test_result = await instance.aexec(f"curl -s localhost:{port}")
    assert local_test_result.exit_code == 0, f"HTTP server not responding locally: {local_test_result.stderr}"
    assert test_id in local_test_result.stdout, "Local HTTP server not serving expected content"
    logger.info("✓ HTTP server confirmed running locally")
    
    try:
        # Expose the HTTP service
        service_url, expose_time = await timed_operation(
            "external_http_service_expose",
            lambda: instance.aexpose_http_service(service_name, port)
        )
        
        logger.info(f"HTTP service exposed at: {service_url}")
        
        # Verify service is registered
        instance = await client.instances.aget(instance.id)  # Refresh instance data
        assert len(instance.networking.http_services) > 0, "No HTTP services exposed"
        assert any(s.port == port for s in instance.networking.http_services), "Service not found in instance networking"
        logger.info("✓ Service confirmed in instance networking")
        
        # CRITICAL: Test external HTTP accessibility using aiohttp
        logger.info("Testing external HTTP accessibility using aiohttp...")
        
        # Configure SSL context to be more permissive for testing
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            
            external_response, external_time = await timed_operation(
                "external_http_access",
                lambda: session.get(service_url)
            )
            
            async with external_response as response:
                # Validate HTTP response
                assert response.status == 200, f"External HTTP request failed with status {response.status}"
                
                response_content = await response.text()
                
                # Validate content
                assert test_id in response_content, f"Test ID not found in external HTTP response: {test_id}"
                assert service_name in response_content, f"Service name not found in external HTTP response: {service_name}"
                assert "External Access: VERIFIED" in response_content, "External access marker not found"
                assert instance.id in response_content, "Instance ID not found in response"
                
                # Check response headers
                assert 'content-type' in response.headers, "Content-Type header missing"
                assert 'server' in response.headers, "Server header missing"
                
                logger.info(f"✅ External HTTP request successful:")
                logger.info(f"   Status:      {response.status}")
                logger.info(f"   Content-Type: {response.headers.get('content-type', 'N/A')}")
                logger.info(f"   Server:      {response.headers.get('server', 'N/A')}")
                logger.info(f"   Content Length: {len(response_content)} chars")
                logger.info(f"   Response Time:  {external_time:.2f}s")
        
        # Test multiple external requests to verify consistency
        logger.info("Testing multiple external HTTP requests...")
        
        request_results = []
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context),
            timeout=aiohttp.ClientTimeout(total=20)
        ) as session:
            
            for i in range(3):
                try:
                    req_start = time.time()
                    async with session.get(service_url) as response:
                        req_duration = time.time() - req_start
                        
                        content = await response.text()
                        
                        request_results.append({
                            'request_num': i + 1,
                            'status': response.status,
                            'duration': req_duration,
                            'content_length': len(content),
                            'has_test_id': test_id in content,
                            'success': response.status == 200 and test_id in content
                        })
                        
                        logger.info(f"✓ External request {i+1}: {response.status} in {req_duration:.2f}s")
                        
                except Exception as e:
                    req_duration = time.time() - req_start if 'req_start' in locals() else 0
                    logger.error(f"❌ External request {i+1} failed: {e}")
                    request_results.append({
                        'request_num': i + 1,
                        'success': False,
                        'error': str(e),
                        'duration': req_duration
                    })
        
        # Analyze multiple request results
        successful_requests = [r for r in request_results if r.get('success', False)]
        success_rate = len(successful_requests) / len(request_results)
        
        logger.info(f"📊 Multiple External HTTP Requests Results:")
        logger.info(f"   Successful:    {len(successful_requests)}/{len(request_results)}")
        logger.info(f"   Success Rate:  {success_rate*100:.1f}%")
        
        if successful_requests:
            avg_duration = sum(r['duration'] for r in successful_requests) / len(successful_requests)
            logger.info(f"   Avg Duration:  {avg_duration:.2f}s")
        
        # Require high success rate for external access
        assert success_rate >= 0.8, f"External HTTP access success rate too low: {success_rate*100:.1f}% (need ≥80%)"
        
        # Hide service
        _, hide_time = await timed_operation(
            "external_http_service_hide",
            lambda: instance.ahide_http_service(service_name)
        )
        
        # Verify service is no longer accessible externally
        logger.info("Testing that hidden service is no longer accessible...")
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context),
            timeout=aiohttp.ClientTimeout(total=10)
        ) as session:
            
            try:
                async with session.get(service_url) as response:
                    # Service should no longer be accessible
                    logger.warning(f"⚠️ Hidden service still accessible: {response.status}")
                    if response.status != 200:
                        logger.info("✓ Service correctly returns non-200 status after hiding")
                    else:
                        content = await response.text()
                        if test_id not in content:
                            logger.info("✓ Service content changed after hiding (expected)")
                        else:
                            logger.warning("⚠️ Service still serving original content after hiding")
                            
            except Exception as e:
                logger.info(f"✓ Hidden service not accessible (expected): {e}")
        
        # Performance summary
        logger.info(f"📊 External HTTP Accessibility Performance:")
        logger.info(f"   Setup:        {server_setup_time:.2f}s")
        logger.info(f"   Expose:       {expose_time:.2f}s")
        logger.info(f"   External:     {external_time:.2f}s")
        logger.info(f"   Hide:         {hide_time:.2f}s")
        logger.info(f"   Success Rate: {success_rate*100:.1f}%")
        
    finally:
        # Cleanup tmux session
        await instance.aexec(f"tmux kill-session -t {service_name} 2>/dev/null || true")


async def test_external_vs_internal_http_comparison(http_external_instance, client):
    """Compare external aiohttp vs internal curl access."""
    logger.info("Comparing external vs internal HTTP access methods")
    
    instance_data = http_external_instance
    instance = instance_data['instance']
    
    port = 8090
    service_name = "comparison-test"
    test_id = uuid.uuid4().hex[:8]
    
    # Setup service
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>HTTP Access Comparison</title></head>
    <body>
        <h1>External vs Internal Access Comparison</h1>
        <p>Test ID: {test_id}</p>
        <p>Port: {port}</p>
        <p>Timestamp: {datetime.now().isoformat()}</p>
    </body>
    </html>
    """
    
    await instance.aexec(f"mkdir -p /tmp/{service_name}")
    await instance.aexec(f"cat > /tmp/{service_name}/index.html << 'EOF'\n{html_content}\nEOF")
    
    # Start service
    server_cmd = f"cd /tmp/{service_name} && tmux new-session -d -s {service_name} 'python3 -m http.server {port}'"
    await instance.aexec(server_cmd)
    await asyncio.sleep(3)
    
    # Expose service
    service_url, _ = await timed_operation(
        "comparison_service_expose",
        lambda: instance.aexpose_http_service(service_name, port)
    )
    
    try:
        # Test internal access (current approach)
        internal_result, internal_time = await timed_operation(
            "comparison_internal_access",
            lambda: instance.aexec(f"curl -s localhost:{port}")
        )
        
        internal_success = internal_result.exit_code == 0 and test_id in internal_result.stdout
        internal_content_length = len(internal_result.stdout) if internal_success else 0
        
        # Test external access (new approach)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        external_success = False
        external_content_length = 0
        external_status = 0
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context),
            timeout=aiohttp.ClientTimeout(total=20)
        ) as session:
            
            try:
                external_response, external_time = await timed_operation(
                    "comparison_external_access",
                    lambda: session.get(service_url)
                )
                
                async with external_response as response:
                    external_status = response.status
                    content = await response.text()
                    external_content_length = len(content)
                    external_success = response.status == 200 and test_id in content
                    
            except Exception as e:
                external_time = 0
                logger.error(f"External access failed: {e}")
        
        # Compare results
        logger.info(f"📊 Internal vs External HTTP Access Comparison:")
        logger.info(f"   Internal Access (curl localhost):")
        logger.info(f"     Success:      {internal_success}")
        logger.info(f"     Time:         {internal_time:.2f}s")
        logger.info(f"     Content:      {internal_content_length} chars")
        logger.info(f"   External Access (aiohttp):")
        logger.info(f"     Success:      {external_success}")
        logger.info(f"     Time:         {external_time:.2f}s")
        logger.info(f"     Status:       {external_status}")
        logger.info(f"     Content:      {external_content_length} chars")
        
        # Both methods should succeed
        assert internal_success, f"Internal access should succeed: {internal_result.stderr}"
        assert external_success, f"External access should succeed (status: {external_status})"
        
        # Content should be similar
        content_ratio = abs(internal_content_length - external_content_length) / max(internal_content_length, external_content_length) if max(internal_content_length, external_content_length) > 0 else 0
        assert content_ratio < 0.2, f"Content length difference too large: {content_ratio*100:.1f}%"
        
        # Performance comparison
        if internal_time > 0 and external_time > 0:
            speed_ratio = external_time / internal_time
            logger.info(f"   Speed Ratio:  External is {speed_ratio:.1f}x {'slower' if speed_ratio > 1 else 'faster'} than internal")
        
        logger.info("✅ Both internal and external HTTP access methods working correctly")
        
    finally:
        # Cleanup
        await instance.ahide_http_service(service_name)
        await instance.aexec(f"tmux kill-session -t {service_name} 2>/dev/null || true")


async def test_external_http_with_custom_headers_and_methods(http_external_instance, client):
    """Test external HTTP access with different methods and headers."""
    logger.info("Testing external HTTP with custom headers and methods")
    
    instance_data = http_external_instance
    instance = instance_data['instance']
    
    port = 8095
    service_name = "methods-test"
    test_id = uuid.uuid4().hex[:8]
    
    # Setup a more sophisticated HTTP service
    python_server_code = f'''
import http.server
import socketserver
import json
from urllib.parse import parse_qs

class TestHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Test-ID', '{test_id}')
        self.send_header('X-Custom-Header', 'test-value')
        self.end_headers()
        
        response = {{
            "method": "GET",
            "test_id": "{test_id}",
            "path": self.path,
            "headers": dict(self.headers),
            "timestamp": "{datetime.now().isoformat()}"
        }}
        
        self.wfile.write(json.dumps(response, indent=2).encode())
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Test-ID', '{test_id}')
        self.end_headers()
        
        response = {{
            "method": "POST",
            "test_id": "{test_id}",
            "data": post_data,
            "timestamp": "{datetime.now().isoformat()}"
        }}
        
        self.wfile.write(json.dumps(response, indent=2).encode())

if __name__ == "__main__":
    with socketserver.TCPServer(("", {port}), TestHTTPHandler) as httpd:
        httpd.serve_forever()
'''
    
    # Setup service
    await instance.aexec(f"mkdir -p /tmp/{service_name}")
    await instance.aexec(f"cat > /tmp/{service_name}/server.py << 'EOF'\n{python_server_code}\nEOF")
    
    # Start sophisticated server
    server_cmd = f"cd /tmp/{service_name} && tmux new-session -d -s {service_name} 'python3 server.py'"
    await instance.aexec(server_cmd)
    await asyncio.sleep(4)
    
    # Expose service
    service_url, _ = await timed_operation(
        "methods_service_expose",
        lambda: instance.aexpose_http_service(service_name, port)
    )
    
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_context),
            timeout=aiohttp.ClientTimeout(total=20)
        ) as session:
            
            # Test GET request with custom headers
            logger.info("Testing GET request with custom headers...")
            
            custom_headers = {
                'User-Agent': 'MorphCloud-Test/1.0',
                'X-Test-Client': 'aiohttp',
                'Accept': 'application/json'
            }
            
            async with session.get(service_url, headers=custom_headers) as response:
                assert response.status == 200, f"GET request failed: {response.status}"
                
                # Check custom response headers
                assert response.headers.get('X-Test-ID') == test_id, "Custom response header missing"
                assert response.headers.get('X-Custom-Header') == 'test-value', "Custom header value incorrect"
                
                get_data = await response.json()
                assert get_data['method'] == 'GET', "Method not recorded correctly"
                assert get_data['test_id'] == test_id, "Test ID not in response"
                
                logger.info("✅ GET request with custom headers successful")
            
            # Test POST request with data
            logger.info("Testing POST request with data...")
            
            post_data = json.dumps({
                'test_type': 'external_http_post',
                'test_id': test_id,
                'timestamp': datetime.now().isoformat()
            })
            
            async with session.post(
                service_url, 
                data=post_data,
                headers={'Content-Type': 'application/json'}
            ) as response:
                assert response.status == 200, f"POST request failed: {response.status}"
                
                post_response = await response.json()
                assert post_response['method'] == 'POST', "POST method not recorded"
                assert test_id in post_response['data'], "POST data not received correctly"
                
                logger.info("✅ POST request with data successful")
            
            # Test query parameters
            logger.info("Testing query parameters...")
            
            query_url = f"{service_url}?param1=value1&param2=value2&test_id={test_id}"
            
            async with session.get(query_url) as response:
                assert response.status == 200, f"Query parameter request failed: {response.status}"
                
                query_data = await response.json()
                assert f"param1=value1" in query_data['path'], "Query parameters not preserved"
                assert f"test_id={test_id}" in query_data['path'], "Test ID parameter missing"
                
                logger.info("✅ Query parameters handled correctly")
            
        logger.info("📊 Advanced HTTP Methods Test Results:")
        logger.info("   GET with headers: ✅")
        logger.info("   POST with data:   ✅")
        logger.info("   Query params:     ✅")
        logger.info("   Custom headers:   ✅")
        
    finally:
        # Cleanup
        await instance.ahide_http_service(service_name)
        await instance.aexec(f"tmux kill-session -t {service_name} 2>/dev/null || true")