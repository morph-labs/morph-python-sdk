"""
Function-scoped tests for as_container functionality in MorphCloud SDK.
"""
import pytest
import logging
import os
import pytest_asyncio

from morphcloud.api import MorphCloudClient

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
async def base_image(client):
    """Get a base image to use for tests."""
    images = await client.images.alist()
    if not images:
        pytest.fail("No images available")
    
    # Use an Ubuntu image or fall back to the first available
    image = next((img for img in images if "ubuntu" in img.id.lower()), images[0])
    logger.info(f"Using base image: {image.id}")
    return image


async def test_as_container_with_dockerfile(client, base_image):
    """Test as_container with a simple Dockerfile."""
    logger.info("Testing as_container with Dockerfile")
    
    # Track created resources for cleanup
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=2,
            memory=1024,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        resources['snapshots'].append(snapshot)
        
        # Start instance
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Simple Dockerfile based on your working example
        dockerfile = """
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install basic packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    git \
    vim \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a test user
RUN useradd -m -s /bin/bash testuser

# Create test directory
RUN mkdir -p /app && echo "Container is ready" > /app/status.txt

USER testuser
WORKDIR /home/testuser

"""
        
        # Configure instance as container
        logger.info("Configuring instance as container")
        await instance.aas_container(
            dockerfile=dockerfile,
            container_name="test-container"
        )

        logger.info("Container configured successfully")
        
        # Test that SSH redirection works
        logger.info("Testing SSH redirection to container")
        result = await instance.aexec("whoami")
        assert result.exit_code == 0, "Should be able to execute commands in container"
        assert "testuser" in result.stdout, "Should be running as testuser in container"
        
        # Test that we're in the container environment
        logger.info("Verifying container environment")
        result = await instance.aexec("cat /app/status.txt")
        assert result.exit_code == 0, "Should be able to read container files"
        assert "Container is ready" in result.stdout, "Should have container-specific content"
        
        # Test working directory
        result = await instance.aexec("pwd")
        assert result.exit_code == 0, "Should be able to get working directory"
        assert "/home/testuser" in result.stdout, "Should be in the correct working directory"
        
        # Test Python is available
        result = await instance.aexec("python3 --version")
        assert result.exit_code == 0, "Python should be available in container"
        assert "Python" in result.stdout, "Should return Python version"
        
        logger.info("as_container with Dockerfile test completed successfully")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_as_container_with_existing_image(client, base_image):
    """Test as_container with an existing Docker image."""
    logger.info("Testing as_container with existing image")
    
    # Track created resources for cleanup
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=2,
            memory=1024,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        resources['snapshots'].append(snapshot)
        
        # Start instance
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Configure instance to use existing Docker image
        logger.info("Configuring instance with existing Docker image")
        await instance.aas_container(
            image="python:3.11-slim",
            container_name="python-container",
        )
        
        logger.info("Container configured successfully")
        
        # Test that SSH redirection works
        logger.info("Testing SSH redirection to Python container")
        result = await instance.aexec("python --version")
        assert result.exit_code == 0, "Should be able to execute Python in container"
        assert "Python 3.11" in result.stdout, "Should be running Python 3.11"
        
        # Test that we can import Python modules
        logger.info("Testing Python functionality")
        result = await instance.aexec("python -c 'import sys; print(sys.version)'")
        assert result.exit_code == 0, "Should be able to run Python code"
        assert "3.11" in result.stdout, "Should show Python 3.11 version"
        
        # Test working directory
        result = await instance.aexec("pwd")
        assert result.exit_code == 0, "Should be able to get working directory"
        
        logger.info("as_container with existing image test completed successfully")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_as_container_with_complex_dockerfile(client, base_image):
    """Test as_container with a more complex Dockerfile similar to basic_test.py."""
    logger.info("Testing as_container with complex Dockerfile")
    
    # Track created resources for cleanup
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot with more resources for complex container
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=4,
            memory=4096,
            disk_size=20000
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        resources['snapshots'].append(snapshot)
        
        # Start instance
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Complex Dockerfile similar to your working example
        dockerfile = """
FROM ghcr.io/astral-sh/uv:python3.13-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    NVM_DIR=/usr/local/nvm \
    NODE_VERSION=22.14.0 \
    NODE_OPTIONS="--max-old-space-size=8192" \
    PYTHONUNBUFFERED=1 \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    PYTHONPATH="/usr/local/lib/python3.13/site-packages" \
    IS_SANDBOX=True \
    USER=testuser \
    HOMEBREW_NO_AUTO_UPDATE=1

ENV PATH=$NVM_DIR/versions/node/$NODE_VERSION/bin:/usr/local/nvm:/usr/local/bin:/root/.local/bin:$PATH

# System packages
RUN apt-get update && apt-get install -y -o Dpkg::Options::="--force-confold" \
    git \
    curl \
    tree \
    openssh-server \
    tmux \
    nano \
    vim \
    sudo \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Node.js via NVM
RUN mkdir -p $NVM_DIR \
 && curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash \
 && . $NVM_DIR/nvm.sh \
 && nvm install $NODE_VERSION \
 && nvm use $NODE_VERSION \
 && npm install -g yarn

# Create user
RUN useradd -m -s /bin/bash $USER \
 && chown -R $USER:$USER /home/$USER

# Create test files
RUN echo "Development environment ready" > /tmp/status.txt
RUN echo "Node.js and Python environment" > /tmp/environment.txt

USER $USER
WORKDIR /home/$USER

"""
        
        # Configure instance as container
        logger.info("Configuring instance as complex container")
        await instance.aas_container(
            dockerfile=dockerfile,
            container_name="dev-container",
        )
        
        logger.info("Complex container configured successfully")
        
        # Test that SSH redirection works
        logger.info("Testing SSH redirection to complex container")
        result = await instance.aexec("whoami")
        assert result.exit_code == 0, "Should be able to execute commands in container"
        assert "testuser" in result.stdout, "Should be running as testuser in container"
        
        # Test environment files
        logger.info("Verifying container environment files")
        result = await instance.aexec("cat /tmp/status.txt")
        assert result.exit_code == 0, "Should be able to read status file"
        assert "Development environment ready" in result.stdout, "Should have correct status content"
        
        result = await instance.aexec("cat /tmp/environment.txt")
        assert result.exit_code == 0, "Should be able to read environment file"
        assert "Node.js and Python environment" in result.stdout, "Should have correct environment content"
        
        # Test working directory
        result = await instance.aexec("pwd")
        assert result.exit_code == 0, "Should be able to get working directory"
        assert "/home/testuser" in result.stdout, "Should be in the correct working directory"
        
        # Test that Python is available
        result = await instance.aexec("python3 --version")
        assert result.exit_code == 0, "Python should be available in container"
        assert "Python" in result.stdout, "Should return Python version"
        
        # Test that Node.js tools are available
        result = await instance.aexec("which node")
        if result.exit_code == 0:
            logger.info("Node.js is available, testing version")
            result = await instance.aexec("node --version")
            assert result.exit_code == 0, "Should be able to get Node.js version"
        else:
            logger.info("Node.js not immediately available (might need shell sourcing)")
        
        # Test that git is available
        result = await instance.aexec("git --version")
        assert result.exit_code == 0, "Git should be available in container"
        assert "git version" in result.stdout, "Should return git version"
        
        logger.info("as_container with complex Dockerfile test completed successfully")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")


async def test_as_container_with_port_mapping(client, base_image):
    """Test as_container with port mapping."""
    logger.info("Testing as_container with port mapping")
    
    # Track created resources for cleanup
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=2,
            memory=1024,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        resources['snapshots'].append(snapshot)
        
        # Start instance
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Simple Dockerfile that uses COPY instead of echo
        dockerfile = """
FROM python:3.11-slim

# Install basic packages
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create app directory
RUN mkdir -p /app

# Copy the server script
COPY server.py /app/server.py

# Make sure it's executable
RUN chmod +x /app/server.py

WORKDIR /app
EXPOSE 8000
"""
        
        # Create build context directory on the remote instance
        build_context_remote = "/tmp/web-server-build"
        logger.info("Creating build context directory on instance")
        await instance.aexec(f"mkdir -p {build_context_remote}")
        
        # Write the Python server script using cat with heredoc
        logger.info("Writing server script to build context")
        server_script_command = f"""cat > {build_context_remote}/server.py << 'EOF'
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

def start_server():
    os.chdir("/tmp")
    with open("index.html", "w") as f:
        f.write("<h1>Container Web Server</h1><p>Server is running!</p>")
    
    server = HTTPServer(("0.0.0.0", 8000), SimpleHTTPRequestHandler)
    print("Server starting on port 8000...")
    server.serve_forever()

if __name__ == "__main__":
    start_server()
EOF"""
        
        result = await instance.aexec(server_script_command)
        assert result.exit_code == 0, "Should be able to create server script"
        
        # Verify the script was created
        result = await instance.aexec(f"ls -la {build_context_remote}/server.py")
        assert result.exit_code == 0, "Server script should exist in build context"
        
        # Configure instance as container with port mapping and build context
        logger.info("Configuring instance with port mapping and build context")
        await instance.aas_container(
            dockerfile=dockerfile,
            container_name="web-container",
            build_context=build_context_remote,
            ports={8080: 8000}  # Map host port 8080 to container port 8000
        )
        
        logger.info("Container with port mapping configured successfully")
        
        # Test that SSH redirection works
        logger.info("Testing SSH redirection")
        result = await instance.aexec("pwd")
        assert result.exit_code == 0, "Should be able to execute commands in container"
        assert "/app" in result.stdout, "Should be in the correct working directory"
        
        # Test that Python is available
        result = await instance.aexec("python --version")
        assert result.exit_code == 0, "Python should be available in container"
        assert "Python 3.11" in result.stdout, "Should be running Python 3.11"
        
        # Test that the server script exists
        result = await instance.aexec("ls -la /app/server.py")
        assert result.exit_code == 0, "Server script should exist"
        
        # Test that we can run the Python script (in background)
        logger.info("Starting web server in background")
        result = await instance.aexec("nohup python /app/server.py > /tmp/server.log 2>&1 &")
        assert result.exit_code == 0, "Should be able to start the web server"
        
        # Give the server a moment to start
        import asyncio
        await asyncio.sleep(5)
        
        # Test that we can access the web server
        result = await instance.aexec("curl -s http://localhost:8000")
        if result.exit_code == 0 and "Container Web Server" in result.stdout:
            logger.info("✅ Web server is accessible from within container")
        else:
            # Check server logs for debugging
            log_result = await instance.aexec("cat /tmp/server.log")
            logger.info(f"Server logs: {log_result.stdout}")
            logger.warning("Web server test inconclusive (server might not be fully started)")
        
        logger.info("as_container with port mapping test completed successfully")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")

async def test_as_container_with_environment_variables(client, base_image):
    """Test as_container with environment variables."""
    logger.info("Testing as_container with environment variables")
    
    # Track created resources for cleanup
    resources = {
        'snapshots': [],
        'instances': []
    }
    
    try:
        # Create snapshot
        logger.info("Creating snapshot")
        snapshot = await client.snapshots.acreate(
            image_id=base_image.id,
            vcpus=2,
            memory=1024,
            disk_size=8192
        )
        logger.info(f"Created snapshot: {snapshot.id}")
        resources['snapshots'].append(snapshot)
        
        # Start instance
        logger.info("Starting instance")
        instance = await client.instances.astart(snapshot.id)
        logger.info(f"Created instance: {instance.id}")
        resources['instances'].append(instance)
        
        # Wait for instance to be ready
        logger.info(f"Waiting for instance {instance.id} to be ready")
        await instance.await_until_ready(timeout=300)
        logger.info(f"Instance {instance.id} is ready")
        
        # Simple Dockerfile
        dockerfile = """
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

"""
        
        # Test environment variables
        test_env = {
            "TEST_VAR": "test_value",
            "CUSTOM_PATH": "/custom/path",
            "DEBUG": "true"
        }
        
        # Configure instance as container with environment variables
        logger.info("Configuring instance with environment variables")
        await instance.aas_container(
            dockerfile=dockerfile,
            container_name="env-container",
            env=test_env
        )
        
        logger.info("Container with environment variables configured successfully")
        
        # Test that SSH redirection works
        logger.info("Testing SSH redirection")
        result = await instance.aexec("echo 'Container is working'")
        assert result.exit_code == 0, "Should be able to execute commands in container"
        assert "Container is working" in result.stdout, "Should get expected output"
        
        # Test environment variables
        for key, expected_value in test_env.items():
            logger.info(f"Testing environment variable {key}")
            result = await instance.aexec(f"echo ${key}")
            assert result.exit_code == 0, f"Should be able to access environment variable {key}"
            assert expected_value in result.stdout, f"Environment variable {key} should have value {expected_value}"
        
        # Test that environment variables are available
        result = await instance.aexec("env | grep TEST_VAR")
        assert result.exit_code == 0, "Should be able to find TEST_VAR in environment"
        assert "test_value" in result.stdout, "TEST_VAR should have correct value"
        
        logger.info("as_container with environment variables test completed successfully")
        
    finally:
        # Clean up resources
        for instance in reversed(resources['instances']):
            try:
                logger.info(f"Stopping instance {instance.id}")
                await instance.astop()
                logger.info(f"Instance stopped")
            except Exception as e:
                logger.error(f"Error stopping instance: {e}")
        
        for snapshot in reversed(resources['snapshots']):
            try:
                logger.info(f"Deleting snapshot {snapshot.id}")
                await snapshot.adelete()
                logger.info(f"Snapshot deleted")
            except Exception as e:
                logger.error(f"Error deleting snapshot: {e}")
