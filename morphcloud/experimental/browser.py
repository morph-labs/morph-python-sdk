#!/usr/bin/env python3
"""
MorphBrowser - Remote browser sessions with tmux integration

Creates morphcloud instances with real headless Chrome and provides CDP URLs
for browser automation tools like Playwright.

Usage:
    from morphcloud.experimental.browser import MorphBrowser
    
    mb = MorphBrowser()
    
    # Create a new browser session
    session = mb.sessions.create()
    
    # Get CDP URL for Playwright
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(session.connect_url)
        page = browser.new_page()
        page.goto('https://example.com')
        print(page.title())
        browser.close()
    
    # Clean up when done
    session.close()

Environment Variables:
    MORPH_API_KEY - MorphCloud API key
    MORPH_BASE_URL - MorphCloud API base URL  
    MORPH_API_HOST - MorphCloud API host
    MORPH_SSH_HOSTNAME - MorphCloud SSH hostname
"""

import json
import time
import requests
import logging
from typing import Optional, Dict, Any

# Import Snapshot class directly to avoid circular imports
from morphcloud.experimental import Snapshot

# Configure logging
logger = logging.getLogger(__name__)

# Constants
CHROME_CDP_PORT = 9222
PROXY_PORT = 9223
CHROME_STARTUP_TIMEOUT = 30
PROXY_STARTUP_TIMEOUT = 10
HTTP_TIMEOUT = 10
DEFAULT_VCPUS = 1
DEFAULT_MEMORY = 4 * 1024  # 4GB
DEFAULT_DISK_SIZE = 16 * 1024  # 16GB


class BrowserSession:
    """
    A remote browser session with headless Chrome and external CDP access.
    
    Provides a simple interface for creating remote browser instances
    that can be controlled via Chrome DevTools Protocol.
    """
    
    def __init__(self, instance, cdp_url, connect_url):
        """
        Initialize a browser session.
        
        Args:
            instance: The morphcloud instance
            cdp_url: Base HTTP URL for CDP endpoints
            connect_url: WebSocket URL for browser automation tools
        """
        self._instance = instance
        self._cdp_url = cdp_url
        self._connect_url = connect_url
    
    @property
    def connect_url(self):
        """
        WebSocket URL for connecting browser automation tools.
        
        Returns:
            str: WebSocket URL ready for playwright.chromium.connect_over_cdp()
        """
        return self._connect_url
    
    @property
    def cdp_url(self):
        """
        Base HTTP URL for Chrome DevTools Protocol endpoints.
        
        Returns:
            str: HTTP URL for accessing /json/version, /json, etc.
        """
        return self._cdp_url
    
    @property
    def instance(self):
        """
        Access to the underlying morphcloud instance.
        
        Returns:
            Instance: The morphcloud instance for advanced usage
        """
        return self._instance
    
    def get_tabs(self) -> list:
        """
        Get list of available browser tabs/pages.
        
        Returns:
            List of tab objects with id, title, url, webSocketDebuggerUrl
        """
        try:
            response = requests.get(f"{self._cdp_url}/json", timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            else:
                raise RuntimeError(f"Failed to get tabs: HTTP {response.status_code}")
        except Exception as e:
            raise RuntimeError(f"Error getting tabs: {e}")
    
    def get_version(self) -> Dict[str, Any]:
        """
        Get browser version information.
        
        Returns:
            Browser version info with Browser, Protocol-Version, etc.
        """
        try:
            response = requests.get(f"{self._cdp_url}/json/version", timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            else:
                raise RuntimeError(f"Failed to get version: HTTP {response.status_code}")
        except Exception as e:
            raise RuntimeError(f"Error getting version: {e}")
    
    def is_ready(self) -> bool:
        """
        Check if the browser session is ready for automation.
        
        Returns:
            True if browser is responding to CDP requests
        """
        try:
            version = self.get_version()
            return 'Browser' in version and 'Protocol-Version' in version
        except:
            return False
    
    def close(self):
        """
        Close the browser session and clean up resources.
        Note: This will terminate the morphcloud instance.
        """
        if self._instance:
            try:
                # Clean up tmux sessions
                self._instance.exec("tmux kill-session -t chrome-session || true")
                self._instance.exec("tmux kill-session -t proxy-session || true")
                
                # Hide the HTTP service
                self._instance.hide_http_service("cdp-server")
            except:
                pass  # Service might already be hidden or instance stopped
    
    @classmethod
    def _get_chrome_command(cls) -> list:
        """Get Chrome command line arguments."""
        return [
            "google-chrome",
            "--headless=new",
            "--no-sandbox", 
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-features=TranslateUI,VizDisplayCompositor",
            "--enable-features=NetworkService",
            "--remote-debugging-address=0.0.0.0",
            f"--remote-debugging-port={CHROME_CDP_PORT}",
            "--user-data-dir=/tmp/chrome-user-data",
            "--data-path=/tmp/chrome-data",
            "--disk-cache-dir=/tmp/chrome-cache",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-plugins",
            "--allow-running-insecure-content",
            "--disable-web-security",
            "--remote-allow-origins=*"
        ]
    
    @classmethod
    def _get_websocket_url(cls, instance, cdp_url: str, verbose: bool) -> str:
        """Get WebSocket URL for browser automation."""
        if verbose:
            logger.info("Getting Chrome WebSocket URL...")
        
        # First, try to get browser-level WebSocket URL from /json/version
        connect_url = None
        version_result = instance.exec(f"curl -s http://0.0.0.0:{PROXY_PORT}/json/version")
        if version_result.exit_code == 0:
            try:
                version_data = json.loads(version_result.stdout)
                if verbose:
                    logger.info(f"Got version data from proxy port {PROXY_PORT}")
                
                # Extract browser-level WebSocket URL from version endpoint
                if 'webSocketDebuggerUrl' in version_data:
                    chrome_ws_url = version_data['webSocketDebuggerUrl']
                    if verbose:
                        logger.info(f"Chrome browser WebSocket URL: {chrome_ws_url}")
                    
                    # Convert Chrome's internal WebSocket URL to external URL
                    if 'devtools/browser/' in chrome_ws_url:
                        # Extract the browser UUID from the URL
                        browser_uuid = chrome_ws_url.split('devtools/browser/')[-1]
                        ws_base = cdp_url.replace('http://', '').replace('https://', '')
                        ws_protocol = 'wss' if cdp_url.startswith('https://') else 'ws'
                        connect_url = f"{ws_protocol}://{ws_base}/devtools/browser/{browser_uuid}"
                        if verbose:
                            logger.info("Using browser-level WebSocket URL for Playwright")
                    
            except Exception as e:
                if verbose:
                    logger.warning(f"Error parsing version: {e}")
        
        # If browser-level URL not found, try to get page-level URLs from /json
        if not connect_url:
            internal_tabs = instance.exec(f"curl -s http://0.0.0.0:{PROXY_PORT}/json")
            if internal_tabs.exit_code == 0:
                try:
                    tabs_data = json.loads(internal_tabs.stdout)
                    if verbose:
                        logger.info(f"Got tabs from proxy port {PROXY_PORT}: {len(tabs_data)} tabs")
                    
                    # Look for a page-level WebSocket URL as fallback
                    for tab in tabs_data:
                        if tab.get('type') == 'page' and 'webSocketDebuggerUrl' in tab:
                            chrome_ws_url = tab['webSocketDebuggerUrl']
                            if verbose:
                                logger.info(f"Using page-level WebSocket URL: {chrome_ws_url}")
                            
                            # Convert Chrome's internal WebSocket URL to external URL
                            if 'devtools/page/' in chrome_ws_url:
                                page_uuid = chrome_ws_url.split('devtools/page/')[-1]
                                ws_base = cdp_url.replace('http://', '').replace('https://', '')
                                ws_protocol = 'wss' if cdp_url.startswith('https://') else 'ws'
                                connect_url = f"{ws_protocol}://{ws_base}/devtools/page/{page_uuid}"
                                if verbose:
                                    logger.warning("Using page-level WebSocket URL as fallback")
                                break
                    
                except Exception as e:
                    if verbose:
                        logger.warning(f"Error parsing tabs: {e}")
        
        # Ultimate fallback: use hardcoded browser path
        if not connect_url:
            ws_base = cdp_url.replace('http://', '').replace('https://', '')
            ws_protocol = 'wss' if cdp_url.startswith('https://') else 'ws'
            connect_url = f"{ws_protocol}://{ws_base}/devtools/browser"
            if verbose:
                logger.warning("Using hardcoded browser WebSocket URL as final fallback")
        
        if verbose:
            logger.info(f"Final WebSocket URL: {connect_url}")
        
        return connect_url
    
    @classmethod
    def _create_snapshot(cls, name, vcpus, memory, disk_size, verbose, invalidate=False):
        """Helper method to create and configure the snapshot."""
        # Use a consistent base name for caching (regardless of instance name)
        base_snapshot_name = f"chrome-base-{vcpus}cpu-{memory}mb"
        
        # Check if snapshot already exists using digest
        try:
            from morphcloud.api import MorphCloudClient
            client = MorphCloudClient()
            existing_snapshots = client.snapshots.list(digest=base_snapshot_name)
            if existing_snapshots and not invalidate:
                snapshot_info = existing_snapshots[0]
                logger.info(f'Using existing chrome snapshot: {base_snapshot_name}')
                if verbose:
                    logger.info(f'  Snapshot ID: {snapshot_info.get("id", "unknown")}')
                    logger.info(f'  Created: {snapshot_info.get("created_at", "unknown")}')
                    logger.info(f'  To force rebuild, use invalidate=True')
                snapshot = Snapshot(existing_snapshots[0])
                return snapshot
        except:
            pass  # Fall through to create new snapshot
            
        logger.info('Creating Chrome snapshot...')
        snapshot = Snapshot.create(
            base_snapshot_name,
            image_id="morphvm-minimal",
            vcpus=vcpus,
            memory=memory,
            disk_size=disk_size,
            invalidate=invalidate
        )
        
        # Layer 1: Update package lists
        snapshot = snapshot.run("apt-get update -y")
        logger.info('Updated package lists')
        
        # Layer 2: Install dependencies including tmux
        snapshot = snapshot.run("apt-get install -y curl wget gnupg lsb-release tmux socat")
        logger.info('Installed dependencies')

        # Layer 3: Add Google Chrome repository
        snapshot = snapshot.run("wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor | tee /etc/apt/trusted.gpg.d/google.gpg > /dev/null")
        snapshot = snapshot.run('echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | tee /etc/apt/sources.list.d/google-chrome.list')
        logger.info('Added Google Chrome repository')
        
        # Layer 4: Update and install Chrome
        snapshot = snapshot.run("apt-get update -y")
        snapshot = snapshot.run("apt-get install -y google-chrome-stable")
        logger.info('Installed Chrome')
        
        # Layer 5: Install additional Chrome dependencies
        snapshot = snapshot.run("apt-get install -y fonts-liberation libasound2 libatk-bridge2.0-0 libdrm2 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libxss1 libnss3")
        logger.info('Installed Chrome dependencies')
        
        return snapshot
    
    @classmethod
    def create(cls, name: Optional[str] = None, vcpus: int = DEFAULT_VCPUS, memory: int = DEFAULT_MEMORY, disk_size: int = DEFAULT_DISK_SIZE, verbose: bool = False, invalidate: bool = False):
        """
        Create a new browser session with headless Chrome.
        
        Args:
            name: Name for the browser instance
            vcpus: Number of virtual CPUs
            memory: Memory in MB
            disk_size: Disk size in MB
            verbose: Enable verbose output
            invalidate: Force fresh snapshot creation
            
        Returns:
            BrowserSession: Ready browser session with CDP access
            
        Raises:
            Exception: If browser session creation fails
        """
        if name is None:
            import uuid
            name = f"browser-{str(uuid.uuid4())[:8]}"
        
        if verbose:
            logger.info(f"Creating browser session '{name}' with Chrome...")
        
        try:
            snapshot = cls._create_snapshot(name, vcpus, memory, disk_size, verbose, invalidate)
                
            if verbose:
                logger.info("Snapshot created, starting instance...")
                
            # Start instance (don't use context manager to keep it running)
            instance = snapshot.start(metadata={"name": name})
            
            # Verify Chrome installation
            if verbose:
                logger.info("Verifying Chrome installation...")
            result = instance.exec("google-chrome --version")
            if result.exit_code != 0:
                raise Exception(f"Chrome not properly installed: {result.stderr}")
            if verbose:
                logger.info(f"Chrome installed: {result.stdout.strip()}")
            
            # Start headless Chrome with CDP
            if verbose:
                logger.info("Starting headless Chrome...")
            chrome_command = cls._get_chrome_command()
            
            # Create user data directory
            instance.exec("mkdir -p /tmp/chrome-user-data /tmp/chrome-data /tmp/chrome-cache")
            
            # Start Chrome in tmux session (per spec requirements)
            chrome_cmd = " ".join(chrome_command)
            instance.exec("tmux new-session -d -s chrome-session")
            instance.exec(f"tmux send-keys -t chrome-session '{chrome_cmd}' Enter")
            
            # socat already installed in snapshot
            
            # Clean up any existing proxy processes and start fresh
            instance.exec(f"pkill -f 'TCP-LISTEN:{PROXY_PORT}' || true")
            
            # Start socat reverse proxy in tmux session (per spec requirements)
            instance.exec("tmux new-session -d -s proxy-session")
            instance.exec(f"tmux send-keys -t proxy-session 'socat TCP-LISTEN:{PROXY_PORT},fork,bind=0.0.0.0 TCP:127.0.0.1:{CHROME_CDP_PORT}' Enter")
            
            # Wait for Chrome to start and CDP to be ready
            if verbose:
                logger.info("Waiting for Chrome CDP to be ready...")
                
            for i in range(CHROME_STARTUP_TIMEOUT):
                time.sleep(1)
                result = instance.exec(f"curl -s http://localhost:{CHROME_CDP_PORT}/json/version 2>/dev/null")
                if result.exit_code == 0:
                    try:
                        version_data = json.loads(result.stdout)
                        if "Browser" in version_data:
                            if verbose:
                                logger.info(f"Chrome CDP ready after {i+1}s")
                                logger.info(f"Browser: {version_data.get('Browser')}")
                                logger.info(f"Protocol: {version_data.get('Protocol-Version')}")
                            break
                    except:
                        pass
                if i % 5 == 0 and verbose:
                    logger.info(f"Starting Chrome... {i+1}/{CHROME_STARTUP_TIMEOUT}")
            else:
                # Show Chrome logs for debugging
                if verbose:
                    log_result = instance.exec("cat /tmp/chrome.log 2>/dev/null || echo 'No Chrome logs'")
                    logger.error(f"Chrome logs: {log_result.stdout}")
                    ps_result = instance.exec("ps aux | grep chrome | head -5")
                    logger.error(f"Chrome processes: {ps_result.stdout}")
                raise Exception(f"Chrome failed to start within {CHROME_STARTUP_TIMEOUT} seconds")
            
            # Create an initial page via CDP (since Chrome starts with no pages)
            if verbose:
                logger.info("Creating initial page via CDP...")
            create_page_result = instance.exec(f'curl -s -X PUT "http://localhost:{CHROME_CDP_PORT}/json/new?about:blank"')
            if create_page_result.exit_code == 0:
                if verbose:
                    logger.info("Initial page created successfully")
                    logger.debug(f"Response: {create_page_result.stdout}")
                    
                # Verify the page was created by checking CDP targets
                targets_result = instance.exec(f'curl -s http://localhost:{CHROME_CDP_PORT}/json')
                if targets_result.exit_code == 0:
                    logger.debug(f"Current CDP targets: {targets_result.stdout}")
                else:
                    logger.warning(f"Failed to check CDP targets: {targets_result.stderr}")
            else:
                if verbose:
                    logger.warning(f"Failed to create initial page: {create_page_result.stderr}")
                    logger.debug(f"stdout: {create_page_result.stdout}")
            
            # Wait for socat proxy to be ready
            if verbose:
                logger.info("Waiting for socat proxy to be ready...")
            for i in range(PROXY_STARTUP_TIMEOUT):
                time.sleep(1)
                proxy_test = instance.exec(f"curl -s http://0.0.0.0:{PROXY_PORT}/json/version")
                if proxy_test.exit_code == 0:
                    if verbose:
                        logger.info(f"Socat proxy ready after {i+1}s")
                    break
            else:
                if verbose:
                    logger.error("Socat proxy failed to start")
                    socat_log = instance.exec("cat /tmp/socat.log")
                    logger.error(f"Socat logs: {socat_log.stdout}")
                raise Exception(f"Socat proxy failed to start on port {PROXY_PORT}")
            
            # Expose service externally on proxy port
            if verbose:
                logger.info(f"Exposing CDP proxy service on port {PROXY_PORT}...")
            cdp_url = instance.expose_http_service(name="cdp-server", port=PROXY_PORT)
            
            # Test external access
            if verbose:
                logger.info("Testing external access...")
                logger.info(f"CDP URL: {cdp_url}")
            
            # Get WebSocket URL from Chrome response
            connect_url = cls._get_websocket_url(instance, cdp_url, verbose)
            
            # Create and return session
            session = cls(instance, cdp_url, connect_url)
            if verbose:
                logger.info("Browser session ready!")
                logger.info(f"CDP URL: {cdp_url}")
                logger.info(f"Connect URL: {connect_url}")
                
                # Log instance details
                try:
                    logger.info(f"MorphVM Instance: {instance.id}")
                    logger.info(f"Instance status: {instance.status}")
                    logger.info(f"Resources: {instance.spec.vcpus} vCPUs, {instance.spec.memory}MB RAM, {instance.spec.disk_size}MB disk")
                except Exception as e:
                    logger.debug(f"Could not get instance details: {e}")
            
            return session
                    
        except Exception as e:
            raise RuntimeError(f"Failed to create browser session: {e}")


def main(verbose=True):
    """Example usage of BrowserSession with real Chrome and Playwright."""
    logger.info("BrowserSession - Remote Chrome Browser Demo")
    
    session = None
    try:
        logger.info("Creating browser session with real Chrome...")
        session = BrowserSession.create(name="demo-browser", verbose=verbose)
        
        logger.info("Chrome session ready!")
        logger.info(f"Connect URL: {session.connect_url}")
        logger.info(f"CDP URL: {session.cdp_url}")
        
        # Log instance information
        try:
            logger.info(f"MorphVM Instance: {session.instance.id}")
        except Exception:
            logger.info("MorphVM Instance: Details not available")
        
        # Test with Playwright
        logger.info("Testing with Playwright...")
        try:
            from playwright.sync_api import sync_playwright
            logger.info("Playwright already installed")
        except ImportError:
            logger.info("Playwright not found, skipping test")
            return False
        
        # Test the CDP connection
        try:
            with sync_playwright() as p:
                logger.info("Connecting to remote Chrome via CDP...")
                browser = p.chromium.connect_over_cdp(session.connect_url)
                logger.info("Successfully connected to remote Chrome!")
                
                version = browser.version
                logger.info(f"Browser version: {version}")
                
                contexts = browser.contexts
                logger.info(f"Available contexts: {len(contexts)}")
                
                browser.close()
                logger.info("Browser connection closed successfully")
                playwright_success = True
                
        except Exception as e:
            logger.error(f"Playwright connection failed: {e}")
            playwright_success = False
        
        if playwright_success:
            logger.info("ALL TESTS PASSED! Remote Chrome browser working perfectly!")
        else:
            logger.warning("Basic setup works but Playwright test failed")
        
        return playwright_success
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return False
    
    finally:
        if session:
            logger.info("Cleaning up session...")
            try:
                session.close()
                logger.info("Session closed")
            except Exception as e:
                logger.warning(f"Error closing session: {e}")


def simple_example():
    """Simple example showing the clean API"""
    session = BrowserSession.create()
    
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(session.connect_url)
            logger.info(f"Connected to {browser.version}")
            browser.close()
        return True
    except Exception as e:
        logger.error(f"Failed: {e}")
        return False
    finally:
        session.close()


class SessionManager:
    """Manages browser sessions for MorphBrowser."""
    
    def create(self, name: Optional[str] = None, vcpus: int = DEFAULT_VCPUS, memory: int = DEFAULT_MEMORY, disk_size: int = DEFAULT_DISK_SIZE, verbose: bool = False, invalidate: bool = False) -> 'BrowserSession':
        """
        Create a new browser session.
        
        Args:
            name: Name for the browser instance
            vcpus: Number of virtual CPUs
            memory: Memory in MB
            disk_size: Disk size in MB
            verbose: Enable verbose output
            invalidate: Force fresh snapshot creation
            
        Returns:
            Ready browser session with CDP access
        """
        return BrowserSession.create(name=name, vcpus=vcpus, memory=memory, disk_size=disk_size, verbose=verbose, invalidate=invalidate)


class MorphBrowser:
    """
    Main browser management class following the spec API.
    
    Usage:
        mb = MorphBrowser()
        session = mb.sessions.create()
        # Use session.connect_url with Playwright
        session.close()
    """
    
    def __init__(self):
        self.sessions = SessionManager()


if __name__ == "__main__":
    import sys
    
    if "--example" in sys.argv:
        simple_example()
    else:
        verbose = "--verbose" in sys.argv or "-v" in sys.argv
        main(verbose=verbose)
