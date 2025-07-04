#!/usr/bin/env python3
"""
Setup browser snapshot and print the snapshot ID for manual experimentation.

Usage:
    python examples/setup_browser_snapshot.py
    
Then use the snapshot ID to manually start instances and experiment with proxy configs.
"""

from morphcloud.experimental.browser import BrowserSession
import sys

def main():
    print("🚀 Creating browser snapshot...")
    print("This will install Chrome and dependencies, then create a reusable snapshot.")
    
    # Create browser session to get snapshot - this handles all the setup
    session = BrowserSession.create(name="browser-snapshot-setup", verbose=True, invalidate=True)
    
    print(f"\n✅ Browser snapshot ready!")
    print(f"📦 Snapshot ID: {session.instance.snapshot_id if hasattr(session.instance, 'snapshot_id') else 'Unknown'}")
    print(f"🌐 Instance ID: {session.instance.id}")
    print(f"🔗 CDP URL: {session.cdp_url}")
    
    print(f"\n🛠️  Manual experimentation commands:")
    print(f"# SSH into instance:")
    print(f"# morphcloud instances ssh {session.instance.id}")
    print(f"")
    print(f"# Test proxy configs manually:")
    print(f"# tmux kill-session -t proxy-session")  
    print(f"# pkill socat")
    print(f"# socat TCP-LISTEN:9223,fork,reuseaddr TCP:localhost:9222 &")
    print(f"# curl http://localhost:9223/json")
    print(f"")
    print(f"# Try nginx instead:")
    print(f"# apt-get install nginx -y")
    print(f"# # ... configure nginx ...")
    
    input("\nPress Enter to clean up the instance (or Ctrl+C to keep it running for experiments)...")
    session.close()
    print("✅ Cleaned up!")

if __name__ == "__main__":
    main()