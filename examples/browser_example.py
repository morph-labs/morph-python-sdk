#!/usr/bin/env python3
"""
Browser example following the spec.md API exactly.

This demonstrates the MorphBrowser API as specified in spec.md.

Usage:
    python examples/browser_example.py
    python examples/browser_example.py --rebuild    # Force fresh snapshot creation
    python examples/browser_example.py --verbose    # Enable verbose output
"""

from playwright.sync_api import sync_playwright, Playwright
from morphcloud.experimental.browser import MorphBrowser
import sys

def main():
    # Parse command line flags
    rebuild = "--rebuild" in sys.argv
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    
    mb = MorphBrowser()

    def run(playwright: Playwright):
        # Create a session on MorphCloud
        session = mb.sessions.create(invalidate=rebuild, verbose=verbose)

        # Show instance information
        try:
            print(f"✅ MorphVM Instance: {session.instance.id}")
        except Exception:
            print("✅ MorphVM Instance: Details not available")

        # Connect to the remote session
        chromium = playwright.chromium
        
        if verbose:
            print(f"Connecting to: {session.connect_url}")
        
        browser = chromium.connect_over_cdp(session.connect_url)
        
        if verbose:
            print(f"Connected to browser, contexts: {len(browser.contexts)}")
            for i, context in enumerate(browser.contexts):
                print(f"  Context {i}: {len(context.pages)} pages")
        
        # Use the exact spec.md pattern
        context = browser.contexts[0]
        page = context.pages[0]

        try:
            page.goto("https://news.ycombinator.com/")
            print(page.title())
        finally:
            page.close()
            browser.close()

    with sync_playwright() as playwright:
        run(playwright)

if __name__ == "__main__":
    main()