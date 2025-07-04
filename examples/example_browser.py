#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "playwright",
# ]
# ///
"""
Example usage of MorphBrowser with the new API from spec.md

This example shows how to use the MorphBrowser class to create remote browser sessions
and control them with Playwright.
"""

from playwright.sync_api import sync_playwright, Playwright
from morphcloud.experimental.browser import MorphBrowser
import os

mb = MorphBrowser()

def run(playwright: Playwright, invalidate=False):
    print("🚀 Starting browser session creation...")
    
    # Create a session on Browserbase (with verbose output)
    if invalidate:
        print("🔄 Invalidating cached snapshot (will rebuild from scratch)...")
    session = mb.sessions.create(verbose=True, invalidate=invalidate)
    print(f"✅ Session created!")
    print(f"🔗 Connect URL: {session.connect_url}")
    print(f"📡 CDP URL: {session.cdp_url}")

    print("🎭 Connecting to remote Chrome via Playwright...")
    # Connect to the remote session
    chromium = playwright.chromium
    browser = chromium.connect_over_cdp(session.connect_url)
    print("✅ Connected to remote Chrome!")
    
    # Debug the CDP connection thoroughly
    print(f"🔍 Debugging CDP connection state...")
    
    # Check what Playwright sees
    print(f"   Browser version: {browser.version}")
    contexts = browser.contexts
    print(f"   Contexts available: {len(contexts)}")
    
    for i, context in enumerate(contexts):
        pages = context.pages
        print(f"   Context {i}: {len(pages)} pages")
        for j, page in enumerate(pages):
            try:
                url = page.url
                print(f"     Page {j}: {url}")
            except Exception as e:
                print(f"     Page {j}: Error getting URL - {e}")
    
    # Let's also check what the CDP endpoint directly shows
    print(f"🌐 Checking CDP endpoint directly...")
    import requests
    try:
        cdp_response = requests.get(f"{session.cdp_url}/json", timeout=5)
        if cdp_response.status_code == 200:
            cdp_data = cdp_response.json()
            print(f"   CDP shows {len(cdp_data)} targets:")
            for target in cdp_data:
                print(f"     Type: {target.get('type')}, URL: {target.get('url')}, Title: {target.get('title')}")
        else:
            print(f"   CDP request failed: {cdp_response.status_code}")
    except Exception as e:
        print(f"   CDP request error: {e}")
    
    # Now try to get a page
    if contexts and len(contexts[0].pages) > 0:
        context = contexts[0]
        page = context.pages[0]
        print(f"📄 Using existing page")
    else:
        print(f"❌ No pages found - this is our problem!")
        print(f"   We need to understand why Chrome has contexts but no pages")
        raise Exception("No pages found in remote Chrome")
    
    print(f"🌐 Navigating to Hacker News...")

    try:
        page.goto("https://news.ycombinator.com/")
        title = page.title()
        print(f"📰 Page title: {title}")
        print("🎉 Success!")
    finally:
        print("🧹 Cleaning up...")
        page.close()
        browser.close()
        session.close()
        print("✅ All cleaned up!")

if __name__ == "__main__":
    import sys
    
    # Check for rebuild flag
    invalidate = "--rebuild" in sys.argv
    
    if invalidate:
        print("🔄 Running with --rebuild flag (will rebuild snapshot from scratch)")
    else:
        print("📦 Using cached snapshot (add --rebuild flag to rebuild)")
    
    with sync_playwright() as playwright:
        run(playwright, invalidate=invalidate)