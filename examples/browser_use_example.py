#!/usr/bin/env python3
"""Run a Browser Use agent in a Morph Cloud browser.

Setup:
    uv pip install morphcloud browser-use
    export MORPH_API_KEY=...
    export BROWSER_USE_API_KEY=...
"""

import asyncio

from browser_use import Agent, Browser, ChatBrowserUse
from morphcloud.experimental.browser import MorphBrowser


async def main() -> None:
    session = MorphBrowser().sessions.create(ttl_seconds=900)
    browser = Browser(cdp_url=session.connect_url, is_local=False)

    try:
        agent = Agent(
            task="Find the top Hacker News story and return its title and URL.",
            llm=ChatBrowserUse(),
            browser=browser,
        )
        await agent.run()
    finally:
        try:
            await browser.stop()
        finally:
            session.close()


if __name__ == "__main__":
    asyncio.run(main())
