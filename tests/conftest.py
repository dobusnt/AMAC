from __future__ import annotations

import asyncio
import os
import sys


# On Windows, some libs behave better with the Selector event loop (esp. pytest + httpx).
def pytest_sessionstart(session):
    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined]
        except Exception:
            # If not available (older Py versions), just continue.
            pass
    # Make sure UTF-8 is used for any subprocess/file ops in tests.
    os.environ.setdefault("PYTHONUTF8", "1")
