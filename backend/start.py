#!/usr/bin/env python3
"""Start the scanner server (kills any existing instance first)"""

import subprocess
import os
import sys

PORT = 8000
GRACEFUL_TIMEOUT = 30  # Force close connections after 30 seconds on reload/shutdown

# Kill anything on port 8000
subprocess.run(f"fuser -k {PORT}/tcp 2>/dev/null", shell=True)

# Start uvicorn with graceful shutdown timeout
os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.execvp("uvicorn", [
    "uvicorn", "main:app",
    "--host", "0.0.0.0",
    "--port", str(PORT),
    "--reload",
    "--timeout-graceful-shutdown", str(GRACEFUL_TIMEOUT)
])
