#!/usr/bin/env python3
"""Start the scanner server (kills any existing instance first)"""

import subprocess
import os
import sys
from pathlib import Path

PORT = 8000
GRACEFUL_TIMEOUT = 30  # Force close connections after 30 seconds on reload/shutdown

# Get backend directory
backend_dir = Path(__file__).parent.absolute()
venv_dir = backend_dir / "venv"
venv_python = venv_dir / "bin" / "python"
venv_uvicorn = venv_dir / "bin" / "uvicorn"

# Check if venv exists
if not venv_dir.exists():
    print("❌ Virtual environment not found!")
    print(f"   Expected: {venv_dir}")
    print("\n   Create it with:")
    print("   cd backend && python3 -m venv venv")
    print("   source venv/bin/activate && pip install -r requirements.txt")
    sys.exit(1)

# Check if uvicorn is installed in venv
if not venv_uvicorn.exists():
    print("❌ uvicorn not found in virtual environment!")
    print("\n   Install dependencies with:")
    print("   source venv/bin/activate && pip install -r requirements.txt")
    sys.exit(1)

# Kill anything on port 8000
subprocess.run(f"fuser -k {PORT}/tcp 2>/dev/null", shell=True)

# Change to backend directory
os.chdir(backend_dir)

print(f"🚀 Starting Davy Code Scanner on port {PORT}")
print(f"   Using venv: {venv_dir}")
print(f"   Server URL: http://localhost:{PORT}\n")

# Start uvicorn with venv's python and uvicorn
os.execv(str(venv_python), [
    str(venv_python), "-m", "uvicorn", "main:app",
    "--host", "0.0.0.0",
    "--port", str(PORT),
    "--reload",
    "--timeout-graceful-shutdown", str(GRACEFUL_TIMEOUT)
])
