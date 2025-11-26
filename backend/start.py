#!/usr/bin/env python3
"""Start the scanner server (kills any existing instance first)"""

import subprocess
import os
import sys

PORT = 8000

# Kill anything on port 8000
subprocess.run(f"fuser -k {PORT}/tcp 2>/dev/null", shell=True)

# Start uvicorn
os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.execvp("uvicorn", ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(PORT), "--reload"])
