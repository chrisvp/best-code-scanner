#!/bin/bash
#
# Davy Code Scanner - Install Script
# Extracts the application and sets up the server
#
# Place this script alongside davy-scanner.zip in your install directory
# e.g., /opt/davy-code-scanner/install.sh
#       /opt/davy-code-scanner/davy-scanner.zip
#
# After running: /opt/davy-code-scanner/backend/
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Davy Code Scanner Installer ==="
echo ""
echo "Install directory: $SCRIPT_DIR"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Found Python $PYTHON_VERSION"

# Check for zip file
if [ ! -f "$SCRIPT_DIR/davy-scanner.zip" ]; then
    echo "Error: Cannot find davy-scanner.zip in $SCRIPT_DIR"
    exit 1
fi

# Extract to current directory
echo "Extracting davy-scanner.zip..."
unzip -o "$SCRIPT_DIR/davy-scanner.zip" -d "$SCRIPT_DIR"

cd "$SCRIPT_DIR/backend"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate and install dependencies
echo "Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

# Create uploads directory
mkdir -p uploads

echo ""
echo "=== Installation Complete ==="
echo ""
echo "To start the server:"
echo "  cd $SCRIPT_DIR/backend"
echo "  source venv/bin/activate"
echo "  python start.py"
echo ""
echo "Or run: $SCRIPT_DIR/backend/run.sh"
echo ""
echo "Server will be available at: http://localhost:8000"
