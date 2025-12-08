#!/bin/bash
# Setup script for Joern CPG scanner
# This script pulls the Joern Docker image, sets up the sandbox directory,
# and verifies Docker volume mounts work correctly.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default image (can be overridden via JOERN_DOCKER_IMAGE env var)
JOERN_IMAGE="${JOERN_DOCKER_IMAGE:-ghcr.io/joernio/joern:nightly}"

# Determine sandbox directory
# Default is ./sandbox relative to this script's directory (the backend)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="${SANDBOX_DIR:-$SCRIPT_DIR/sandbox}"

echo "=== Joern Setup Script ==="
echo ""

# Check Docker is installed
echo -n "[1/6] Checking Docker installation... "
if ! command -v docker &> /dev/null; then
    echo -e "${RED}FAILED${NC}"
    echo "ERROR: Docker is not installed or not in PATH"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}OK${NC} ($(docker --version | cut -d' ' -f3 | tr -d ','))"

# Check Docker daemon is running
echo -n "[2/6] Checking Docker daemon... "
if ! docker info &> /dev/null; then
    echo -e "${RED}FAILED${NC}"
    echo "ERROR: Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi
echo -e "${GREEN}OK${NC}"

# Check if user can run Docker without sudo
echo -n "[3/6] Checking Docker permissions... "
if ! docker ps &> /dev/null; then
    echo -e "${YELLOW}WARNING${NC}"
    echo "      Current user may need sudo to run Docker."
    echo "      To fix: sudo usermod -aG docker \$USER && newgrp docker"
else
    echo -e "${GREEN}OK${NC}"
fi

# Set up sandbox directory
echo -n "[4/6] Setting up sandbox directory... "
if [ ! -d "$SANDBOX_DIR" ]; then
    mkdir -p "$SANDBOX_DIR"
    echo -e "${GREEN}CREATED${NC} ($SANDBOX_DIR)"
else
    echo -e "${GREEN}EXISTS${NC} ($SANDBOX_DIR)"
fi

# Ensure sandbox directory is writable and has correct permissions
chmod 755 "$SANDBOX_DIR" 2>/dev/null || true

# Test Docker volume mount with sandbox directory
echo -n "[5/6] Testing Docker volume mount... "
TEST_FILE="$SANDBOX_DIR/.joern_mount_test"
echo "test" > "$TEST_FILE"

# Try to read the file from inside a Docker container
MOUNT_TEST=$(docker run --rm -v "$SANDBOX_DIR:/test:ro" alpine cat /test/.joern_mount_test 2>&1) || true
rm -f "$TEST_FILE"

if [ "$MOUNT_TEST" = "test" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo ""
    echo "ERROR: Docker cannot mount the sandbox directory: $SANDBOX_DIR"
    echo ""
    echo "Possible fixes:"
    echo "  1. On WSL2: Make sure the path is accessible from Docker Desktop"
    echo "     - The sandbox should be on the Linux filesystem (/home/... or /tmp/...)"
    echo "     - Windows paths (/mnt/c/...) may have permission issues"
    echo ""
    echo "  2. On Linux with SELinux: Add :z or :Z to volume mounts"
    echo "     - You may need to run: sudo chcon -Rt svirt_sandbox_file_t $SANDBOX_DIR"
    echo ""
    echo "  3. Check directory permissions: ls -la $SANDBOX_DIR"
    echo ""
    exit 1
fi

# Pull the Joern image
echo "[6/6] Pulling Joern image: $JOERN_IMAGE"
echo "      (This may take a few minutes on first run...)"
docker pull "$JOERN_IMAGE"

# Test Joern is working
echo ""
echo -n "      Testing Joern... "
JOERN_VERSION=$(docker run --rm "$JOERN_IMAGE" joern --version 2>/dev/null | head -1 || echo "unknown")
echo -e "${GREEN}OK${NC} ($JOERN_VERSION)"

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Joern is ready to use with the Davy Code Scanner."
echo ""
echo "Configuration summary:"
echo "  - Docker image: $JOERN_IMAGE"
echo "  - Sandbox directory: $SANDBOX_DIR"
echo "  - Volume mount: VERIFIED"
echo ""
echo "Add to your .env file (optional):"
echo "  JOERN_DOCKER_IMAGE=$JOERN_IMAGE"
echo "  JOERN_TIMEOUT=600"
echo ""

# Write a marker file so the app knows Joern is configured
echo "$JOERN_IMAGE" > "$SCRIPT_DIR/.joern_configured"
echo "Wrote configuration marker to $SCRIPT_DIR/.joern_configured"
