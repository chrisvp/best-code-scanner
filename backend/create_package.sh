#!/bin/bash
#
# Davy Code Scanner - Create Distribution Package
# Creates a fresh davy-scanner.zip with cleaned database
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"
STAGING_DIR="/tmp/davy-scanner-staging"

echo "=== Creating Davy Code Scanner Package ==="
echo ""

# Clean staging area
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# Copy backend files (excluding dev/temp files)
echo "Copying backend files..."
rsync -a \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.pytest_cache' \
    --exclude='*.egg-info' \
    --exclude='.git' \
    --exclude='scans.db' \
    --exclude='scans.db.bak' \
    --exclude='scans_snapshot.db' \
    --exclude='uploads/*' \
    --exclude='sandbox' \
    --exclude='tests' \
    --exclude='venv_fix' \
    --exclude='*.tar.gz' \
    --exclude='benchmark_results*.json' \
    --exclude='simulate_benchmarks.py' \
    --exclude='test_*.py' \
    --exclude='check_models*.py' \
    --exclude='scan_report.py' \
    --exclude='create_package.sh' \
    "$SCRIPT_DIR/" "$STAGING_DIR/backend/"

# Create uploads directory
mkdir -p "$STAGING_DIR/backend/uploads"

# Copy and clean database
if [ -f "/tmp/scans.db" ]; then
    DB_SOURCE="/tmp/scans.db"
elif [ -f "$SCRIPT_DIR/scans.db" ]; then
    DB_SOURCE="$SCRIPT_DIR/scans.db"
else
    echo "Warning: No database found, package will start fresh"
    DB_SOURCE=""
fi

if [ -n "$DB_SOURCE" ]; then
    echo "Cleaning database (removing scan data, keeping config)..."
    cp "$DB_SOURCE" "$STAGING_DIR/backend/scans.db"
    sqlite3 "$STAGING_DIR/backend/scans.db" "
        DELETE FROM findings;
        DELETE FROM verified_findings;
        DELETE FROM draft_findings;
        DELETE FROM scan_file_chunks;
        DELETE FROM scan_files;
        DELETE FROM scan_error_logs;
        DELETE FROM scan_metrics;
        DELETE FROM llm_call_metrics;
        DELETE FROM scan_configs;
        DELETE FROM scans;
        DELETE FROM mr_reviews;
        DELETE FROM repo_watchers;
        DELETE FROM symbols;
        DELETE FROM symbol_references;
        DELETE FROM import_relations;
        DELETE FROM generated_fixes;
        DELETE FROM webhook_delivery_logs;
        DELETE FROM github_repos;
        DELETE FROM gitlab_repos;
        VACUUM;
    "

    # Show what's included
    echo ""
    sqlite3 "$STAGING_DIR/backend/scans.db" "SELECT 'Models: ' || COUNT(*) FROM model_configs;"
    sqlite3 "$STAGING_DIR/backend/scans.db" "SELECT 'Profiles: ' || COUNT(*) FROM scan_profiles;"
    sqlite3 "$STAGING_DIR/backend/scans.db" "SELECT 'Analyzers: ' || COUNT(*) FROM profile_analyzers;"
fi

# Create zip
echo ""
echo "Creating zip archive..."
cd "$STAGING_DIR"
rm -f "$OUTPUT_DIR/davy-scanner.zip"
zip -rq "$OUTPUT_DIR/davy-scanner.zip" backend

# Cleanup
rm -rf "$STAGING_DIR"

# Show result
echo ""
echo "=== Package Created ==="
ls -lh "$OUTPUT_DIR/davy-scanner.zip"
echo ""
echo "Contents:"
unzip -l "$OUTPUT_DIR/davy-scanner.zip" | tail -1
