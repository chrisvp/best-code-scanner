#!/bin/bash
# Benchmark different chunk sizes with gpt-oss-120b

ENDPOINT="http://localhost:8000"
TARGET="/tmp/vuln-cpp-large.tar.gz"
RESULTS_FILE="/tmp/chunk_benchmark_results.txt"

echo "======================================" > $RESULTS_FILE
echo "Chunk Size Benchmark - gpt-oss-120b" >> $RESULTS_FILE
echo "Started: $(date)" >> $RESULTS_FILE
echo "======================================" >> $RESULTS_FILE

run_scan() {
    CHUNK_SIZE=$1
    echo ""
    echo "=============================================="
    echo "Starting scan with chunk_size=$CHUNK_SIZE"
    echo "=============================================="

    # Start scan
    RESPONSE=$(curl -s -X POST $ENDPOINT/scan/start \
        -F "target_url=$TARGET" \
        -F "chunk_size=$CHUNK_SIZE" \
        -F "multi_model_scan=false")

    SCAN_ID=$(echo $RESPONSE | grep -o 'ID: #[0-9]*' | grep -o '[0-9]*')

    if [ -z "$SCAN_ID" ]; then
        echo "ERROR: Failed to start scan"
        echo "$RESPONSE"
        return 1
    fi

    echo "Scan #$SCAN_ID started"

    # Wait for completion
    while true; do
        PROGRESS=$(curl -s $ENDPOINT/scan/$SCAN_ID/progress)
        STATUS=$(curl -s $ENDPOINT/scan/$SCAN_ID | grep -o '"status":"[^"]*"' | head -1)

        CHUNKS_TOTAL=$(echo $PROGRESS | jq -r '.chunks.total')
        CHUNKS_SCANNED=$(echo $PROGRESS | jq -r '.chunks.scanned')
        DRAFTS=$(echo $PROGRESS | jq -r '.drafts.total')
        VERIFIED=$(echo $PROGRESS | jq -r '.drafts.verified')

        echo "Progress: $CHUNKS_SCANNED/$CHUNKS_TOTAL chunks, $DRAFTS drafts, $VERIFIED verified"

        if echo "$STATUS" | grep -q "completed\|failed"; then
            break
        fi

        sleep 30
    done

    # Get metrics
    echo ""
    echo "Chunk Size: $CHUNK_SIZE" >> $RESULTS_FILE
    echo "Scan ID: $SCAN_ID" >> $RESULTS_FILE

    cd /home/chris/code/code-scanner/backend
    python scripts/scan_metrics.py $SCAN_ID >> $RESULTS_FILE
    echo "" >> $RESULTS_FILE
    echo "----------------------------------------------" >> $RESULTS_FILE

    echo "Scan #$SCAN_ID completed"
}

# Already running scan 1 with 8k
echo "Waiting for existing 8k scan to complete..."
while true; do
    STATUS=$(curl -s $ENDPOINT/scan/1 | grep -o '"status":"[^"]*"' | head -1)
    if echo "$STATUS" | grep -q "completed\|failed"; then
        break
    fi
    sleep 30
done

# Record 8k results
echo ""
echo "Chunk Size: 8000" >> $RESULTS_FILE
echo "Scan ID: 1" >> $RESULTS_FILE
cd /home/chris/code/code-scanner/backend
python scripts/scan_metrics.py 1 >> $RESULTS_FILE
echo "" >> $RESULTS_FILE
echo "----------------------------------------------" >> $RESULTS_FILE

# Run remaining chunk sizes
run_scan 16000
run_scan 32000
run_scan 48000

echo ""
echo "======================================" >> $RESULTS_FILE
echo "Completed: $(date)" >> $RESULTS_FILE
echo "======================================" >> $RESULTS_FILE

echo ""
echo "Benchmark complete! Results saved to $RESULTS_FILE"
cat $RESULTS_FILE
