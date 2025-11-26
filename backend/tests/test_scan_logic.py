import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from app.services.analysis.draft_scanner import DraftScanner
from app.services.analysis.static_detector import StaticPatternDetector
from app.models.scanner_models import ScanFileChunk, ScanFile

# Mock data
MOCK_CODE = """#include <stdio.h>
#include <string.h>

void process_input(char *input) {
    char buffer[64];
    // VULN: Buffer overflow
    strcpy(buffer, input);
    
    char cmd[128];
    // VULN: Command injection
    sprintf(cmd, "echo %s", input);
    system(cmd);
    
    // VULN: Hardcoded credential
    char *api_key = "12345-SECRET-KEY";
}
"""

MOCK_LLM_RESPONSE = """
*DRAFT: Buffer Overflow
*TYPE: CWE-120
*SEVERITY: High
*LINE: 6
*SNIPPET: strcpy(buffer, input);
*REASON: Unbounded copy into fixed-size buffer
*END_DRAFT

*DRAFT: Command Injection
*TYPE: CWE-78
*SEVERITY: Critical
*LINE: 11
*SNIPPET: system(cmd);
*REASON: User input passed directly to system shell
*END_DRAFT

*DRAFT: Hardcoded Credentials
*TYPE: CWE-798
*SEVERITY: High
*LINE: 14
*SNIPPET: char *api_key = "12345-SECRET-KEY";
*REASON: Hardcoded secret in source code
*END_DRAFT
"""

@pytest.mark.asyncio
async def test_draft_scanner_flow():
    """Test the draft scanner with mocked LLM and DB"""
    
    # 1. Setup Mocks
    mock_db = MagicMock()
    mock_cache = MagicMock()
    mock_cache.get_analysis.return_value = None  # No cache hit
    
    mock_pool = MagicMock()
    mock_pool.config.name = "test-model"
    mock_pool.call_batch = AsyncMock(return_value=[MOCK_LLM_RESPONSE])
    
    # Mock StaticDetector to avoid DB calls
    with patch('app.services.analysis.draft_scanner.StaticPatternDetector') as MockDetector:
        detector_instance = MockDetector.return_value
        # Return empty static findings to force LLM call
        detector_instance.scan_fast.return_value = ([], True)
        
        scanner = DraftScanner(scan_id=1, model_pools=[mock_pool], cache=mock_cache)
        
        # Replace the real static detector with our mock (just to be safe)
        scanner.static_detector = detector_instance

        # 2. Create Mock Chunk
        chunk = ScanFileChunk(
            id=101,
            scan_file_id=50,
            start_line=1,
            end_line=17,
            content_hash="abc",
            chunk_index=0
        )
        
        # Mock _get_chunk_content to return our code
        with patch.object(scanner, '_get_chunk_content', return_value=MOCK_CODE):
             # Mock _get_language
            with patch.object(scanner, '_get_language', return_value='c'):
                
                # 3. Run Scan
                results = await scanner.scan_batch([chunk])
                
                # 4. Verify Results
                assert 101 in results
                findings = results[101]
                
                print("\nFound Findings:")
                for f in findings:
                    print(f"- {f.get('title')} (Line {f.get('line')})")
                
                assert len(findings) == 3
                
                # Check specific findings
                titles = [f.get('title') for f in findings]
                assert "Buffer Overflow" in titles
                assert "Command Injection" in titles
                assert "Hardcoded Credentials" in titles
                
                # Verify Line Numbers
                bo = next(f for f in findings if f['title'] == "Buffer Overflow")
                assert int(bo['line']) == 6
                
                # Verify LLM Prompt contained line numbers
                call_args = mock_pool.call_batch.call_args[0][0]
                prompt = call_args[0]
                assert "   6 |     strcpy(buffer, input);" in prompt
                assert "**Memory Safety (C/C++):**" in prompt # Check prompt template
                assert "Examples:" in prompt # Check few-shot examples

if __name__ == "__main__":
    # Manual run if pytest not available
    loop = asyncio.new_event_loop()
    loop.run_until_complete(test_draft_scanner_flow())
    loop.close()
