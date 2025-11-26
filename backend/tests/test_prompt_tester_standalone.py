import sys
import os
import asyncio
import unittest
from unittest.mock import MagicMock, patch, AsyncMock

# --- MOCKS BEFORE IMPORTS ---
# Mock heavy dependencies
sys.modules["sqlalchemy"] = MagicMock()
sys.modules["sqlalchemy.orm"] = MagicMock()

# Mock App Database/Config/Models
mock_db_module = MagicMock()
sys.modules["app.core.database"] = mock_db_module
sys.modules["app.models.models"] = MagicMock()
sys.modules["app.models.scanner_models"] = MagicMock()
sys.modules["app.services.orchestration.model_orchestrator"] = MagicMock()
sys.modules["app.services.orchestration.cache"] = MagicMock()
sys.modules["app.services.analysis.draft_scanner"] = MagicMock() # We might want to test integration, but mocking DraftScanner makes unit testing PromptTester easier. 
# Actually, let's NOT mock DraftScanner entirely, we want to verify the flow.
# But DraftScanner imports things we just mocked.
# We need to ensure DraftScanner can be imported or define a MockDraftScanner.

# Let's verify the Service logic:
# 1. Creates DB records
# 2. Creates Temp Config
# 3. Instantiates Scanner
# 4. Runs batch
# 5. Cleans up

# If we use real DraftScanner, we rely on its internal logic. 
# Let's use a MockDraftScanner to strictly test the Service's orchestration.
# This isolates the test to PromptTesterService.

# Mock Intelligence
sys.modules["app.services.intelligence"] = MagicMock()
sys.modules["app.services.intelligence.ast_parser"] = MagicMock()
sys.modules["app.services.intelligence.context_retriever"] = MagicMock()

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

from app.services.analysis.prompt_tester import PromptTesterService

class TestPromptTester(unittest.TestCase):
    
    def test_prompt_tester_flow(self):
        asyncio.run(self._async_test_flow())

    async def _async_test_flow(self):
        print("Setting up PromptTester test...")
        
        # 1. Setup DB Mock
        mock_db = MagicMock()
        
        # Mock ModelConfig query
        mock_config = MagicMock()
        mock_config.name = "test-model"
        mock_config.base_url = "http://mock"
        mock_config.api_key = "key"
        mock_config.max_tokens = 1000
        mock_config.max_concurrent = 1
        
                # When query(ModelConfig).filter(...).first() is called
                mock_db.query.return_value.filter.return_value.first.return_value = mock_config
                
                # Mock ScanFileChunk to have a fixed ID
                mock_chunk = MagicMock()
                mock_chunk.id = 999
                import app.models.scanner_models
                app.models.scanner_models.ScanFileChunk.return_value = mock_chunk
                
                # 2. Setup DraftScanner Mock
                with patch("app.services.analysis.prompt_tester.DraftScanner") as MockScannerClass, \
                     patch("app.services.analysis.prompt_tester.ModelPool") as MockPoolClass:
                    
                    # Configure Mock Scanner instance
                    mock_scanner_instance = MockScannerClass.return_value
                    # Return findings keyed by the known chunk ID
                    mock_scanner_instance.scan_batch = AsyncMock(return_value={
                        999: [{'_model': 'test-model', 'title': 'Bug Found', 'line': 10}]
                    })
        
                    # Configure Mock Pool
                    mock_pool_instance = MockPoolClass.return_value
                    mock_pool_instance.start = AsyncMock()
                    mock_pool_instance.stop = AsyncMock()
                    mock_pool_instance.config.name = "test-model" # CRITICAL: Set the name so it matches the string key
                    
                    # 3. Run Service            service = PromptTesterService(mock_db)
            
            CODE = "void test() {}"
            MODELS = ["test-model"]
            PROMPT = "CUSTOM PROMPT {code}"
            
            results = await service.test_prompt(CODE, MODELS, PROMPT)
            
            # 4. Verify
            print("Verifying results...")
            self.assertIn("test-model", results)
            self.assertEqual(len(results["test-model"]), 1)
            self.assertEqual(results["test-model"][0]['title'], "Bug Found")
            
            # Verify Pool was created with custom prompt
            # MockPoolClass was called with a config object.
            call_args = MockPoolClass.call_args
            config_passed = call_args[0][0]
            self.assertEqual(config_passed.analysis_prompt_template, PROMPT)
            print("Confirmed ModelPool received custom prompt.")
            
            # Verify Cleanup
            # We expect db.query(...).delete() calls
            self.assertTrue(mock_db.query.called)
            
            print("Test Passed!")

if __name__ == "__main__":
    unittest.main()
