import os
import uuid
import tempfile
import asyncio
from typing import List, Dict, Optional
from sqlalchemy.orm import Session

from app.models.models import Scan
from app.models.scanner_models import ModelConfig, ScanFile, ScanFileChunk, ScanConfig
from app.services.orchestration.model_orchestrator import ModelPool
from app.services.analysis.draft_scanner import DraftScanner
from app.services.orchestration.cache import AnalysisCache

class MockCache:
    """No-op cache for testing prompts to ensure fresh results"""
    def get_analysis(self, *args): return None
    def set_analysis(self, *args): pass
    @staticmethod
    def hash_content(content): return "hash"

class PromptTesterService:
    """
    Service to programmatically test prompts against specific models 
    using isolated temporary contexts.
    """
    def __init__(self, db: Session):
        self.db = db

    async def test_prompt(
        self,
        code_content: str,
        model_names: List[str],
        custom_prompt: str
    ) -> Dict[str, List[dict]]:
        """
        Run a scan on the provided code using selected models and a custom prompt.
        
        Args:
            code_content: The source code to scan
            model_names: List of model names to use (must exist in DB)
            custom_prompt: The prompt template to test
            
        Returns:
            Dictionary mapping model_name -> list of findings
        """
        # 1. Setup Temporary Context (Scan, File, Chunk)
        scan_id = f"test_{uuid.uuid4().hex[:8]}"
        temp_file_path = self._create_temp_file(code_content)
        
        try:
            # Create Temp DB Records
            scan = Scan(id=999999, target_url="manual_test", status="running") # distinct ID
            # Note: We don't add Scan to DB to avoid constraint issues or pollution, 
            # but DraftScanner needs ScanFileChunk -> ScanFile in DB.
            
            # We'll create a real Scan record but mark it as test
            scan = Scan(target_url="prompt_test", status="test")
            self.db.add(scan)
            self.db.commit()
            
            scan_file = ScanFile(
                scan_id=scan.id,
                file_path=temp_file_path,
                risk_level="high" # Force LLM scan
            )
            self.db.add(scan_file)
            self.db.commit()
            
            chunk = ScanFileChunk(
                scan_file_id=scan_file.id,
                chunk_index=0,
                start_line=1,
                end_line=code_content.count('\n') + 1,
                content_hash="manual_test",
                chunk_type="manual"
            )
            self.db.add(chunk)
            self.db.commit()

            # 2. Prepare Model Pools with Custom Prompt
            pools = []
            for name in model_names:
                config = self.db.query(ModelConfig).filter(ModelConfig.name == name).first()
                if not config:
                    continue
                    
                # Create a temporary config object (not persisted)
                temp_config = ModelConfig(
                    name=config.name,
                    base_url=config.base_url,
                    api_key=config.api_key,
                    max_tokens=config.max_tokens,
                    max_concurrent=config.max_concurrent,
                    analysis_prompt_template=custom_prompt # OVERRIDE
                )
                
                pool = ModelPool(temp_config)
                await pool.start()
                pools.append(pool)

            if not pools:
                return {"error": "No valid models found"}

            # 3. Run Scanner
            scanner = DraftScanner(scan_id=scan.id, model_pools=pools, cache=MockCache())
            
            # Execute
            results = await scanner.scan_batch([chunk])
            
            # 4. Format Results
            # DraftScanner returns {chunk_id: [findings]}
            # We want to organize by model: {model_name: [findings]}
            
            findings = results.get(chunk.id, [])
            
            by_model = {}
            for pool in pools:
                by_model[pool.config.name] = []
                
            for f in findings:
                model = f.get('_model')
                if model and model in by_model:
                    by_model[model].append(f)
                    
            return by_model

        finally:
            # Cleanup
            self._cleanup_temp_file(temp_file_path)
            # Cleanup DB
            try:
                if 'scan' in locals() and scan.id:
                    self.db.query(ScanFileChunk).filter(ScanFileChunk.scan_file_id == scan_file.id).delete()
                    self.db.query(ScanFile).filter(ScanFile.id == scan_file.id).delete()
                    self.db.query(Scan).filter(Scan.id == scan.id).delete()
                    self.db.commit()
            except Exception as e:
                print(f"Cleanup failed: {e}")
            
            # Stop pools
            if 'pools' in locals():
                for pool in pools:
                    await pool.stop()

    def _create_temp_file(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".cpp", text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        return path

    def _cleanup_temp_file(self, path: str):
        if os.path.exists(path):
            os.remove(path)
