import os
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
import asyncio
from pathlib import Path
from typing import Optional

class IngestionService:
    def __init__(self, sandbox_root: str = "sandbox"):
        self.sandbox_root = Path(sandbox_root)
        self.sandbox_root.mkdir(exist_ok=True)

    def _remove_readonly(self, func, path, _):
        import os, stat
        os.chmod(path, stat.S_IWRITE)
        func(path)

    def create_sandbox(self, scan_id: str) -> Path:
        import time
        scan_dir = self.sandbox_root / scan_id
        if scan_dir.exists():
            # Handle read-only files and retry for locked files
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    shutil.rmtree(scan_dir, onerror=self._remove_readonly)
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        time.sleep(1)  # Wait for file locks to release
                    else:
                        raise e
        scan_dir.mkdir(parents=True)
        return scan_dir

    async def clone_repo(self, repo_url: str, scan_id: str, token: Optional[str] = None) -> Path:
        target_dir = self.create_sandbox(scan_id)
        
        final_url = repo_url
        # TODO: Token handling

        try:
            # Debugging: Use blocking subprocess to capture output reliably
            result = subprocess.run(
                ["git", "clone", "--depth", "1", final_url, str(target_dir)],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
                raise Exception(f"Git clone failed (Code {result.returncode}): {error_msg}")
                
            return target_dir
        except Exception as e:
            raise Exception(f"Git clone failed: {str(e)}")

    async def extract_archive(self, file_path: str, scan_id: str) -> Path:
        target_dir = self.create_sandbox(scan_id)
        
        if file_path.endswith(".zip"):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(target_dir)
        elif file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
            with tarfile.open(file_path, "r:gz") as tar_ref:
                tar_ref.extractall(target_dir)
        else:
            # TODO: Add ISO support via libarchive or 7z
            raise ValueError("Unsupported archive format")
            
        return target_dir

ingestion_service = IngestionService()
