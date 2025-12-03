import os
import shutil
import subprocess
import zipfile
import tarfile
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
        """Create sandbox directory for extracted archives or cloned repos."""
        import time
        scan_dir = self.sandbox_root / scan_id
        if scan_dir.exists():
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    shutil.rmtree(scan_dir, onerror=self._remove_readonly)
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        time.sleep(1)
                    else:
                        raise e
        scan_dir.mkdir(parents=True)
        return scan_dir

    async def use_local_dir(self, source_path: str) -> Path:
        """Use local directory directly without copying - read-only scanning."""
        source = Path(source_path).resolve()
        if not source.exists():
            raise Exception(f"Source directory does not exist: {source_path}")
        if not source.is_dir():
            raise Exception(f"Source is not a directory: {source_path}")
        return source

    async def clone_repo(self, repo_url: str, scan_id: str, token: Optional[str] = None) -> Path:
        # Local directory - use directly without copying
        if os.path.isdir(repo_url):
            return await self.use_local_dir(repo_url)

        # Git URL - clone to sandbox
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

    async def copy_from_scan(self, source_scan_id: str, target_scan_id: str) -> Path:
        """Copy code from an existing scan's sandbox to a new scan."""
        source_dir = self.sandbox_root / str(source_scan_id)
        if not source_dir.exists():
            raise Exception(f"Source scan {source_scan_id} sandbox not found")

        target_dir = self.create_sandbox(str(target_scan_id))

        # Copy all contents from source to target
        for item in source_dir.iterdir():
            src_path = source_dir / item.name
            dst_path = target_dir / item.name
            if src_path.is_dir():
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)

        return target_dir

ingestion_service = IngestionService()
