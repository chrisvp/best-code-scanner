import os
import shutil
import subprocess
import zipfile
import tarfile
from pathlib import Path
from typing import Optional

class IngestionService:
    def __init__(self, sandbox_root: str = None):
        if sandbox_root:
            self.sandbox_root = Path(sandbox_root)
        else:
            # Default to backend/sandbox relative to this file
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.sandbox_root = base_dir / "sandbox"
        self.sandbox_root.mkdir(parents=True, exist_ok=True)

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

    async def copy_from_scan(self, source_scan_id: str, target_scan_id: str, db=None) -> Path:
        """Reuse an existing scan's sandbox directly (no copy).

        The file_filter in ScanConfig controls which files to scan,
        while the full codebase remains available for context (e.g., agentic verifiers).

        If the source scan itself was a rescan (has source_scan_id), trace back
        through the chain to find the original sandbox with actual code.
        """
        current_scan_id = str(source_scan_id)
        visited = []

        # Trace back through source_scan_id chain to find the ORIGINAL source
        # (the scan that doesn't have a source_scan_id - i.e., it was cloned/extracted)
        while current_scan_id:
            if current_scan_id in visited:
                break  # Cycle detection
            visited.append(current_scan_id)

            # Try to find the parent scan's source_scan_id
            if db:
                from app.models.scanner_models import ScanConfig
                config = db.query(ScanConfig).filter(ScanConfig.scan_id == int(current_scan_id)).first()
                if config and config.source_scan_id:
                    # This scan was a rescan - continue tracing
                    current_scan_id = str(config.source_scan_id)
                    continue

            # No source_scan_id means this is the original source scan
            break

        # Use the final traced scan's sandbox
        final_scan_id = visited[-1] if visited else source_scan_id
        source_dir = self.sandbox_root / str(final_scan_id)
        
        with open("/tmp/ingestion_debug.log", "a") as f:
            f.write(f"Checking sandbox path: {source_dir} (exists: {source_dir.exists()})\n")
            f.write(f"Sandbox root: {self.sandbox_root} (exists: {self.sandbox_root.exists()})\n")

        if source_dir.exists():
            if final_scan_id != source_scan_id:
                print(f"[Ingestion] Using sandbox from scan {final_scan_id} (traced from {source_scan_id} via {' -> '.join(visited)})")
            else:
                print(f"[Ingestion] Using sandbox from scan {final_scan_id}")
            return source_dir

        # Fallback: try each sandbox in the chain
        for scan_id in visited:
            fallback_dir = self.sandbox_root / str(scan_id)
            if fallback_dir.exists():
                print(f"[Ingestion] Using fallback sandbox from scan {scan_id} (traced from {source_scan_id})")
                return fallback_dir

        raise Exception(f"No sandbox found for scan chain: {' -> '.join(visited)}")

ingestion_service = IngestionService()
