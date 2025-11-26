import hashlib
from typing import Optional, List, Dict, Any


class AnalysisCache:
    """Scan-specific caching layer for speed optimization.

    Each cache instance is tied to a specific scan_id.
    Cache is automatically cleared when the scan completes or a new scan starts.
    This prevents stale/empty results from previous scans affecting new scans.
    """

    # Class-level registry of active caches per scan
    _instances: Dict[int, 'AnalysisCache'] = {}

    def __init__(self, scan_id: int, max_ast_cache: int = 10000, max_analysis_cache: int = 50000):
        self.scan_id = scan_id
        self.ast_cache: Dict[tuple, Any] = {}
        self.analysis_cache: Dict[str, List[dict]] = {}
        self.symbol_cache: Dict[str, Any] = {}

        self._max_ast = max_ast_cache
        self._max_analysis = max_analysis_cache

        # Register this instance
        AnalysisCache._instances[scan_id] = self

    @classmethod
    def for_scan(cls, scan_id: int, max_ast_cache: int = 10000, max_analysis_cache: int = 50000) -> 'AnalysisCache':
        """Get or create a cache instance for a specific scan.

        If a cache already exists for this scan, return it.
        Otherwise, create a new one.
        """
        if scan_id in cls._instances:
            return cls._instances[scan_id]
        return cls(scan_id, max_ast_cache, max_analysis_cache)

    @classmethod
    def cleanup_scan(cls, scan_id: int):
        """Clean up cache for a completed/failed scan to free memory."""
        if scan_id in cls._instances:
            instance = cls._instances[scan_id]
            instance.clear()
            del cls._instances[scan_id]

    @classmethod
    def cleanup_all(cls):
        """Clean up all cached data across all scans."""
        for instance in cls._instances.values():
            instance.clear()
        cls._instances.clear()

    def get_ast(self, file_path: str, mtime: float) -> Optional[Any]:
        """Get cached parsed AST for a file"""
        key = (file_path, mtime)
        return self.ast_cache.get(key)

    def set_ast(self, file_path: str, mtime: float, parsed: Any):
        """Cache parsed AST for a file"""
        key = (file_path, mtime)
        if len(self.ast_cache) >= self._max_ast:
            # Simple eviction - remove oldest
            oldest_key = next(iter(self.ast_cache))
            del self.ast_cache[oldest_key]
        self.ast_cache[key] = parsed

    def get_analysis(self, content_hash: str) -> Optional[List[dict]]:
        """Get cached analysis results for content hash (scan-specific)"""
        return self.analysis_cache.get(content_hash)

    def set_analysis(self, content_hash: str, findings: List[dict]):
        """Cache analysis results for content hash (scan-specific)"""
        if len(self.analysis_cache) >= self._max_analysis:
            oldest_key = next(iter(self.analysis_cache))
            del self.analysis_cache[oldest_key]
        self.analysis_cache[content_hash] = findings

    def get_symbol(self, key: str) -> Optional[Any]:
        """Get cached symbol lookup"""
        return self.symbol_cache.get(key)

    def set_symbol(self, key: str, symbol: Any):
        """Cache symbol lookup"""
        self.symbol_cache[key] = symbol

    def clear(self):
        """Clear all caches for this scan"""
        self.ast_cache.clear()
        self.analysis_cache.clear()
        self.symbol_cache.clear()

    @staticmethod
    def hash_content(content: str) -> str:
        """Generate hash for content"""
        return hashlib.md5(content.encode()).hexdigest()
