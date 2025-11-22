import hashlib
from typing import Optional, List, Dict, Any


class AnalysisCache:
    """Caching layer for speed optimization"""

    def __init__(self, max_ast_cache: int = 10000, max_analysis_cache: int = 50000):
        self.ast_cache: Dict[tuple, Any] = {}
        self.analysis_cache: Dict[str, List[dict]] = {}
        self.symbol_cache: Dict[str, Any] = {}

        self._max_ast = max_ast_cache
        self._max_analysis = max_analysis_cache

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
        """Get cached analysis results for content hash"""
        return self.analysis_cache.get(content_hash)

    def set_analysis(self, content_hash: str, findings: List[dict]):
        """Cache analysis results for content hash"""
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
        """Clear all caches"""
        self.ast_cache.clear()
        self.analysis_cache.clear()
        self.symbol_cache.clear()

    @staticmethod
    def hash_content(content: str) -> str:
        """Generate hash for content"""
        return hashlib.md5(content.encode()).hexdigest()
