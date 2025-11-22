import os
import asyncio
from typing import List, Dict, Optional
from sqlalchemy.orm import Session

from app.models.scanner_models import Symbol, SymbolReference, ImportRelation
from app.services.intelligence.ast_parser import ASTParser
from app.services.orchestration.cache import AnalysisCache


class CodeIndexer:
    """Builds and maintains the code index for a scan"""

    def __init__(self, scan_id: int, db: Session, cache: AnalysisCache):
        self.scan_id = scan_id
        self.db = db
        self.cache = cache
        self.parser = ASTParser()
        self.module_map: Dict[str, str] = {}  # module_name -> file_path

    async def build_index(self, root_dir: str, incremental: bool = False):
        """Build complete code index for directory"""
        files = self._discover_files(root_dir)

        if incremental:
            files = self._filter_changed_files(files)

        # Build module map first
        self._build_module_map(root_dir, files)

        # Index files with controlled concurrency
        semaphore = asyncio.Semaphore(20)

        async def index_with_semaphore(f):
            async with semaphore:
                await self._index_file(f)

        await asyncio.gather(*[index_with_semaphore(f) for f in files])

        self.db.commit()

    def _discover_files(self, root_dir: str) -> List[str]:
        """Discover all supported source files"""
        supported = {'.py', '.c', '.cpp', '.h', '.hpp'}
        files = []

        for root, _, filenames in os.walk(root_dir):
            for filename in filenames:
                ext = os.path.splitext(filename)[1]
                if ext in supported:
                    files.append(os.path.join(root, filename))

        return files

    def _filter_changed_files(self, files: List[str]) -> List[str]:
        """Filter to only changed files for incremental indexing"""
        # TODO: Compare with previous scan's file hashes
        return files

    def _build_module_map(self, root_dir: str, files: List[str]):
        """Map module names to file paths"""
        for file_path in files:
            rel_path = os.path.relpath(file_path, root_dir)

            if file_path.endswith('.py'):
                # Python: app/utils/config.py -> app.utils.config
                module = rel_path[:-3].replace(os.sep, '.').replace('/', '.')
                self.module_map[module] = file_path

                # Also map filename alone
                filename = os.path.basename(file_path)[:-3]
                if filename not in self.module_map:
                    self.module_map[filename] = file_path
            else:
                # C/C++: map by filename
                filename = os.path.basename(file_path)
                self.module_map[filename] = file_path

    async def _index_file(self, file_path: str):
        """Index a single file"""
        try:
            # Check cache first
            mtime = os.path.getmtime(file_path)
            parsed = self.cache.get_ast(file_path, mtime)

            if not parsed:
                parsed = self.parser.parse_file(file_path)
                self.cache.set_ast(file_path, mtime, parsed)

            # Extract and store functions
            for func in parsed.extract_functions():
                qualified = self._make_qualified_name(file_path, func.qualified_name)
                symbol = Symbol(
                    scan_id=self.scan_id,
                    name=func.name,
                    qualified_name=qualified,
                    symbol_type='method' if func.is_method else 'function',
                    file_path=file_path,
                    start_line=func.start_line,
                    end_line=func.end_line,
                    metadata={
                        'params': func.params,
                        'return_type': func.return_type,
                        'docstring': func.docstring
                    }
                )
                self.db.add(symbol)

            # Extract and store classes
            for cls in parsed.extract_classes():
                qualified = self._make_qualified_name(file_path, cls.name)
                symbol = Symbol(
                    scan_id=self.scan_id,
                    name=cls.name,
                    qualified_name=qualified,
                    symbol_type='class',
                    file_path=file_path,
                    start_line=cls.start_line,
                    end_line=cls.end_line,
                    metadata={
                        'bases': cls.bases,
                        'docstring': cls.docstring
                    }
                )
                self.db.add(symbol)

            # Extract and store imports
            for imp in parsed.extract_imports():
                resolved = self._resolve_import(imp.module)
                relation = ImportRelation(
                    scan_id=self.scan_id,
                    importer_file=file_path,
                    imported_module=imp.module,
                    imported_names=imp.names,
                    resolved_file=resolved
                )
                self.db.add(relation)

            # Extract and store call references
            for call in parsed.extract_calls():
                # Store reference (will be resolved later)
                ref = SymbolReference(
                    scan_id=self.scan_id,
                    symbol_id=None,  # Resolve later
                    from_file=file_path,
                    from_line=call.line,
                    from_symbol_id=None,
                    reference_type='call'
                )
                # Note: Full resolution requires second pass
                # For now, we store partial reference

        except Exception as e:
            print(f"Error indexing {file_path}: {e}")

    def _resolve_import(self, module_name: str) -> Optional[str]:
        """Resolve import to actual file path"""
        # Direct match
        if module_name in self.module_map:
            return self.module_map[module_name]

        # Try parent modules
        parts = module_name.split('.')
        for i in range(len(parts), 0, -1):
            partial = '.'.join(parts[:i])
            if partial in self.module_map:
                return self.module_map[partial]

        # C/C++ - try with extensions
        for ext in ['.h', '.hpp', '.c', '.cpp']:
            key = module_name + ext
            if key in self.module_map:
                return self.module_map[key]

        return None  # External/stdlib

    def _make_qualified_name(self, file_path: str, name: str) -> str:
        """Create fully qualified name from file path and symbol name"""
        if file_path.endswith('.py'):
            for module, path in self.module_map.items():
                if path == file_path:
                    return f"{module}.{name}"
        return f"{os.path.basename(file_path)}.{name}"

    def find_symbol(self, name: str, from_file: str = None) -> Optional[Symbol]:
        """Find a symbol by name"""
        # Exact qualified name match
        symbol = self.db.query(Symbol).filter(
            Symbol.scan_id == self.scan_id,
            Symbol.qualified_name == name
        ).first()

        if symbol:
            return symbol

        # Try simple name match
        symbol = self.db.query(Symbol).filter(
            Symbol.scan_id == self.scan_id,
            Symbol.name == name
        ).first()

        return symbol

    def get_symbol_code(self, symbol: Symbol) -> str:
        """Get the source code for a symbol"""
        try:
            with open(symbol.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            return ''.join(lines[symbol.start_line - 1:symbol.end_line])
        except Exception:
            return ""
