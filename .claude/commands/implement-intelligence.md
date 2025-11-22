# Implement Code Intelligence System

Create the tree-sitter based code intelligence system for context-aware scanning.

## Task

Implement full code intelligence with AST parsing, indexing, and context retrieval.

## Files to Create

### 1. backend/app/services/intelligence/__init__.py
Export main classes.

### 2. backend/app/services/intelligence/ast_parser.py

#### Dataclasses
```python
@dataclass
class FunctionDef:
    name: str
    qualified_name: str
    params: List[str]
    return_type: Optional[str]
    start_line: int
    end_line: int
    is_method: bool = False
    docstring: Optional[str] = None

@dataclass
class ClassDef:
    name: str
    bases: List[str]
    start_line: int
    end_line: int
    docstring: Optional[str] = None

@dataclass
class ImportDef:
    module: str
    names: Optional[List[str]]
    line: int

@dataclass
class CallSite:
    callee_name: str
    line: int
    arguments: List[str]
```

#### ASTParser class
- Initialize tree-sitter parsers for Python, C, C++
- parse_file(file_path, content=None) -> ParsedFile

#### ParsedFile class
- Store path, content, tree, language
- get_text(node) -> str
- extract_functions() -> List[FunctionDef]
- extract_classes() -> List[ClassDef]
- extract_imports() -> List[ImportDef]
- extract_calls() -> List[CallSite]

Implement language-specific extraction:
- Python: function_definition, class_definition, import_statement, call
- C/C++: function_definition, preproc_include, call_expression

### 3. backend/app/services/intelligence/code_indexer.py

#### CodeIndexer class
```python
def __init__(self, scan_id: int, db, cache):
    self.scan_id = scan_id
    self.db = db
    self.cache = cache
    self.parser = ASTParser()
    self.module_map = {}  # module_name -> file_path

async def build_index(self, root_dir: str, incremental: bool = False):
    # Discover files
    # Build module map
    # Parse and index each file (parallel with semaphore)
    # Build cross-references

def _build_module_map(self, root_dir: str, files: List[str]):
    # Map Python modules: app/utils/config.py -> app.utils.config
    # Map C/C++ by filename

async def _index_file(self, file_path: str):
    # Parse file
    # Store symbols (functions, classes)
    # Store imports with resolution

def _resolve_import(self, module_name: str) -> Optional[str]:
    # Direct match
    # Parent module match
    # C/C++ extension match
```

### 4. backend/app/services/intelligence/context_retriever.py

#### ContextRetriever class
```python
def __init__(self, scan_id: int, db):
    self.scan_id = scan_id
    self.db = db

async def get_context(self, chunk, max_tokens: int = 4000) -> str:
    # Get calls in chunk
    # Fetch definitions of called functions
    # Get callers of functions in chunk
    # Format as context string

def find_definition(self, symbol_name: str, from_file: str = None) -> Optional[Symbol]:
    # Qualified name lookup
    # Import context lookup
    # Simple name lookup

def find_callers(self, qualified_name: str) -> List[Symbol]:
    # Query SymbolReference for calls to this symbol
    # Return calling functions

def find_callees(self, qualified_name: str) -> List[Symbol]:
    # Query SymbolReference for calls from this symbol

def get_symbol_code(self, symbol) -> str:
    # Read file and extract lines start_line:end_line
```

## Key Implementation Details

### Tree-sitter Node Traversal
```python
def visit(node, callback):
    callback(node)
    for child in node.children:
        visit(child, callback)
```

### Python Function Extraction
- Node type: 'function_definition'
- Get name from child_by_field_name('name')
- Get params from child_by_field_name('parameters')
- Get return type from child_by_field_name('return_type')
- Check parent for class context (method vs function)

### C Function Extraction
- Node type: 'function_definition'
- Get type from child_by_field_name('type')
- Navigate declarator to find identifier (name)
- Find parameter_list for params

### Import Resolution
For Python `from app.utils import helper`:
1. Look up 'app.utils' in module_map
2. Find 'helper' symbol in that file

For C `#include "utils.h"`:
1. Look up 'utils.h' in module_map

## Testing

Create test file with known structure, verify:
- All functions extracted
- All imports found
- References resolve correctly
- Context string is useful
