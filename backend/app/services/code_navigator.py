import os
from typing import List, Dict, Optional
from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_python

class CodeNavigator:
    def __init__(self):
        self.parsers = {}
        self._init_parsers()

    def _init_parsers(self):
        try:
            # C
            c_lang = Language(tree_sitter_c.language())
            c_parser = Parser()
            c_parser.set_language(c_lang)
            self.parsers['c'] = c_parser
            self.parsers['h'] = c_parser
            self.parsers['cpp'] = c_parser # Using C parser for C++ basics for now

            # Python
            py_lang = Language(tree_sitter_python.language())
            py_parser = Parser()
            py_parser.set_language(py_lang)
            self.parsers['py'] = py_parser
        except Exception as e:
            print(f"Warning: Tree-sitter initialization failed: {e}")

    def parse_file(self, file_path: str) -> Dict:
        ext = file_path.split('.')[-1]
        if ext not in self.parsers:
            return {}

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            tree = self.parsers[ext].parse(bytes(content, "utf8"))
            root_node = tree.root_node
            
            return {
                "functions": self._extract_functions(root_node, content),
                "imports": self._extract_imports(root_node, content)
            }
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return {}

    def build_index(self, root_dir: str):
        """Builds a mapping of filename -> full_path for the scanned directory."""
        self.file_index = {}
        for root, _, files in os.walk(root_dir):
            for file in files:
                self.file_index[file] = os.path.join(root, file)

    def resolve_reference(self, ref_name: str) -> Optional[str]:
        """
        Resolves a reference (e.g., 'stdio.h', 'utils.py') to a full path.
        Naively matches filename for now.
        """
        # Direct match
        if ref_name in self.file_index:
            return self.file_index[ref_name]
        
        # Try adding extensions if missing (for Python imports)
        if ref_name + ".py" in self.file_index:
            return self.file_index[ref_name + ".py"]
            
        return None

    def _extract_functions(self, node, content) -> List[str]:
        # Regex fallback for now as it's robust for a prototype
        import re
        # C/C++: void foo(int a)
        # Python: def foo():
        funcs = []
        # Very basic regex, can be improved with tree-sitter later
        matches = re.findall(r'(?:def|void|int|char|bool|float|double)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', content)
        return matches

    def _extract_imports(self, node, content) -> List[str]:
        import re
        imports = []
        
        # C/C++ Includes
        # #include "foo.h" or <foo.h>
        includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', content)
        imports.extend(includes)
        
        # Python Imports
        # import foo
        # from foo import bar
        py_imports = re.findall(r'^(?:from|import)\s+([a-zA-Z0-9_\.]+)', content, re.MULTILINE)
        imports.extend(py_imports)
        
        return imports

code_navigator = CodeNavigator()
