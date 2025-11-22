from tree_sitter import Language, Parser, Node
from typing import List, Dict, Optional
from dataclasses import dataclass, field
import tree_sitter_python
import tree_sitter_c
import tree_sitter_cpp


@dataclass
class FunctionDef:
    """Extracted function definition"""
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
    """Extracted class definition"""
    name: str
    bases: List[str]
    start_line: int
    end_line: int
    docstring: Optional[str] = None


@dataclass
class ImportDef:
    """Extracted import statement"""
    module: str
    names: Optional[List[str]]
    line: int


@dataclass
class CallSite:
    """Extracted function call"""
    callee_name: str
    line: int
    arguments: List[str] = field(default_factory=list)


class ASTParser:
    """Language-aware AST parser using tree-sitter"""

    def __init__(self):
        self.parsers: Dict[str, Parser] = {}
        self._init_languages()

    def _init_languages(self):
        """Initialize tree-sitter parsers for supported languages"""
        try:
            # Python
            py_lang = Language(tree_sitter_python.language())
            py_parser = Parser(py_lang)
            self.parsers['py'] = py_parser

            # C
            c_lang = Language(tree_sitter_c.language())
            c_parser = Parser(c_lang)
            self.parsers['c'] = c_parser
            self.parsers['h'] = c_parser

            # C++
            cpp_lang = Language(tree_sitter_cpp.language())
            cpp_parser = Parser(cpp_lang)
            self.parsers['cpp'] = cpp_parser
            self.parsers['hpp'] = cpp_parser

        except Exception as e:
            print(f"Warning: Tree-sitter initialization failed: {e}")

    def parse_file(self, file_path: str, content: str = None) -> 'ParsedFile':
        """Parse a file and return ParsedFile object"""
        ext = file_path.rsplit('.', 1)[-1] if '.' in file_path else ''
        if ext not in self.parsers:
            raise ValueError(f"Unsupported file type: {ext}")

        if content is None:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        tree = self.parsers[ext].parse(bytes(content, 'utf8'))
        return ParsedFile(file_path, content, tree, ext)


class ParsedFile:
    """Parsed file with extraction methods"""

    def __init__(self, path: str, content: str, tree, language: str):
        self.path = path
        self.content = content
        self.tree = tree
        self.language = language
        self._lines = content.split('\n')

    def get_text(self, node: Node) -> str:
        """Get text content of a node"""
        return self.content[node.start_byte:node.end_byte]

    def get_line(self, line_num: int) -> str:
        """Get a specific line (1-indexed)"""
        if 0 < line_num <= len(self._lines):
            return self._lines[line_num - 1]
        return ""

    def extract_functions(self) -> List[FunctionDef]:
        """Extract all function definitions"""
        if self.language == 'py':
            return self._extract_python_functions()
        elif self.language in ('c', 'cpp', 'h', 'hpp'):
            return self._extract_c_functions()
        return []

    def extract_classes(self) -> List[ClassDef]:
        """Extract all class definitions"""
        if self.language == 'py':
            return self._extract_python_classes()
        elif self.language in ('cpp', 'hpp'):
            return self._extract_cpp_classes()
        return []

    def extract_imports(self) -> List[ImportDef]:
        """Extract all import statements"""
        if self.language == 'py':
            return self._extract_python_imports()
        elif self.language in ('c', 'cpp', 'h', 'hpp'):
            return self._extract_c_includes()
        return []

    def extract_calls(self) -> List[CallSite]:
        """Extract all function calls"""
        calls = []

        def visit(node: Node):
            if self.language == 'py' and node.type == 'call':
                call = self._parse_python_call(node)
                if call:
                    calls.append(call)
            elif self.language in ('c', 'cpp', 'h', 'hpp') and node.type == 'call_expression':
                call = self._parse_c_call(node)
                if call:
                    calls.append(call)

            for child in node.children:
                visit(child)

        visit(self.tree.root_node)
        return calls

    # Python extraction methods
    def _extract_python_functions(self) -> List[FunctionDef]:
        functions = []

        def visit(node: Node, class_name: Optional[str] = None):
            if node.type == 'function_definition':
                func = self._parse_python_function(node, class_name)
                if func:
                    functions.append(func)
            elif node.type == 'class_definition':
                name_node = node.child_by_field_name('name')
                cname = self.get_text(name_node) if name_node else None
                for child in node.children:
                    visit(child, cname)
            else:
                for child in node.children:
                    visit(child, class_name)

        visit(self.tree.root_node)
        return functions

    def _parse_python_function(self, node: Node, class_name: Optional[str]) -> Optional[FunctionDef]:
        name_node = node.child_by_field_name('name')
        if not name_node:
            return None

        name = self.get_text(name_node)

        # Extract parameters
        params = []
        params_node = node.child_by_field_name('parameters')
        if params_node:
            for child in params_node.children:
                if child.type in ('identifier', 'typed_parameter', 'default_parameter'):
                    params.append(self.get_text(child))

        # Return type
        return_node = node.child_by_field_name('return_type')
        return_type = self.get_text(return_node) if return_node else None

        # Docstring
        docstring = self._extract_docstring(node)

        return FunctionDef(
            name=name,
            qualified_name=f"{class_name}.{name}" if class_name else name,
            params=params,
            return_type=return_type,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            is_method=class_name is not None,
            docstring=docstring
        )

    def _extract_python_classes(self) -> List[ClassDef]:
        classes = []

        def visit(node: Node):
            if node.type == 'class_definition':
                cls = self._parse_python_class(node)
                if cls:
                    classes.append(cls)
            for child in node.children:
                visit(child)

        visit(self.tree.root_node)
        return classes

    def _parse_python_class(self, node: Node) -> Optional[ClassDef]:
        name_node = node.child_by_field_name('name')
        if not name_node:
            return None

        name = self.get_text(name_node)

        # Extract base classes
        bases = []
        for child in node.children:
            if child.type == 'argument_list':
                for arg in child.children:
                    if arg.type in ('identifier', 'attribute'):
                        bases.append(self.get_text(arg))

        return ClassDef(
            name=name,
            bases=bases,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            docstring=self._extract_docstring(node)
        )

    def _extract_python_imports(self) -> List[ImportDef]:
        imports = []

        def visit(node: Node):
            if node.type == 'import_statement':
                for child in node.children:
                    if child.type == 'dotted_name':
                        imports.append(ImportDef(
                            module=self.get_text(child),
                            names=None,
                            line=node.start_point[0] + 1
                        ))
            elif node.type == 'import_from_statement':
                module_node = node.child_by_field_name('module_name')
                module = self.get_text(module_node) if module_node else ""

                names = []
                for child in node.children:
                    if child.type == 'dotted_name' and child != module_node:
                        names.append(self.get_text(child))
                    elif child.type == 'aliased_import':
                        name_node = child.child_by_field_name('name')
                        if name_node:
                            names.append(self.get_text(name_node))

                imports.append(ImportDef(
                    module=module,
                    names=names if names else None,
                    line=node.start_point[0] + 1
                ))

            for child in node.children:
                visit(child)

        visit(self.tree.root_node)
        return imports

    def _parse_python_call(self, node: Node) -> Optional[CallSite]:
        func_node = node.child_by_field_name('function')
        if not func_node:
            return None

        callee = self.get_text(func_node)

        # Extract arguments
        args = []
        args_node = node.child_by_field_name('arguments')
        if args_node:
            for child in args_node.children:
                if child.type not in ('(', ')', ','):
                    args.append(self.get_text(child))

        return CallSite(
            callee_name=callee,
            line=node.start_point[0] + 1,
            arguments=args
        )

    # C/C++ extraction methods
    def _extract_c_functions(self) -> List[FunctionDef]:
        functions = []

        def visit(node: Node):
            if node.type == 'function_definition':
                func = self._parse_c_function(node)
                if func:
                    functions.append(func)
            for child in node.children:
                visit(child)

        visit(self.tree.root_node)
        return functions

    def _parse_c_function(self, node: Node) -> Optional[FunctionDef]:
        declarator = node.child_by_field_name('declarator')
        if not declarator:
            return None

        # Find function name
        name = None
        params = []

        def find_name(n):
            nonlocal name
            if n.type == 'identifier':
                name = self.get_text(n)
                return True
            for child in n.children:
                if find_name(child):
                    return True
            return False

        find_name(declarator)

        # Find parameters
        def find_params(n):
            if n.type == 'parameter_list':
                return n
            for child in n.children:
                result = find_params(child)
                if result:
                    return result
            return None

        param_list = find_params(declarator)
        if param_list:
            for child in param_list.children:
                if child.type == 'parameter_declaration':
                    params.append(self.get_text(child))

        # Return type
        type_node = node.child_by_field_name('type')
        return_type = self.get_text(type_node) if type_node else None

        if not name:
            return None

        return FunctionDef(
            name=name,
            qualified_name=name,
            params=params,
            return_type=return_type,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            is_method=False,
            docstring=None
        )

    def _extract_cpp_classes(self) -> List[ClassDef]:
        classes = []

        def visit(node: Node):
            if node.type in ('class_specifier', 'struct_specifier'):
                name_node = node.child_by_field_name('name')
                if name_node:
                    classes.append(ClassDef(
                        name=self.get_text(name_node),
                        bases=[],  # TODO: extract base classes
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1
                    ))
            for child in node.children:
                visit(child)

        visit(self.tree.root_node)
        return classes

    def _extract_c_includes(self) -> List[ImportDef]:
        imports = []

        def visit(node: Node):
            if node.type == 'preproc_include':
                path_node = node.child_by_field_name('path')
                if path_node:
                    path = self.get_text(path_node).strip('<>"')
                    imports.append(ImportDef(
                        module=path,
                        names=None,
                        line=node.start_point[0] + 1
                    ))
            for child in node.children:
                visit(child)

        visit(self.tree.root_node)
        return imports

    def _parse_c_call(self, node: Node) -> Optional[CallSite]:
        func_node = node.child_by_field_name('function')
        if not func_node:
            return None

        callee = self.get_text(func_node)

        # Extract arguments
        args = []
        args_node = node.child_by_field_name('arguments')
        if args_node:
            for child in args_node.children:
                if child.type not in ('(', ')', ','):
                    args.append(self.get_text(child))

        return CallSite(
            callee_name=callee,
            line=node.start_point[0] + 1,
            arguments=args
        )

    def _extract_docstring(self, node: Node) -> Optional[str]:
        """Extract docstring from function/class body"""
        body = node.child_by_field_name('body')
        if body and body.children:
            first_stmt = body.children[0]
            if first_stmt.type == 'expression_statement':
                expr = first_stmt.children[0] if first_stmt.children else None
                if expr and expr.type == 'string':
                    return self.get_text(expr).strip('"""\'\'\'')
        return None
