import hashlib
import os
from typing import List, Optional

from app.services.intelligence.ast_parser import ASTParser


class FileChunker:
    """Splits files into semantic chunks for analysis"""

    def __init__(self, max_tokens: int = 3000):
        self.max_tokens = max_tokens
        self.parser = ASTParser()

    def chunk_file(self, file_path: str, content: str = None) -> List[dict]:
        """
        Chunk a file into semantic units.
        Returns list of chunk dicts with metadata.
        """
        if content is None:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        # Small file - single chunk
        if self._count_tokens(content) <= self.max_tokens:
            return [{
                'chunk_index': 0,
                'chunk_type': 'full_file',
                'symbol_name': None,
                'start_line': 1,
                'end_line': content.count('\n') + 1,
                'content_hash': hashlib.md5(content.encode()).hexdigest()
            }]

        # Try semantic chunking with tree-sitter
        try:
            ext = os.path.splitext(file_path)[1].lstrip('.')
            if ext in self.parser.parsers:
                return self._chunk_by_symbols(file_path, content)
        except Exception as e:
            print(f"Semantic chunking failed for {file_path}: {e}")

        # Fallback to simple chunking
        return self._simple_chunk(content)

    def _chunk_by_symbols(self, file_path: str, content: str) -> List[dict]:
        """Chunk by functions and classes"""
        parsed = self.parser.parse_file(file_path, content)
        chunks = []

        # Extract preamble (imports, globals)
        preamble = self._extract_preamble(parsed, content)

        # Get all functions
        functions = parsed.extract_functions()

        if not functions:
            # No functions found - fall back to simple
            return self._simple_chunk(content)

        for i, func in enumerate(functions):
            # Get function content
            lines = content.split('\n')
            func_lines = lines[func.start_line - 1:func.end_line]
            func_content = '\n'.join(func_lines)

            # Combine with preamble
            chunk_content = preamble + '\n\n# ... (other code) ...\n\n' + func_content

            # Check if too large
            if self._count_tokens(chunk_content) > self.max_tokens:
                # Split large function
                sub_chunks = self._split_large_content(func_content, func.start_line, preamble)
                for j, sub in enumerate(sub_chunks):
                    chunks.append({
                        'chunk_index': len(chunks),
                        'chunk_type': 'function_part',
                        'symbol_name': f"{func.name}_part{j}",
                        'start_line': sub['start_line'],
                        'end_line': sub['end_line'],
                        'content_hash': hashlib.md5(sub['content'].encode()).hexdigest()
                    })
            else:
                chunks.append({
                    'chunk_index': i,
                    'chunk_type': 'function',
                    'symbol_name': func.name,
                    'start_line': func.start_line,
                    'end_line': func.end_line,
                    'content_hash': hashlib.md5(chunk_content.encode()).hexdigest()
                })

        # If no chunks created, fall back
        if not chunks:
            return self._simple_chunk(content)

        return chunks

    def _extract_preamble(self, parsed, content: str) -> str:
        """Extract imports and top-level code before first function"""
        functions = parsed.extract_functions()

        if not functions:
            return ""

        first_func_line = min(f.start_line for f in functions)
        lines = content.split('\n')

        # Get everything before first function
        preamble_lines = lines[:first_func_line - 1]

        # Filter to just imports and globals
        filtered = []
        for line in preamble_lines:
            stripped = line.strip()
            # Keep imports, from imports, includes, #defines
            if stripped.startswith(('import ', 'from ', '#include', '#define', '#pragma')):
                filtered.append(line)
            # Keep short variable assignments
            elif '=' in stripped and len(stripped) < 100 and not stripped.startswith('#'):
                filtered.append(line)

        return '\n'.join(filtered)

    def _simple_chunk(self, content: str, chunk_size: int = None) -> List[dict]:
        """Simple line-based chunking"""
        if chunk_size is None:
            chunk_size = self.max_tokens * 4  # Rough char estimate

        lines = content.split('\n')
        chunks = []
        current_chunk_lines = []
        current_size = 0
        start_line = 1

        for i, line in enumerate(lines, 1):
            line_size = len(line)

            if current_size + line_size > chunk_size and current_chunk_lines:
                # Save current chunk
                chunk_content = '\n'.join(current_chunk_lines)
                chunks.append({
                    'chunk_index': len(chunks),
                    'chunk_type': 'block',
                    'symbol_name': None,
                    'start_line': start_line,
                    'end_line': i - 1,
                    'content_hash': hashlib.md5(chunk_content.encode()).hexdigest()
                })

                # Start new chunk
                current_chunk_lines = []
                current_size = 0
                start_line = i

            current_chunk_lines.append(line)
            current_size += line_size

        # Save last chunk
        if current_chunk_lines:
            chunk_content = '\n'.join(current_chunk_lines)
            chunks.append({
                'chunk_index': len(chunks),
                'chunk_type': 'block',
                'symbol_name': None,
                'start_line': start_line,
                'end_line': len(lines),
                'content_hash': hashlib.md5(chunk_content.encode()).hexdigest()
            })

        return chunks

    def _split_large_content(self, content: str, base_line: int, preamble: str) -> List[dict]:
        """Split large content into smaller pieces"""
        max_chars = self.max_tokens * 4 - len(preamble)
        lines = content.split('\n')
        chunks = []
        current_lines = []
        current_size = 0
        start_offset = 0

        for i, line in enumerate(lines):
            if current_size + len(line) > max_chars and current_lines:
                chunks.append({
                    'start_line': base_line + start_offset,
                    'end_line': base_line + i - 1,
                    'content': preamble + '\n\n' + '\n'.join(current_lines)
                })
                current_lines = []
                current_size = 0
                start_offset = i

            current_lines.append(line)
            current_size += len(line)

        if current_lines:
            chunks.append({
                'start_line': base_line + start_offset,
                'end_line': base_line + len(lines) - 1,
                'content': preamble + '\n\n' + '\n'.join(current_lines)
            })

        return chunks

    def _count_tokens(self, text: str) -> int:
        """Rough token count estimate"""
        return len(text) // 4
