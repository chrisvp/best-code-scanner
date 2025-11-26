import hashlib
import os
from typing import List, Optional, Literal

from app.services.intelligence.ast_parser import ASTParser


ChunkStrategy = Literal["lines", "functions", "smart"]


class FileChunker:
    """Splits files into semantic chunks for analysis"""

    def __init__(self, max_tokens: int = 8000, strategy: ChunkStrategy = "smart"):
        """
        Initialize chunker.

        Args:
            max_tokens: Target tokens per chunk (default 8k). Chunks can exceed
                       this slightly to avoid splitting mid-function.
            strategy: Chunking strategy
                - "lines": Simple line-based chunking with overlap
                - "functions": One function per chunk (most granular)
                - "smart": Batch functions together, respecting function boundaries (default)
        """
        self.max_tokens = max_tokens
        self.strategy = strategy
        self.parser = ASTParser()

    def chunk_file(self, file_path: str, content: str = None) -> List[dict]:
        """
        Chunk a file into semantic units.
        Returns list of chunk dicts with metadata.
        """
        if content is None:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        # Small file - single chunk regardless of strategy
        if self._count_tokens(content) <= self.max_tokens:
            return [{
                'chunk_index': 0,
                'chunk_type': 'full_file',
                'symbol_name': None,
                'start_line': 1,
                'end_line': content.count('\n') + 1,
                'content_hash': hashlib.md5(content.encode()).hexdigest()
            }]

        # Strategy: lines - simple chunking
        if self.strategy == "lines":
            return self._simple_chunk(content)

        # Strategy: functions or smart - try semantic chunking
        try:
            ext = os.path.splitext(file_path)[1].lstrip('.')
            if ext in self.parser.parsers:
                if self.strategy == "functions":
                    return self._chunk_by_functions(file_path, content)
                else:  # smart
                    return self._chunk_smart(file_path, content)
        except Exception as e:
            print(f"Semantic chunking failed for {file_path}: {e}")

        # Fallback to simple chunking
        return self._simple_chunk(content)

    def _chunk_by_functions(self, file_path: str, content: str) -> List[dict]:
        """One function per chunk - most granular, most LLM calls"""
        parsed = self.parser.parse_file(file_path, content)
        chunks = []

        preamble = self._extract_preamble(parsed, content)
        functions = parsed.extract_functions()

        if not functions:
            return self._simple_chunk(content)

        lines = content.split('\n')

        for i, func in enumerate(functions):
            func_lines = lines[func.start_line - 1:func.end_line]
            func_content = '\n'.join(func_lines)
            chunk_content = preamble + '\n\n// ... (other code) ...\n\n' + func_content

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
                    'chunk_index': len(chunks),
                    'chunk_type': 'function',
                    'symbol_name': func.name,
                    'start_line': func.start_line,
                    'end_line': func.end_line,
                    'content_hash': hashlib.md5(chunk_content.encode()).hexdigest()
                })

        return chunks if chunks else self._simple_chunk(content)

    def _chunk_smart(self, file_path: str, content: str) -> List[dict]:
        """
        Smart chunking - batch functions together around token limit.
        Allows going over limit to preserve function boundaries (fuzzy chunking).
        """
        parsed = self.parser.parse_file(file_path, content)
        chunks = []

        preamble = self._extract_preamble(parsed, content)
        preamble_tokens = self._count_tokens(preamble)
        functions = parsed.extract_functions()

        if not functions:
            return self._simple_chunk(content)

        lines = content.split('\n')

        # Allow 50% overflow to avoid splitting functions
        soft_limit = self.max_tokens
        hard_limit = int(self.max_tokens * 1.5)

        # Batch functions together
        current_batch = []
        current_tokens = preamble_tokens + 50  # Reserve for separator
        batch_start_line = None
        batch_end_line = None

        for func in functions:
            func_lines = lines[func.start_line - 1:func.end_line]
            func_content = '\n'.join(func_lines)
            func_tokens = self._count_tokens(func_content)

            # Only split truly massive functions (>2x limit)
            if func_tokens + preamble_tokens > hard_limit * 2:
                # Save current batch first
                if current_batch:
                    chunks.append(self._create_batch_chunk(
                        len(chunks), current_batch, batch_start_line, batch_end_line, preamble
                    ))
                    current_batch = []
                    current_tokens = preamble_tokens + 50

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
                batch_start_line = None
                batch_end_line = None
                continue

            # If we're over soft limit and have content, save batch
            # But if adding this function keeps us under hard limit, include it first
            if current_tokens > soft_limit and current_batch:
                if current_tokens + func_tokens > hard_limit:
                    # Save current batch, start new one
                    chunks.append(self._create_batch_chunk(
                        len(chunks), current_batch, batch_start_line, batch_end_line, preamble
                    ))
                    current_batch = []
                    current_tokens = preamble_tokens + 50
                    batch_start_line = None

            # Add function to batch
            current_batch.append({
                'name': func.name,
                'content': func_content,
                'start_line': func.start_line,
                'end_line': func.end_line
            })
            current_tokens += func_tokens

            if batch_start_line is None:
                batch_start_line = func.start_line
            batch_end_line = func.end_line

        # Save final batch
        if current_batch:
            chunks.append(self._create_batch_chunk(
                len(chunks), current_batch, batch_start_line, batch_end_line, preamble
            ))

        return chunks if chunks else self._simple_chunk(content)

    def _create_batch_chunk(self, index: int, batch: List[dict], start_line: int,
                           end_line: int, preamble: str) -> dict:
        """Create a chunk from a batch of functions"""
        func_names = [f['name'] for f in batch]
        combined_content = '\n\n'.join(f['content'] for f in batch)
        full_content = preamble + '\n\n// ... (other code) ...\n\n' + combined_content

        return {
            'chunk_index': index,
            'chunk_type': 'function_batch',
            'symbol_name': ','.join(func_names),
            'start_line': start_line,
            'end_line': end_line,
            'content_hash': hashlib.md5(full_content.encode()).hexdigest()
        }

    def _extract_preamble(self, parsed, content: str) -> str:
        """Extract imports and top-level code before first function"""
        functions = parsed.extract_functions()

        if not functions:
            return ""

        first_func_line = min(f.start_line for f in functions)
        lines = content.split('\n')
        preamble_lines = lines[:first_func_line - 1]

        # Filter to just imports and globals
        filtered = []
        for line in preamble_lines:
            stripped = line.strip()
            # Keep imports, includes, defines, struct definitions
            if stripped.startswith(('import ', 'from ', '#include', '#define', '#pragma',
                                    'typedef ', 'struct ', 'enum ', 'const ', 'static ')):
                filtered.append(line)
            # Keep short variable/constant assignments
            elif '=' in stripped and len(stripped) < 100 and not stripped.startswith(('#', '//')):
                filtered.append(line)

        return '\n'.join(filtered)

    def _simple_chunk(self, content: str, chunk_size: int = None, overlap_lines: int = 10) -> List[dict]:
        """Simple line-based chunking with overlap"""
        if chunk_size is None:
            chunk_size = self.max_tokens * 3  # Use same ratio as token estimate

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

                # Start new chunk with overlap
                overlap_start_index = max(0, len(current_chunk_lines) - overlap_lines)
                overlap_content = current_chunk_lines[overlap_start_index:]

                current_chunk_lines = overlap_content
                current_size = sum(len(l) for l in current_chunk_lines)
                start_line = max(1, i - len(overlap_content))

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
        max_chars = self.max_tokens * 3 - len(preamble)
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
        """Rough token count estimate - use conservative ratio for code"""
        # Code has more tokens per char than prose (keywords, symbols, etc)
        # Use ~3 chars per token to be safe
        return len(text) // 3
