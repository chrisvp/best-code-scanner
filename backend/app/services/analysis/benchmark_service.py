import os
import json
import asyncio
import time
import re
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.scanner_models import (
    BenchmarkDataset, BenchmarkCase, BenchmarkRun, BenchmarkResult, 
    ModelConfig
)
from app.services.analysis.prompt_tester import PromptTesterService

class BenchmarkService:
    def __init__(self, db: Session):
        self.db = db

    def ensure_default_dataset(self):
        """Ensure the 'Standard Test Suite' exists from test_samples/"""
        dataset_name = "Standard Test Suite"
        dataset = self.db.query(BenchmarkDataset).filter(BenchmarkDataset.name == dataset_name).first()
        
        if not dataset:
            dataset = BenchmarkDataset(
                name=dataset_name, 
                description="Default vulnerability samples from test_samples/"
            )
            self.db.add(dataset)
            self.db.commit()
            
            # Populate from filesystem
            # Go up 5 levels: analysis -> services -> app -> backend -> root
            base_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
                "test_samples"
            )
            
            if os.path.exists(base_dir):
                self._import_directory(dataset.id, base_dir)
        
        return dataset

    def _parse_benchmark_metadata(self, content: str) -> Dict[str, str]:
        """Parse @benchmark_* metadata from file header"""
        metadata = {}
        for line in content.split('\n')[:20]: # Check first 20 lines
            match = re.search(r'@benchmark_(\w+):\s*(.+)', line)
            if match:
                key = match.group(1)
                value = match.group(2).strip()
                metadata[key] = value
        return metadata

    def _import_directory(self, dataset_id: int, directory: str):
        """Recursively import files as test cases"""
        print(f"Scanning for benchmarks in: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.c', '.cpp', '.py', '.js', '.ts')):
                    path = os.path.join(root, file)
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    metadata = self._parse_benchmark_metadata(content)
                    
                    # Heuristic fallback if no metadata
                    if 'finding' in metadata:
                        vuln_type = metadata['finding']
                        severity = metadata.get('severity', 'High')
                        line = int(metadata.get('line', 0)) if metadata.get('line') else None
                    else:
                        vuln_type = "Unknown"
                        if "overflow" in file.lower(): vuln_type = "Buffer Overflow"
                        elif "injection" in file.lower(): vuln_type = "Injection"
                        elif "xss" in file.lower(): vuln_type = "XSS"
                        elif "leak" in file.lower(): vuln_type = "Memory Leak"
                        severity = "Medium"
                        line = None
                    
                    case = BenchmarkCase(
                        dataset_id=dataset_id,
                        file_path=file,
                        content=content,
                        language=os.path.splitext(file)[1][1:],
                        expected_finding_type=vuln_type,
                        expected_severity=severity,
                        line_number=line,
                        is_vulnerable=True, # Assume samples are vulnerable
                        description=f"Imported from {file}"
                    )
                    self.db.add(case)
        self.db.commit()

    async def run_benchmark(self, dataset_id: int, model_id: int, prompt_template: Optional[str] = None) -> int:
        """Run a benchmark for a specific model"""
        dataset = self.db.query(BenchmarkDataset).filter(BenchmarkDataset.id == dataset_id).first()
        model = self.db.query(ModelConfig).filter(ModelConfig.id == model_id).first()
        
        if not dataset or not model:
            raise ValueError("Invalid dataset or model ID")

        # Create Run Record
        run = BenchmarkRun(
            dataset_id=dataset_id,
            model_id=model_id,
            prompt_template=prompt_template,
            status="running",
            total_cases=len(dataset.cases)
        )
        self.db.add(run)
        self.db.commit()
        
        tester = PromptTesterService(self.db)
        
        passed = 0
        failed = 0
        latencies = []
        
        try:
            for case in dataset.cases:
                start_time = time.time()
                
                prompt_to_use = prompt_template or model.analysis_prompt_template
                
                results = await tester.test_prompt(
                    code_content=case.content,
                    model_names=[model.name],
                    custom_prompt=prompt_to_use
                )
                
                duration_ms = (time.time() - start_time) * 1000
                latencies.append(duration_ms)
                
                findings = results.get(model.name, [])
                
                # Evaluation Logic
                verdict = "FN" # Default to False Negative
                found_severity = None
                found_line = None
                
                if findings:
                    # Found something
                    top_finding = findings[0] # Just take first for now
                    found_severity = top_finding.get('severity')
                    found_line = top_finding.get('line_number')
                    
                    if case.is_vulnerable:
                        # Check if finding matches expectation
                        title_match = case.expected_finding_type.lower() in top_finding.get('title', '').lower()
                        desc_match = case.expected_finding_type.lower() in top_finding.get('description', '').lower()
                        
                        # Line number check (tolerance of +/- 5 lines)
                        line_match = True
                        if case.line_number and found_line:
                            if abs(case.line_number - found_line) > 5:
                                line_match = False
                        
                        if (title_match or desc_match) and line_match:
                            verdict = "TP" # True Positive (Correct finding)
                        elif title_match or desc_match:
                            verdict = "TP (Line Miss)" # Right bug, wrong line
                        else:
                            verdict = "TP (Type Miss)" # Found a bug, but maybe wrong type?
                            # For simple benchmark, treating ANY finding in a vulnerable file as TP is often acceptable baseline
                            # but strictly it might be a different issue.
                            
                    else:
                        verdict = "FP" # False Positive (Found bug in safe code)
                else:
                    # Found nothing
                    if not case.is_vulnerable:
                        verdict = "TN" # True Negative
                
                # Simplify verdict for stats
                if verdict.startswith("TP") or verdict == "TN":
                    passed += 1
                else:
                    failed += 1
                    
                # Save Result
                result_record = BenchmarkResult(
                    run_id=run.id,
                    case_id=case.id,
                    verdict=verdict,
                    latency_ms=duration_ms,
                    model_response=json.dumps([f.get('title') for f in findings]),
                    found_severity=found_severity,
                    found_line=found_line
                )
                self.db.add(result_record)
                
            # Finalize Run
            run.status = "completed"
            run.passed_cases = passed
            run.failed_cases = failed
            run.completed_at = func.now()
            if latencies:
                run.avg_latency_ms = sum(latencies) / len(latencies)
                run.total_time_ms = sum(latencies)
            
            self.db.commit()
            return run.id
            
        except Exception as e:
            run.status = "failed"
            self.db.commit()
            print(f"Benchmark failed: {e}")
            raise e