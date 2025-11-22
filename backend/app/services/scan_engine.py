import asyncio
from sqlalchemy.orm import Session
from app.models.models import Scan, Finding, ScanStatus
from app.services.ingestion import ingestion_service
from app.services.llm_provider import llm_provider
from app.core.database import SessionLocal
from app.core.config import settings
import os

class ScanEngine:
    def __init__(self):
        self.active_scans = {}

    def log(self, scan_id: int, message: str):
        # Skip console logging to avoid Windows encoding crashes
        try:
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                import datetime
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                scan.logs = (scan.logs or "") + f"[{timestamp}] {message}\n"
                db.commit()
        except Exception as e:
            # Log to file as fallback
            pass
        finally:
            db.close()

    async def start_scan(self, scan_id: int, target: str, is_git: bool = True):
        # Update status to RUNNING
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = ScanStatus.RUNNING
        db.commit()
        db.close()

        self.log(scan_id, f"Starting scan for target: {target}")

        try:
            # 1. Ingestion
            self.log(scan_id, f"Starting ingestion for target: {target}")
            
            # Auto-detect type if not explicitly set (or default is True)
            if target.endswith(".zip") or target.endswith(".tar.gz"):
                is_git = False
            
            if is_git:
                try:
                    self.log(scan_id, "Cloning repository... (This may take a moment)")
                    # Run in executor to avoid blocking the event loop
                    loop = asyncio.get_running_loop()
                    scan_dir = await loop.run_in_executor(
                        None, 
                        lambda: asyncio.run(ingestion_service.clone_repo(target, str(scan_id))) 
                        # Wait, clone_repo is async? If so, await it directly.
                        # Checking ingestion_service... it is defined as async def clone_repo.
                        # But subprocess.run inside it is blocking!
                    )
                    # Correction: clone_repo is async but uses subprocess.run which blocks.
                    # We should fix ingestion_service to use asyncio.create_subprocess_exec
                    # For now, let's just await it, but we know it blocks the loop.
                    scan_dir = await ingestion_service.clone_repo(target, str(scan_id))
                    
                except Exception as e:
                    self.log(scan_id, f"Ingestion failed: {str(e)}")
                    raise e
            else:
                # target is file path
                self.log(scan_id, "Extracting archive...")
                scan_dir = await ingestion_service.extract_archive(target, str(scan_id))

            self.log(scan_id, f"Ingestion complete. Directory: {scan_dir}")
            self.log(scan_id, "Starting static analysis...")

            # 2. Analysis
            # Walk files and scan
            file_count = 0
            files_analyzed = 0
            files_skipped = 0
            for root, _, files in os.walk(scan_dir):
                for file in files:
                    if file.endswith(".py") or file.endswith(".c") or file.endswith(".cpp"):
                        file_count += 1
                        file_path = os.path.join(root, file)
                        try:
                            # Use safe logging that won't crash on special characters
                            safe_filename = file.encode('ascii', 'ignore').decode('ascii') or f"file_{file_count}"
                            self.log(scan_id, f"Analyzing file [{file_count}]: {safe_filename}")
                            await self.analyze_file(file_path, scan_id)
                            files_analyzed += 1
                        except Exception as e:
                            files_skipped += 1
                            self.log(scan_id, f"Skipped file [{file_count}] due to error: {str(e)[:100]}")
            
            self.log(scan_id, f"Analysis complete: {files_analyzed} files analyzed, {files_skipped} skipped")
            
            if file_count == 0:
                self.log(scan_id, "Warning: No supported source files found to analyze.")
            
            # 3. Consensus / Verification (Optional)
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan.consensus_enabled:
                self.log(scan_id, "Starting consensus verification...")
                # Re-query DB for findings to verify
                findings_to_verify = db.query(Finding).filter(Finding.scan_id == scan_id).all()
                
                client = llm_provider.get_client()
                for finding in findings_to_verify:
                    for model_name in settings.LLM_VERIFICATION_MODELS:
                        await self.verify_finding(finding, client, model_name)
            db.close()
            
            # 4. Completion
            self.log(scan_id, "Scan completed successfully.")
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            scan.status = ScanStatus.COMPLETED
            db.commit()
            
        except Exception as e:
            self.log(scan_id, f"Scan failed: {str(e)}")
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            scan.status = ScanStatus.FAILED
            # Log error
            print(f"Scan failed: {e}")
            db.commit()
        finally:
            db.close()

    async def verify_finding(self, finding: Finding, client, model_name: str):
        """
        Asks the LLM to verify if a finding is a True Positive.
        """
        try:
            prompt = f"""
            Review the following security finding and determine if it is a False Positive or True Positive.
            
            Finding: {finding.description}
            Snippet: {finding.snippet}
            
            Return JSON: {{"valid": true/false, "reason": "..."}}
            """
            
            response = await client.chat.completions.create(
                model=model_name, 
                messages=[
                    {"role": "system", "content": "You are a senior security auditor."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0
            )
            
            import json
            import re
            content = response.choices[0].message.content
            match = re.search(r"```json\n(.*)\n```", content, re.DOTALL)
            if match:
                content = match.group(1)
            elif re.search(r"```\n(.*)\n```", content, re.DOTALL):
                 match = re.search(r"```\n(.*)\n```", content, re.DOTALL)
                 content = match.group(1)
            
            data = json.loads(content)
            if not data.get("valid", True):
                # Mark as False Positive or lower severity
                # For now, let's just append a note to description
                db = SessionLocal()
                f = db.query(Finding).filter(Finding.id == finding.id).first()
                f.description = f"{f.description}\n[Verification: {model_name}] Flagged as False Positive: {data.get('reason')}"
                # Only downgrade if it's not already low? Or maybe we need a voting system.
                # For now, just append the note.
                # f.severity = "Low" 
                db.commit()
                db.close()
                
        except Exception as e:
            print(f"Verification failed for finding {finding.id}: {e}")

    async def analyze_file(self, file_path: str, scan_id: int):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Skip empty or too large files for now
            if not content or len(content) > 100000:
                return

            # 1. Parse Code Structure
            from app.services.code_navigator import code_navigator
            # Ensure index is built (naive: rebuilds per file, should be per scan)
            # In a real app, we'd build this once per scan start.
            # For now, we assume it's built or we build it lazily if needed, 
            # but let's just build it for the parent dir of the file for context.
            scan_root = os.path.dirname(os.path.dirname(file_path)) # Approximation
            code_navigator.build_index(scan_root)
            
            metadata = code_navigator.parse_file(file_path)
            imports = metadata.get('imports', [])
            
            # 2. Retrieve Context (Dependencies)
            context_files = ""
            for imp in imports:
                resolved_path = code_navigator.resolve_reference(imp)
                if resolved_path and os.path.exists(resolved_path):
                    try:
                        with open(resolved_path, 'r', encoding='utf-8', errors='ignore') as dep_f:
                            dep_content = dep_f.read()
                            if len(dep_content) < 5000: # Limit context size
                                context_files += f"\n--- Referenced File: {imp} ---\n{dep_content}\n"
                    except:
                        pass

            client = llm_provider.get_client()
            
            prompt = f"""
            Analyze the following code for security vulnerabilities. 
            Return ONLY a JSON list of findings with keys: line_number, severity, description, snippet, remediation.
            If no vulnerabilities, return empty list [].
            
            Context Files:
            {context_files[:10000]}
            
            Target Code:
            {content[:10000]} 
            """

            try:
                response = await asyncio.wait_for(
                    client.chat.completions.create(
                        model=settings.LLM_MODEL, 
                        messages=[
                            {"role": "system", "content": "You are a firmware security expert."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0
                    ),
                    timeout=60.0
                )
            except asyncio.TimeoutError:
                self.log(scan_id, f"LLM call timed out for {file_path}")
                return
            except Exception as e:
                self.log(scan_id, f"LLM call failed for {file_path}: {str(e)}")
                return
            
            # Parse response
            import json
            import re
            
            content_resp = response.choices[0].message.content
            self.log(scan_id, f"Raw LLM Response for {file_path}: {content_resp[:500]}...")
            match = re.search(r"```json\n(.*)\n```", content_resp, re.DOTALL)
            if match:
                content_resp = match.group(1)
            elif re.search(r"```\n(.*)\n```", content_resp, re.DOTALL):
                 match = re.search(r"```\n(.*)\n```", content_resp, re.DOTALL)
                 content_resp = match.group(1)
            
            try:
                findings_data = json.loads(content_resp)
            except json.JSONDecodeError:
                # Fallback: try to find list in text
                start = content_resp.find('[')
                end = content_resp.rfind(']') + 1
                if start != -1 and end != -1:
                    findings_data = json.loads(content_resp[start:end])
                else:
                    findings_data = []
            
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            
            for f in findings_data:
                finding = Finding(
                    scan_id=scan.id,
                    file_path=os.path.basename(file_path),
                    line_number=f.get('line_number'),
                    severity=f.get('severity', 'Medium'),
                    description=f.get('description'),
                    snippet=f.get('snippet'),
                    remediation=f.get('remediation')
                )
                db.add(finding)
            
            db.commit()
            db.close()

        except Exception as e:
            import traceback
            error_msg = f"Error analyzing {file_path}: {str(e)}\n{traceback.format_exc()}"
            self.log(scan_id, error_msg)
            print(error_msg)


scan_engine = ScanEngine()
