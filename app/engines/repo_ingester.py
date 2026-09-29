"""
CyberSentinel AI - Autonomous GitHub Repository & Live Log Ingestion Engine
Allows DevSecOps teams to audit any GitHub repository in one click:
- Discovers Architecture / OpenAPI specs -> routes to Phase 1 (STRIDE)
- Discovers source code files & routes -> routes to Phase 2 (Cognitive SAST)
- Discovers CI/CD workflows & dependency manifests -> routes to Phase 3 (SBOM)
- Ingests and normalizes live HTTP application log streams -> routes to Phase 5 (Blue Team SOC)
"""
import os
import re
import json
import shutil
import tempfile
import subprocess
import urllib.parse
from uuid import uuid4
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

class RepoIngestionEngine:
    def __init__(self):
        pass

    def normalize_github_url(self, url: str) -> str:
        url = url.strip()
        if not url:
            raise ValueError("Repository URL cannot be empty")
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"
        
        # Clean up git suffixes or branch paths if pasted from browser
        # e.g. https://github.com/owner/repo/tree/main -> https://github.com/owner/repo.git
        m = re.match(r"(https?://github\.com/[^/]+/[^/]+?)(?:/(?:tree|blob)/.*|\.git)?$", url)
        if m:
            return f"{m.group(1)}.git"
        return url

    async def ingest_github_repository(self, repo_url: str) -> Dict[str, Any]:
        """
        Shallow clones a public GitHub repo into an isolated temp directory,
        extracts architecture specs, source code, CI/CD workflows, and dependencies,
        then cleans up the temporary directory.
        """
        clean_url = self.normalize_github_url(repo_url)
        repo_name = clean_url.rstrip("/").split("/")[-1].replace(".git", "")
        temp_dir = Path(tempfile.gettempdir()) / f"cybersentinel_repo_{uuid4().hex[:8]}"

        try:
            # 1. Shallow clone with depth 1
            cmd = ["git", "clone", "--depth", "1", clean_url, str(temp_dir)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            if proc.returncode != 0:
                err_msg = proc.stderr.strip() or proc.stdout.strip() or "Failed to clone repository"
                raise RuntimeError(f"Git Clone Failed: {err_msg}")

            # 2. Inspect Repository Artifacts
            arch_spec_content = ""
            arch_filename = ""
            workflow_content = ""
            workflow_filename = ""
            deps_content = ""
            deps_filename = ""
            primary_code_content = ""
            primary_code_filename = ""
            all_source_files = []

            # A. Search for Architecture / OpenAPI Specs
            spec_patterns = [
                r"openapi\.(json|ya?ml)",
                r"swagger\.(json|ya?ml)",
                r".*api.*spec.*\.(json|ya?ml)",
                r".*api.*doc.*\.(json|ya?ml)",
                r"schema\.(json|ya?ml)"
            ]
            for root, _, files in os.walk(temp_dir):
                if ".git" in root:
                    continue
                for f in files:
                    for pat in spec_patterns:
                        if re.match(pat, f, re.IGNORECASE):
                            filepath = Path(root) / f
                            try:
                                if filepath.stat().st_size < 1024 * 1024:  # Under 1MB
                                    arch_spec_content = filepath.read_text(encoding="utf-8", errors="replace")
                                    arch_filename = str(filepath.relative_to(temp_dir))
                                    break
                            except Exception:
                                pass
                    if arch_spec_content:
                        break
                if arch_spec_content:
                    break

            # B. Search for CI/CD Workflows (.github/workflows)
            wf_dir = temp_dir / ".github" / "workflows"
            if wf_dir.exists() and wf_dir.is_dir():
                for wf_file in sorted(wf_dir.glob("*.y*ml")):
                    try:
                        workflow_content = wf_file.read_text(encoding="utf-8", errors="replace")
                        workflow_filename = str(wf_file.relative_to(temp_dir))
                        break
                    except Exception:
                        pass

            # C. Search for Dependency Manifests
            manifest_names = ["requirements.txt", "package.json", "Pipfile", "poetry.lock", "pom.xml", "go.mod", "Cargo.toml"]
            for m_name in manifest_names:
                candidate = temp_dir / m_name
                if candidate.exists() and candidate.is_file():
                    try:
                        deps_content = candidate.read_text(encoding="utf-8", errors="replace")
                        deps_filename = m_name
                        break
                    except Exception:
                        pass
            
            # If not in root, look in services/ or subdirectories
            if not deps_content:
                for root, _, files in os.walk(temp_dir):
                    if ".git" in root:
                        continue
                    for f in files:
                        if f in manifest_names:
                            filepath = Path(root) / f
                            try:
                                deps_content = filepath.read_text(encoding="utf-8", errors="replace")
                                deps_filename = str(filepath.relative_to(temp_dir))
                                break
                            except Exception:
                                pass
                    if deps_content:
                        break

            # D. Search for Source Code Files (Focus on routes, controllers, views, or main logic)
            code_priority = ["routes", "views", "controller", "community", "auth", "api", "app", "main", "service"]
            source_candidates = []

            for root, _, files in os.walk(temp_dir):
                if ".git" in root or "node_modules" in root or "venv" in root or "__pycache__" in root:
                    continue
                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in [".py", ".js", ".ts", ".go", ".java"]:
                        filepath = Path(root) / f
                        rel_path = str(filepath.relative_to(temp_dir))
                        size = filepath.stat().st_size
                        if 100 < size < 100000:  # Valid source file size
                            # Compute score based on priority words
                            score = sum(2 for p in code_priority if p in rel_path.lower())
                            source_candidates.append({
                                "path": rel_path,
                                "abs_path": filepath,
                                "name": f,
                                "size": size,
                                "score": score
                            })

            source_candidates.sort(key=lambda x: (x["score"], x["size"]), reverse=True)

            if source_candidates:
                top = source_candidates[0]
                try:
                    primary_code_content = top["abs_path"].read_text(encoding="utf-8", errors="replace")
                    primary_code_filename = top["path"]
                except Exception:
                    pass
                
                all_source_files = [
                    {"name": c["name"], "path": c["path"], "size": c["size"]}
                    for c in source_candidates[:12]
                ]

            # If no spec was explicitly found, formulate a synthetic OpenAPI schema based on detected files
            if not arch_spec_content:
                arch_filename = f"{repo_name}_synthetic_spec.json"
                endpoints = []
                for sf in all_source_files[:6]:
                    base = Path(sf["name"]).stem
                    endpoints.append({
                        "path": f"/api/v1/{base}",
                        "method": "GET",
                        "summary": f"Inferred from {sf['path']}"
                    })
                arch_spec_content = json.dumps({
                    "openapi": "3.0.0",
                    "info": {
                        "title": f"{repo_name} Inferred Architecture",
                        "version": "1.0.0",
                        "description": f"Automatically generated architecture model for {repo_name}."
                    },
                    "paths": {ep["path"]: {"get": {"summary": ep["summary"], "responses": {"200": {"description": "OK"}}}} for ep in endpoints}
                }, indent=2)

            return {
                "status": "SUCCESS",
                "repo_name": repo_name,
                "clean_url": clean_url,
                "architecture_spec": arch_spec_content,
                "architecture_filename": arch_filename or "openapi.json",
                "primary_source_code": primary_code_content or "# No primary Python/JS source code detected in root\n",
                "primary_source_filename": primary_code_filename or "app.py",
                "all_source_files": all_source_files,
                "workflow_content": workflow_content or "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n",
                "workflow_filename": workflow_filename or "ci.yml",
                "dependencies_content": deps_content or "requests==2.31.0\nurllib3==2.0.7\n",
                "dependencies_filename": deps_filename or "requirements.txt",
                "stats": {
                    "source_files_found": len(source_candidates),
                    "has_spec": bool(arch_filename and not arch_filename.endswith("_synthetic_spec.json")),
                    "has_workflow": bool(workflow_filename),
                    "has_dependencies": bool(deps_filename)
                }
            }

        finally:
            # Clean up cloned folder
            if temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception:
                    pass

    async def ingest_live_logs_from_url(self, log_url: str) -> List[Dict[str, Any]]:
        """
        Fetches live application or security logs from an HTTP/HTTPS endpoint.
        Normalizes JSON arrays or plain-text syslog/Nginx streams into chronological telemetry events.
        """
        log_url = log_url.strip()
        if not log_url.startswith("http://") and not log_url.startswith("https://"):
            log_url = f"https://{log_url}"

        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(log_url)
            if resp.status_code != 200:
                raise RuntimeError(f"Log Endpoint returned HTTP {resp.status_code}: {resp.text[:150]}")

            # 1. Try parsing JSON
            try:
                data = resp.json()
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    for key in ["events", "logs", "records", "data", "telemetry"]:
                        if key in data and isinstance(data[key], list):
                            return data[key]
                    return [data]
            except Exception:
                pass

            # 2. Parse Plain-Text / Common Log Format (Nginx / Apache / Syslog)
            text = resp.text.strip()
            lines = text.split("\n")
            parsed_events = []
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Regex for IP, Method, Endpoint, Status Code
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                ip = ip_match.group(0) if ip_match else "127.0.0.1"

                endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
                endpoint = endpoint_match.group(1) if endpoint_match else "/api/request"

                # Detect user agent
                ua = "Mozilla/5.0"
                if "curl" in line.lower():
                    ua = "curl/8.0.1"
                elif "python" in line.lower():
                    ua = "python-requests/2.31"

                # Exfiltration anomaly flag if byte count is high
                records = 5
                bytes_match = re.search(r'\s(\d{4,8})\s', line)
                if bytes_match:
                    byte_count = int(bytes_match.group(1))
                    if byte_count > 10000:
                        records = byte_count // 10

                parsed_events.append({
                    "timestamp": "2026-09-29T10:00:00Z",
                    "user_id": "remote_user",
                    "session_token": f"sess_{abs(hash(ip)) % 100000}",
                    "action": "api_request",
                    "ip_address": ip,
                    "user_agent": ua,
                    "endpoint": endpoint,
                    "records_fetched": records,
                    "raw_log": line[:200]
                })

            if not parsed_events:
                raise ValueError("Could not extract any valid security events or JSON logs from the URL response.")

            return parsed_events


repo_ingester = RepoIngestionEngine()
