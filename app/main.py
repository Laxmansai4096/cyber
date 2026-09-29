"""
CyberSentinel AI - Main FastAPI Application
Serves the unified AI Cybersecurity Command Center and orchestrates all 5 phases.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Import Engines
from app.engines.threat_modeling import ThreatModelingEngine
from app.engines.whitehat_sast import WhiteHatSASTEngine
from app.engines.cicd_supplychain import CICDSupplyChainEngine
from app.engines.stateful_dast import StatefulDASTEngine
from app.engines.blue_team_soc import BlueTeamSOCEngine
from app.engines.soar_containment import soar_dispatcher
from app.engines.ai_core import ai_core

BASE_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = BASE_DIR / "samples"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="CyberSentinel AI", version="2.0.0", docs_url=None, redoc_url=None)

# Check 27: Restrict CORS origins instead of wildcard with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-goog-api-key"],
)

# Check 46 & Check 64: Security Headers & Resource Limit Middleware
@app.middleware("http")
async def security_middleware(request, call_next):
    # Check 64: Enforce 10MB maximum payload ceiling to prevent memory exhaustion DoS
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 10 * 1024 * 1024:
        return JSONResponse(status_code=413, content={"error": "Payload exceeds 10MB limit (Check 64)"})

    response = await call_next(request)

    # Check 46: Browser security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000 https://generativelanguage.googleapis.com;"
    )
    return response

# Check 12: Generic production error masking
@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    import logging
    logging.getLogger("uvicorn.error").error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": "An unexpected error occurred. Details recorded in private server logs."}
    )


# Instantiate engines
threat_engine = ThreatModelingEngine()
sast_engine = WhiteHatSASTEngine()
cicd_engine = CICDSupplyChainEngine()
dast_engine = StatefulDASTEngine()
soc_engine = BlueTeamSOCEngine()

from app.engines.ai_core import ai_core, PROVIDER_PRESETS

@app.get("/api/status")
async def get_status():
    return {
        "status": "ONLINE",
        "system": "CyberSentinel AI Autonomous SecOps",
        "has_gemini_key": ai_core.has_active_key(),
        "provider": ai_core.get_provider_name(),
        "model": ai_core.get_active_model(),
        "available_providers": [
            {
                "id": pid,
                "name": pdata["name"],
                "default_model": pdata["default_model"],
                "models": pdata["models"]
            }
            for pid, pdata in PROVIDER_PRESETS.items()
        ],
        "phases_ready": ["Phase 1 (Architecture)", "Phase 2 (SAST)", "Phase 3 (CI/CD Supply Chain)", "Phase 4 (DAST)", "Phase 5 (SOC UEBA)"]
    }

@app.post("/api/set-api-key")
async def set_api_key(payload: Dict[str, Any] = Body(...)):
    key = str(payload.get("key", "")).strip()
    provider = str(payload.get("provider", "")).strip()
    model = str(payload.get("model", "")).strip()
    base_url = str(payload.get("base_url", "")).strip()
    if not key:
        raise HTTPException(status_code=400, detail="API Key cannot be empty")
    ai_core.set_api_key(key, base_url=base_url, model=model, provider=provider)
    if provider == "google" or not provider:
        os.environ["GEMINI_API_KEY"] = key
    return {
        "status": "SUCCESS",
        "provider": ai_core.get_provider_name(),
        "model": ai_core.get_active_model(),
        "message": f"Successfully activated {ai_core.get_provider_name()} with model {ai_core.get_active_model()}"
    }

# -------------------------------------------------------------
# PHASE 1: Architecture & Threat Modeling
# -------------------------------------------------------------
@app.post("/api/phase1/threat-model")
async def run_phase1_threat_model(payload: Optional[Dict[str, Any]] = Body(None)):
    spec = None
    if payload:
        if "spec_text" in payload and isinstance(payload["spec_text"], str):
            try:
                spec = json.loads(payload["spec_text"])
            except Exception:
                spec = {"info": {"title": "Custom Architecture Description"}, "paths": {}}
        elif "paths" in payload or "openapi" in payload:
            spec = payload

    if not spec:
        sample_path = SAMPLES_DIR / "sample_api_spec.json"
        with open(sample_path, "r", encoding="utf-8") as f:
            spec = json.load(f)

    # 1. Deterministic STRIDE rule engine
    deterministic_analysis = threat_engine.analyze_architecture(spec)
    
    # 2. Deep Gemini AI Architect Reasoning
    ai_insights = None
    if ai_core.has_active_key():
        ai_insights = await ai_core.ai_threat_model(json.dumps(spec, indent=2))

    return {
        "phase": "Phase 1: Architecture & System Design",
        "deterministic": deterministic_analysis,
        "ai_augmented": ai_insights
    }

# -------------------------------------------------------------
# PHASE 2: Code Review & White-Hat SAST
# -------------------------------------------------------------
@app.post("/api/phase2/sast-audit")
async def run_phase2_sast_audit(payload: Optional[Dict[str, str]] = Body(None)):
    filename = "vulnerable_service.py"
    code = ""
    if payload and "code" in payload:
        code = payload["code"]
        filename = payload.get("filename", "custom_code.py")
    else:
        sample_path = SAMPLES_DIR / "vulnerable_service.py"
        with open(sample_path, "r", encoding="utf-8") as f:
            code = f.read()

    # 1. AST Taint & High-entropy Scan
    sast_results = sast_engine.scan_code(filename, code)

    # 2. Gemini AI Deep Reasoning & Patch Formulation
    ai_patches = None
    if ai_core.has_active_key():
        ai_patches = await ai_core.ai_sast_code_review(filename, code, sast_results["findings"])

    return {
        "phase": "Phase 2: Code Review & White-Hat SAST",
        "sast_results": sast_results,
        "ai_augmented_review": ai_patches
    }

# -------------------------------------------------------------
# PHASE 3: CI/CD Pipeline & Supply Chain Reachability
# -------------------------------------------------------------
@app.post("/api/phase3/supply-chain")
async def run_phase3_supply_chain(payload: Optional[Dict[str, Any]] = Body(None)):
    workflow_content = ""
    requirements_content = ""
    source_code = ""

    if payload:
        workflow_content = payload.get("workflow", "")
        requirements_content = payload.get("requirements", "")
        source_code = payload.get("source_code", "")
    
    if not workflow_content:
        with open(SAMPLES_DIR / "sample_workflow.yml", "r", encoding="utf-8") as f:
            workflow_content = f.read()
    if not requirements_content:
        with open(SAMPLES_DIR / "sample_requirements.txt", "r", encoding="utf-8") as f:
            requirements_content = f.read()
    if not source_code:
        with open(SAMPLES_DIR / "vulnerable_service.py", "r", encoding="utf-8") as f:
            source_code = f.read()

    ci_audit = cicd_engine.audit_github_workflow(workflow_content)
    reachability = cicd_engine.analyze_reachability(requirements_content, source_code)

    ai_insights = None
    if ai_core.has_active_key():
        ai_insights = await ai_core.ai_supply_chain_analysis(workflow_content, reachability, source_code)

    return {
        "phase": "Phase 3: CI/CD & Supply Chain Integrity",
        "workflow_audit": ci_audit,
        "reachability_analysis": reachability,
        "ai_insights": ai_insights
    }

# -------------------------------------------------------------
# PHASE 4: Pre-Production Staging DAST
# -------------------------------------------------------------
@app.post("/api/phase4/dast-probe")
async def run_phase4_dast(payload: Optional[Dict[str, Any]] = Body(None)):
    target_url = "https://staging.paysecure.internal"
    mock_headers = {
        "Server": "nginx/1.18.0",
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json"
    }
    endpoints_to_probe = [
        {
            "path": "/api/v1/customers/1001/balance",
            "method": "GET",
            "is_private_user_resource": True,
            "user_b_response_code": 200,
            "guest_response_code": 401
        },
        {
            "path": "/api/v1/customers/1001/transactions",
            "method": "GET",
            "is_private_user_resource": True,
            "user_b_response_code": 200,
            "guest_response_code": 401
        },
        {
            "path": "/api/v1/wallet/internal-transfer",
            "method": "POST",
            "is_private_user_resource": True,
            "user_b_response_code": 403,
            "guest_response_code": 401
        }
    ]

    if payload:
        if payload.get("target_url"):
            target_url = payload["target_url"]
        if payload.get("headers") and isinstance(payload["headers"], dict):
            mock_headers.update(payload["headers"])
        if payload.get("endpoints") and isinstance(payload["endpoints"], list):
            endpoints_to_probe = payload["endpoints"]

    header_audit = dast_engine.audit_security_headers(mock_headers, target_url)
    rbac_matrix = dast_engine.probe_rbac_idor_matrix(endpoints_to_probe)
    ssrf_probes = dast_engine.probe_ssrf_cloud_metadata(["webhook_url", "avatar_callback"])

    ai_poc_insights = None
    if ai_core.has_active_key():
        ai_poc_insights = await ai_core.ai_dast_poc_synthesis(target_url, rbac_matrix["matrix"])

    return {
        "phase": "Phase 4: Stateful DAST & Business Logic Probing",
        "headers": header_audit,
        "rbac_idor_matrix": rbac_matrix,
        "ssrf_metadata_probes": ssrf_probes,
        "ai_poc_synthesis": ai_poc_insights
    }

# -------------------------------------------------------------
# PHASE 5: Runtime Blue Team UEBA & SOC Incident Telemetry
# -------------------------------------------------------------
@app.post("/api/phase5/soc-telemetry")
async def run_phase5_soc(payload: Optional[Dict[str, Any]] = Body(None)):
    events = []
    if payload:
        if "events" in payload and isinstance(payload["events"], list):
            events = payload["events"]
        elif "events_text" in payload and isinstance(payload["events_text"], str):
            try:
                events = json.loads(payload["events_text"])
            except Exception:
                events = []

    if not events:
        with open(SAMPLES_DIR / "runtime_telemetry.json", "r", encoding="utf-8") as f:
            events = json.load(f)

    soc_results = soc_engine.analyze_session_logs(events)

    ai_investigation = None
    if ai_core.has_active_key():
        ai_investigation = await ai_core.ai_soc_incident_investigation(events, soc_results["incidents"])

    return {
        "phase": "Phase 5: Blue Team UEBA & SOC Incident Stream",
        "soc_analysis": soc_results,
        "active_containments": soar_dispatcher.list_containments(),
        "ai_soc_investigation": ai_investigation
    }

# -------------------------------------------------------------
# PHASE 5 CONTAINMENT: 1-Click Action Dispatcher
# -------------------------------------------------------------
@app.post("/api/phase5/containment")
async def execute_containment(payload: Dict[str, Any] = Body(...)):
    level = payload.get("level", 1)
    incident_id = payload.get("incident_id", "INC-UNKNOWN")
    user_id = payload.get("user_id", "unknown_user")
    ip_address = payload.get("ip_address", "127.0.0.1")

    action = soar_dispatcher.execute_containment(level, incident_id, user_id, ip_address)
    return {
        "status": "EXECUTED",
        "action": action
    }

# -------------------------------------------------------------
# SAMPLE ARTIFACTS FETCHER
# -------------------------------------------------------------
@app.get("/api/samples/{sample_name}")
async def get_sample_content(sample_name: str):
    file_map = {
        "api_spec": "sample_api_spec.json",
        "vulnerable_code": "vulnerable_service.py",
        "workflow": "sample_workflow.yml",
        "requirements": "sample_requirements.txt",
        "telemetry": "runtime_telemetry.json"
    }
    if sample_name not in file_map:
        raise HTTPException(status_code=404, detail="Sample not found")
    filepath = SAMPLES_DIR / file_map[sample_name]
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    return {"name": sample_name, "filename": file_map[sample_name], "content": content}

# Mount static frontend
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def serve_index():
    return FileResponse(STATIC_DIR / "index.html")
