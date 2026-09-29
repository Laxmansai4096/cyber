"""
CyberSentinel AI - Unified Gemini AI Core Engine
Connects directly to Google AI Studio (Gemini 2.5 / 2.0 Flash) API.
Drives deep reasoning across all 5 phases: Threat Modeling, SAST Patches, Supply Chain, DAST, and SOC UEBA.
"""
import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import httpx

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)
except Exception:
    pass

logger = logging.getLogger("ai_core")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"

class GeminiAICore:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.provider_base_url = os.environ.get("OPENAI_BASE_URL", "")

    def set_api_key(self, key: str, base_url: str = ""):
        self.api_key = key.strip()
        if base_url:
            self.provider_base_url = base_url.strip()

    def has_active_key(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        if self.api_key.startswith("gsk_"):
            return "Groq (Llama 3.3 70B Free Tier)"
        elif self.api_key.startswith("sk-or-"):
            return "OpenRouter (Free LLM API)"
        elif self.api_key.startswith("AQ.") or "AIza" in self.api_key:
            return "Google Gemini (AI Studio Free Tier)"
        elif self.provider_base_url:
            return f"Custom OpenAI-Compatible ({self.provider_base_url})"
        return "Google Gemini (AI Studio)"

    async def generate_response(self, system_prompt: str, user_content: str, json_mode: bool = False) -> str:
        """
        Invokes LLM API with system instructions and user input.
        Supports Google Gemini, Groq, OpenRouter, and OpenAI-compatible providers
        from awesome-freellm-apis catalog.
        """
        if not self.has_active_key():
            return "GEMINI_API_KEY_NOT_CONFIGURED"

        # 1. Groq or OpenRouter or OpenAI-compatible format
        if self.api_key.startswith("gsk_") or self.api_key.startswith("sk-") or self.provider_base_url:
            base_url = self.provider_base_url
            if not base_url:
                if self.api_key.startswith("gsk_"):
                    base_url = "https://api.groq.com/openai/v1"
                else:
                    base_url = "https://openrouter.ai/api/v1"

            model = "llama-3.3-70b-versatile" if "groq" in base_url else "meta-llama/llama-3.3-70b-instruct:free"

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            if "openrouter" in base_url:
                headers["HTTP-Referer"] = "http://localhost:8000"
                headers["X-Title"] = "CyberSentinel AI"

            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ]
            payload = {
                "model": model,
                "messages": messages,
                "temperature": 0.2,
            }
            if json_mode and "groq" in base_url:
                payload["response_format"] = {"type": "json_object"}

            url = f"{base_url.rstrip('/')}/chat/completions"
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        return choices[0]["message"].get("content", "")
                raise Exception(f"OpenAI-Compatible LLM API Error (HTTP {resp.status_code}): {resp.text}")

        # 2. Google Gemini Native API (Default from AI Studio)
        MODELS = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-2.5-flash", "gemini-flash-latest"]
        last_error = None

        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_key
        }

        generation_config = {
            "temperature": 0.2,
            "maxOutputTokens": 4096
        }
        if json_mode:
            generation_config["responseMimeType"] = "application/json"

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"System Directive:\n{system_prompt}\n\nTask Input:\n{user_content}"}]
                }
            ],
            "generationConfig": generation_config
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            for model_name in MODELS:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
                try:
                    resp = await client.post(url, headers=headers, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if candidates and "content" in candidates[0]:
                            parts = candidates[0]["content"].get("parts", [])
                            if parts and "text" in parts[0]:
                                return parts[0]["text"]
                        return ""
                    elif resp.status_code in [503, 429]:
                        last_error = f"HTTP {resp.status_code} ({model_name} busy, trying alternate model)"
                        continue
                    else:
                        raise Exception(f"Google AI Studio API Error (HTTP {resp.status_code}): {resp.text}")
                except Exception as e:
                    last_error = str(e)
                    continue

        if last_error:
            raise Exception(f"Gemini Models temporarily unavailable: {last_error}")
        return ""


    # Phase 1: AI Threat Modeling
    async def ai_threat_model(self, architecture_text: str) -> Dict[str, Any]:
        system_prompt = (
            "You are a Principal Cybersecurity Architect. Analyze the provided system architecture/OpenAPI specification. "
            "You MUST output a valid JSON object containing ALL of the following top-level keys:\n"
            "1. 'architectural_risk_summary': Executive overview of design risks.\n"
            "2. 'what_to_update': Array of 3-4 specific architectural items, routes, or schema definitions that must be updated.\n"
            "3. 'how_to_update': Array of 3-4 exact technical instructions and configuration changes explaining HOW to update them.\n"
            "4. 'suggestions': Array of 3-4 concrete architectural hardening recommendations.\n"
            "5. 'next_steps': Array of 3-4 sequential actions DevSecOps should take before proceeding to coding.\n"
            "6. 'references': Array of authoritative industry standards (e.g. 'NIST SP 800-207 Zero Trust', 'OWASP API Security Top 10 2023', 'RFC 6749 OAuth2').\n"
            "7. 'stride_threats': Array of objects with category, component, severity, adversary_exploit_vector, mitigation.\n"
            "Ensure 'what_to_update' and 'how_to_update' are always populated with clear, actionable items."
        )
        try:
            raw = await self.generate_response(system_prompt, architecture_text, json_mode=True)
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # Phase 2: Cognitive SAST & Git Diff Patch Generation
    async def ai_sast_code_review(self, filename: str, code_content: str, static_ast_findings: list) -> Dict[str, Any]:
        system_prompt = (
            "You are an Elite White-Hat Security Researcher and Senior Staff Software Engineer. "
            "Review the provided source code and initial AST taint signals. "
            "Output strict JSON with keys:\n"
            "1. 'code_health_summary': Executive assessment of codebase vulnerability posture.\n"
            "2. 'what_to_update': Array of specific code functions, lines, and database queries that must be updated.\n"
            "3. 'how_to_update': Array of exact technical code modifications explaining HOW to update them safely without breaking business logic.\n"
            "4. 'suggestions': Array of 3-4 secure coding best practices tailored to this code.\n"
            "5. 'next_steps': Array of 3-4 immediate developer actions (e.g. merge patches, add pre-commit hooks, secret rotation).\n"
            "6. 'references': Array of CWEs and guides (e.g. 'CWE-89: SQL Injection', 'CWE-798: Hardcoded Credentials', 'OWASP Secure Coding Practices').\n"
            "7. 'vulnerabilities': Array of objects with title, cwe, line, severity, exploit_scenario, remediation, and git_diff."
        )
        user_content = f"File: {filename}\nInitial AST Signals: {json.dumps(static_ast_findings)}\n\nSource Code:\n{code_content}"
        try:
            raw = await self.generate_response(system_prompt, user_content, json_mode=True)
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # Phase 3: CI/CD & Reachability Analysis
    async def ai_supply_chain_analysis(self, workflow_content: str, dependencies_summary: dict, source_code: str) -> Dict[str, Any]:
        system_prompt = (
            "You are a Supply Chain Security & SLSA Expert. Analyze the provided GitHub Actions workflow and dependency call-graph. "
            "Output strict JSON with keys:\n"
            "1. 'supply_chain_summary': Executive risk summary of pipeline and dependencies.\n"
            "2. 'what_to_update': Array of specific workflow triggers, action steps, and package versions that must be updated.\n"
            "3. 'how_to_update': Array of exact YAML refactoring and dependency version pinning instructions explaining HOW to update them.\n"
            "4. 'suggestions': Array of 3-4 supply chain hardening practices (e.g., pinning actions by commit SHA, Cosign signing).\n"
            "5. 'next_steps': Array of 3-4 steps to secure the CI/CD pipeline.\n"
            "6. 'references': Array of standards (e.g. 'SLSA Level 3 Specification', 'OpenSSF Scorecard', 'CycloneDX SBOM Standard').\n"
            "7. 'cve_reachability_insights': Array of explanations on why CVEs are reachable or dormant."
        )
        user_content = f"Workflow:\n{workflow_content}\n\nDependencies:\n{json.dumps(dependencies_summary)}\n\nSample Code:\n{source_code[:2000]}"
        try:
            raw = await self.generate_response(system_prompt, user_content, json_mode=True)
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # Phase 4: Stateful DAST & PoC Formulation
    async def ai_dast_poc_synthesis(self, target_url: str, endpoint_matrix: list) -> Dict[str, Any]:
        system_prompt = (
            "You are a Senior Penetration Tester conducting an ethical, non-destructive audit. "
            "Analyze the RBAC matrix and staging posture. "
            "Output strict JSON with keys:\n"
            "1. 'dast_summary': Executive assessment of staging endpoints and tenant boundary isolation.\n"
            "2. 'what_to_update': Array of specific endpoint authorization checks, CORS headers, and reverse proxy settings to update.\n"
            "3. 'how_to_update': Array of exact Nginx/middleware configurations and tenant validation checks explaining HOW to update them.\n"
            "4. 'suggestions': Array of 3-4 operational security recommendations (e.g. strict CORS, HSTS preload, WAF deployment).\n"
            "5. 'next_steps': Array of 3-4 verification steps for the QA & DevSecOps team.\n"
            "6. 'references': Array of standards (e.g. 'OWASP BOLA Prevention Guide', 'RFC 6797 HSTS', 'AWS IMDSv2 Transition Guide').\n"
            "7. 'reproducible_pocs': Array of objects with endpoint, curl_command, expected_behavior, vulnerable_behavior."
        )
        user_content = f"Target: {target_url}\nMatrix Results:\n{json.dumps(endpoint_matrix)}"
        try:
            raw = await self.generate_response(system_prompt, user_content, json_mode=True)
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # Phase 5: Blue Team UEBA & SOC Incident Correlation
    async def ai_soc_incident_investigation(self, session_telemetry: list, detected_anomalies: list) -> Dict[str, Any]:
        system_prompt = (
            "You are the Lead Incident Responder in a 24/7 Security Operations Center (SOC). "
            "Analyze the live user session logs and detected anomalies. "
            "Output strict JSON with keys:\n"
            "1. 'incident_briefing': Object with summary, severity_level, and impacted_assets.\n"
            "2. 'what_to_update': Array of active session states, firewall IP tables, and user account credentials that must be updated.\n"
            "3. 'how_to_update': Array of exact command-line steps, Redis token revocations, and WAF rules explaining HOW to execute the updates.\n"
            "4. 'suggestions': Array of 3-4 strategic SecOps defense-in-depth suggestions.\n"
            "5. 'next_steps': Array of 3-4 immediate containment and forensic steps.\n"
            "6. 'references': Array of incident response standards (e.g. 'NIST SP 800-61 Incident Handling', 'MITRE ATT&CK Enterprise Matrix v14', 'CISA Cyber Incident Response Playbook').\n"
            "7. 'adversary_attribution': Object with source_ips, user_agents, locations, indicators_of_compromise.\n"
            "8. 'containment_action_plan': Object with immediate_actions and secondary_actions."
        )
        user_content = f"Detected Anomalies:\n{json.dumps(detected_anomalies)}\n\nSession Telemetry:\n{json.dumps(session_telemetry)}"
        try:
            raw = await self.generate_response(system_prompt, user_content, json_mode=True)
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

# Global Singleton
ai_core = GeminiAICore()

