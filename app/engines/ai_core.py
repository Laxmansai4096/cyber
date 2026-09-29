"""
CyberSentinel AI - Unified Multi-Provider AI Core Engine
Powered by SOTA Open-Source & Enterprise AI Models from awesome-freellm-apis catalog:
- DeepSeek-R1 / DeepSeek-V3 (SOTA for Cognitive SAST & Reasoning)
- Qwen 2.5 Coder 32B (SOTA for Code Security & AST Patches)
- Llama 3.3 70B Versatile via Groq / Cerebras (Ultra-fast real-time SOC analysis)
- Google Gemini 2.5 Flash / 2.0 Flash / 1.5 Pro (1M+ Token Context for large specs & SBOMs)
- Mistral Large & Codestral (Advanced Code Security Auditing)
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

# Provider Presets with Optimal Base URLs & Models
PROVIDER_PRESETS = {
    "google": {
        "name": "Google Gemini (AI Studio)",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.5-flash",
        "models": ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "is_native_gemini": True,
    },
    "groq": {
        "name": "Groq (Ultra-Fast 300+ TPS)",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "models": ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b", "mixtral-8x7b-32768"],
        "is_native_gemini": False,
    },
    "openrouter": {
        "name": "OpenRouter (Free SOTA Models)",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "deepseek/deepseek-r1:free",
        "models": [
            "deepseek/deepseek-r1:free",
            "qwen/qwen-2.5-coder-32b-instruct:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "google/gemini-2.0-flash-exp:free"
        ],
        "is_native_gemini": False,
    },
    "cerebras": {
        "name": "Cerebras Cloud (1800+ TPS Low Latency)",
        "base_url": "https://api.cerebras.ai/v1",
        "default_model": "llama3.1-70b",
        "models": ["llama3.1-70b", "llama3.1-8b"],
        "is_native_gemini": False,
    },
    "deepseek": {
        "name": "DeepSeek API (SOTA Reasoning)",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "is_native_gemini": False,
    },
    "sambanova": {
        "name": "SambaNova Cloud",
        "base_url": "https://api.sambanova.ai/v1",
        "default_model": "deepseek-v3-1",
        "models": ["deepseek-v3-1", "Meta-Llama-3.3-70B-Instruct"],
        "is_native_gemini": False,
    },
    "mistral": {
        "name": "Mistral AI",
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "codestral-latest",
        "models": ["codestral-latest", "mistral-medium-3-5-128b", "open-mixtral-8x7b"],
        "is_native_gemini": False,
    },
    "huggingface": {
        "name": "Hugging Face Serverless",
        "base_url": "https://router.huggingface.co/v1",
        "default_model": "Qwen/Qwen2.5-Coder-32B-Instruct",
        "models": ["Qwen/Qwen2.5-Coder-32B-Instruct", "meta-llama/Llama-3.3-70B-Instruct"],
        "is_native_gemini": False,
    }
}


class MultiProviderAICore:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
        self.provider_base_url = os.environ.get("OPENAI_BASE_URL", "")
        self.selected_provider = os.environ.get("AI_PROVIDER", "")
        self.selected_model = os.environ.get("AI_MODEL", "")
        self._auto_detect_provider()

    def _auto_detect_provider(self):
        if not self.selected_provider:
            if self.api_key.startswith("gsk_"):
                self.selected_provider = "groq"
            elif self.api_key.startswith("sk-or-"):
                self.selected_provider = "openrouter"
            elif self.api_key.startswith("csk-"):
                self.selected_provider = "cerebras"
            elif self.api_key.startswith("hf_"):
                self.selected_provider = "huggingface"
            elif self.provider_base_url and "deepseek" in self.provider_base_url:
                self.selected_provider = "deepseek"
            elif self.api_key.startswith("AQ.") or "AIza" in self.api_key or (self.api_key and not self.provider_base_url):
                self.selected_provider = "google"
            elif self.provider_base_url:
                self.selected_provider = "custom"

        if not self.selected_model and self.selected_provider in PROVIDER_PRESETS:
            self.selected_model = PROVIDER_PRESETS[self.selected_provider]["default_model"]

    def set_api_key(self, key: str, base_url: str = "", model: str = "", provider: str = ""):
        self.api_key = key.strip()
        if provider:
            self.selected_provider = provider.strip()
        if base_url:
            self.provider_base_url = base_url.strip()
        elif self.selected_provider in PROVIDER_PRESETS:
            self.provider_base_url = PROVIDER_PRESETS[self.selected_provider]["base_url"]

        if model:
            self.selected_model = model.strip()
        elif self.selected_provider in PROVIDER_PRESETS:
            self.selected_model = PROVIDER_PRESETS[self.selected_provider]["default_model"]
        else:
            self._auto_detect_provider()

    def has_active_key(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        if self.selected_provider in PROVIDER_PRESETS:
            return PROVIDER_PRESETS[self.selected_provider]["name"]
        elif self.provider_base_url:
            return f"Custom Provider ({self.provider_base_url})"
        elif self.api_key.startswith("gsk_"):
            return "Groq (Ultra-Fast)"
        elif self.api_key.startswith("sk-or-"):
            return "OpenRouter (Free SOTA)"
        return "Google Gemini (AI Studio)"

    def get_active_model(self) -> str:
        if self.selected_model:
            return self.selected_model
        if self.selected_provider in PROVIDER_PRESETS:
            return PROVIDER_PRESETS[self.selected_provider]["default_model"]
        return "gemini-2.5-flash"

    def _get_phase_specialized_model(self, task_type: str) -> str:
        """
        Dynamically routes to the highest-performing model for the given cybersecurity task.
        """
        if self.selected_model and self.selected_model != "auto":
            return self.selected_model

        # OpenRouter Task-Specialized Model Routing
        if self.selected_provider == "openrouter":
            if task_type == "sast_review":
                return "qwen/qwen-2.5-coder-32b-instruct:free"  # SOTA code & AST repair
            elif task_type in ["threat_modeling", "dast_audit"]:
                return "deepseek/deepseek-r1:free"  # SOTA reasoning & exploit verification
            elif task_type == "soc_telemetry":
                return "meta-llama/llama-3.3-70b-instruct:free"  # Low-latency correlation
            return "deepseek/deepseek-r1:free"

        # Groq Task-Specialized Model Routing
        if self.selected_provider == "groq":
            if task_type == "sast_review":
                return "deepseek-r1-distill-llama-70b"
            return "llama-3.3-70b-versatile"

        # DeepSeek Native
        if self.selected_provider == "deepseek":
            if task_type in ["sast_review", "dast_audit"]:
                return "deepseek-reasoner"
            return "deepseek-chat"

        # Default fallback to active model
        return self.get_active_model()

    async def generate_response(self, system_prompt: str, user_content: str, json_mode: bool = False, task_type: str = "") -> str:
        """
        Invokes LLM API with system instructions and user input.
        Supports Google Gemini, Groq, OpenRouter, Cerebras, DeepSeek, SambaNova, Hugging Face,
        and custom OpenAI-compatible providers.
        """
        if not self.has_active_key():
            return "GEMINI_API_KEY_NOT_CONFIGURED"

        # 1. Native Google Gemini API (AI Studio)
        is_google = (
            self.selected_provider == "google" or
            self.api_key.startswith("AIza") or
            (not self.provider_base_url and not self.api_key.startswith("gsk_") and not self.api_key.startswith("sk-"))
        )

        if is_google:
            MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash", "gemini-flash-latest"]
            if self.selected_model and self.selected_model.startswith("gemini-"):
                if self.selected_model in MODELS:
                    MODELS.remove(self.selected_model)
                MODELS.insert(0, self.selected_model)

            headers = {
                "Content-Type": "application/json",
                "X-goog-api-key": self.api_key
            }

            generation_config = {
                "temperature": 0.15,
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

            last_error = None
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
                        elif resp.status_code in [503, 429, 404]:
                            last_error = f"HTTP {resp.status_code} on {model_name}"
                            continue
                        else:
                            raise Exception(f"Google AI Studio Error (HTTP {resp.status_code}): {resp.text}")
                    except Exception as e:
                        last_error = str(e)
                        continue

            if last_error:
                raise Exception(f"Gemini API temporarily unavailable: {last_error}")
            return ""

        # 2. OpenAI-Compatible Providers (Groq, OpenRouter, Cerebras, DeepSeek, etc.)
        base_url = self.provider_base_url
        if not base_url and self.selected_provider in PROVIDER_PRESETS:
            base_url = PROVIDER_PRESETS[self.selected_provider]["base_url"]
        elif not base_url:
            if self.api_key.startswith("gsk_"):
                base_url = "https://api.groq.com/openai/v1"
            elif self.api_key.startswith("csk-"):
                base_url = "https://api.cerebras.ai/v1"
            else:
                base_url = "https://openrouter.ai/api/v1"

        model = self._get_phase_specialized_model(task_type)

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
            "temperature": 0.15,
        }
        if json_mode:
            # Most modern providers support json_object response format
            if any(p in base_url for p in ["groq", "cerebras", "deepseek", "openrouter"]):
                payload["response_format"] = {"type": "json_object"}

        url = f"{base_url.rstrip('/')}/chat/completions"
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices", [])
                if choices and "message" in choices[0]:
                    return choices[0]["message"].get("content", "")
            raise Exception(f"AI Provider ({self.get_provider_name()}) Error HTTP {resp.status_code}: {resp.text}")

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
            raw = await self.generate_response(system_prompt, architecture_text, json_mode=True, task_type="threat_modeling")
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # Phase 2: Cognitive SAST & Git Diff Patch Generation (Powered by SOTA Code Models like Qwen 2.5 Coder / DeepSeek)
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
            raw = await self.generate_response(system_prompt, user_content, json_mode=True, task_type="sast_review")
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
            raw = await self.generate_response(system_prompt, user_content, json_mode=True, task_type="supply_chain")
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
            raw = await self.generate_response(system_prompt, user_content, json_mode=True, task_type="dast_audit")
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
            raw = await self.generate_response(system_prompt, user_content, json_mode=True, task_type="soc_telemetry")
            if raw == "GEMINI_API_KEY_NOT_CONFIGURED":
                return {"status": "awaiting_api_key"}
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}


# Global Singleton
ai_core = MultiProviderAICore()
