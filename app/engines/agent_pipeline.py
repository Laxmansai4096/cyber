"""
CyberSentinel AI - 3-Agent Collaborative Testing Framework
Architecture:
1. InteractionAgent: Executes controlled, non-destructive HTTP requests against the application endpoint.
2. AnalysisAgent: Evaluates application response behavior (status code, headers, error traces, data leakage).
3. AdaptationAgent: Formulates refined parameters and interaction hypotheses based on previous analysis.
"""
import time
import json
import logging
from typing import Dict, Any, List, Optional
import httpx
from app.engines.ai_core import ai_core

logger = logging.getLogger("agent_pipeline")


class InteractionAgent:
    """
    Agent 1: Interaction Prober
    Sends controlled HTTP requests to the target application and records the response state.
    """
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    async def execute_interaction(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        method = method.upper()
        req_headers = headers.copy() if headers else {}
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = "CyberSentinel-Security-Agent/1.0"

        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=False) as client:
                if method == "GET":
                    resp = await client.get(url, headers=req_headers, params=params)
                elif method == "POST":
                    resp = await client.post(url, headers=req_headers, params=params, data=data, json=json_body)
                elif method == "PUT":
                    resp = await client.put(url, headers=req_headers, params=params, data=data, json=json_body)
                elif method == "DELETE":
                    resp = await client.delete(url, headers=req_headers, params=params)
                elif method == "OPTIONS":
                    resp = await client.options(url, headers=req_headers)
                elif method == "HEAD":
                    resp = await client.head(url, headers=req_headers)
                else:
                    return {
                        "status": "ERROR",
                        "error": f"Unsupported HTTP method: {method}",
                        "timestamp": time.time()
                    }

            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            content_type = resp.headers.get("content-type", "")

            # Truncate response text safely for evaluation
            body_text = resp.text[:4000]

            return {
                "status": "SUCCESS",
                "request": {
                    "url": str(resp.url),
                    "method": method,
                    "headers": req_headers,
                    "params": params,
                    "json_body": json_body
                },
                "response": {
                    "status_code": resp.status_code,
                    "reason_phrase": resp.reason_phrase,
                    "headers": dict(resp.headers),
                    "body_snippet": body_text,
                    "content_length": len(resp.content),
                    "content_type": content_type,
                    "latency_ms": elapsed_ms
                },
                "timestamp": time.time()
            }

        except httpx.RequestError as exc:
            return {
                "status": "CONNECTION_FAILED",
                "request": {"url": url, "method": method},
                "error": str(exc),
                "latency_ms": round((time.time() - start_time) * 1000, 2),
                "timestamp": time.time()
            }


class AnalysisAgent:
    """
    Agent 2: Response Analyzer
    Parses application behavior, status codes, response headers, and content patterns.
    """
    def __init__(self):
        pass

    async def analyze_response(
        self,
        interaction_result: Dict[str, Any],
        custom_analysis_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        if interaction_result.get("status") != "SUCCESS":
            return {
                "summary": "Target endpoint could not be reached or returned connection error.",
                "observed_behavior": "Network unreachable or connection refused.",
                "status_category": "NETWORK_ERROR",
                "security_observations": ["Ensure the target server is running and accessible."],
                "vulnerabilities_suspected": []
            }

        resp = interaction_result.get("response", {})
        code = resp.get("status_code", 0)
        headers = resp.get("headers", {})
        body = resp.get("body_snippet", "")

        # Heuristic checks
        observations = []
        vulns_suspected = []

        # Server information disclosure
        server_header = headers.get("server") or headers.get("x-powered-by")
        if server_header:
            observations.append(f"Server technology revealed in headers: '{server_header}'.")

        # Verbose error trace check
        if code >= 500:
            observations.append(f"Server returned HTTP {code} internal error.")
            if any(indicator in body.lower() for indicator in ["traceback", "syntaxerror", "exception", "nullpointerexception", "stack trace"]):
                vulns_suspected.append("Verbose stack trace disclosure in error response (CWE-209).")
        elif code in [401, 403]:
            observations.append(f"Access denied with HTTP {code} ({resp.get('reason_phrase')}).")
        elif code == 200:
            observations.append(f"Endpoint accepted request with HTTP 200 OK ({resp.get('latency_ms')}ms).")

        # LLM Reasoning if API key is configured
        ai_assessment = None
        if ai_core.has_active_key():
            system_prompt = (
                "You are an Application Security Assessment Agent. Analyze the HTTP interaction result. "
                "Assess whether the endpoint handled input safely, leaked sensitive data, or responded unexpectedly. "
                "Output strict JSON with keys: 'summary', 'behavior_interpretation', 'security_observations', 'potential_risks'."
            )
            user_content = json.dumps({
                "interaction": interaction_result,
                "user_instruction": custom_analysis_prompt or "Analyze response security behavior."
            })
            try:
                raw = await ai_core.generate_response(system_prompt, user_content, json_mode=True, task_type="sast_audit")
                if raw and raw != "GEMINI_API_KEY_NOT_CONFIGURED":
                    ai_assessment = json.loads(raw)
            except Exception as e:
                logger.warning(f"Analysis agent LLM evaluation error: {e}")

        summary = ai_assessment.get("summary") if ai_assessment else f"HTTP {code} received in {resp.get('latency_ms')}ms."
        if ai_assessment and "security_observations" in ai_assessment:
            observations.extend(ai_assessment.get("security_observations", []))
        if ai_assessment and "potential_risks" in ai_assessment:
            vulns_suspected.extend(ai_assessment.get("potential_risks", []))

        return {
            "status_code": code,
            "latency_ms": resp.get("latency_ms"),
            "summary": summary,
            "observations": list(dict.fromkeys(observations)),
            "vulnerabilities_suspected": list(dict.fromkeys(vulns_suspected)),
            "ai_assessment": ai_assessment
        }


class AdaptationAgent:
    """
    Agent 3: Strategy & Adaptation Agent
    Reviews analysis results and formulates the updated interaction plan for the next cycle.
    """
    def __init__(self):
        pass

    async def plan_next_interaction(
        self,
        target_url: str,
        current_step: int,
        history: List[Dict[str, Any]],
        custom_goal_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Formulates the next interaction parameters (method, headers, query params, body)
        based on what was learned in previous cycles.
        """
        last_cycle = history[-1] if history else {}
        last_analysis = last_cycle.get("analysis", {})
        last_status = last_analysis.get("status_code", 0)

        # Baseline heuristic fallback if LLM is not active
        fallback_plan = {
            "next_method": "GET",
            "next_headers": {"Accept": "application/json"},
            "next_params": {},
            "next_json_body": None,
            "hypothesis": "Test alternative header formatting and query parameters.",
            "rationale": f"Previous step returned HTTP {last_status}."
        }

        # LLM-driven adaptation
        if ai_core.has_active_key():
            system_prompt = (
                "You are an Application Security Testing Strategy Agent. "
                "Review the testing history and previous responses. "
                "Determine the next logical test interaction to evaluate boundary conditions, authentication states, or error handling. "
                "Keep testing non-destructive, safe, and focused on discovery. "
                "Output strict JSON with keys:\n"
                "- 'next_method': HTTP method ('GET', 'POST', 'PUT', 'OPTIONS', etc.)\n"
                "- 'next_headers': dictionary of HTTP headers\n"
                "- 'next_params': dictionary of URL query parameters\n"
                "- 'next_json_body': dictionary of JSON body if method is POST/PUT (or null)\n"
                "- 'hypothesis': What specific behavior or control is this test validating?\n"
                "- 'rationale': Why this updated parameter set is chosen based on prior results."
            )
            user_content = json.dumps({
                "target_url": target_url,
                "current_step": current_step,
                "history": history,
                "operator_goal": custom_goal_prompt or "Identify missing input validation and authorization boundaries."
            })
            try:
                raw = await ai_core.generate_response(system_prompt, user_content, json_mode=True, task_type="sast_audit")
                if raw and raw != "GEMINI_API_KEY_NOT_CONFIGURED":
                    parsed = json.loads(raw)
                    return {
                        "next_method": parsed.get("next_method", "GET").upper(),
                        "next_headers": parsed.get("next_headers", {}),
                        "next_params": parsed.get("next_params", {}),
                        "next_json_body": parsed.get("next_json_body"),
                        "hypothesis": parsed.get("hypothesis", "Validate updated input state."),
                        "rationale": parsed.get("rationale", "Refined based on previous cycle.")
                    }
            except Exception as e:
                logger.warning(f"Adaptation agent LLM planning error: {e}")

        return fallback_plan


class MultiAgentFeedbackLoop:
    """
    Controller orchestrating the 3-Agent Continuous Feedback Loop:
    InteractionAgent -> AnalysisAgent -> AdaptationAgent -> (Next Cycle)
    """
    def __init__(self):
        self.prober = InteractionAgent()
        self.analyzer = AnalysisAgent()
        self.adapter = AdaptationAgent()

    async def run_feedback_loop(
        self,
        target_url: str,
        initial_method: str = "GET",
        initial_headers: Optional[Dict[str, str]] = None,
        initial_params: Optional[Dict[str, Any]] = None,
        initial_body: Optional[Dict[str, Any]] = None,
        max_iterations: int = 3,
        user_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        # Enforce safety bounds (1 to 5 cycles max)
        max_iterations = max(1, min(max_iterations, 5))
        history = []

        current_url = target_url
        current_method = initial_method
        current_headers = initial_headers or {}
        current_params = initial_params or {}
        current_body = initial_body

        for step in range(1, max_iterations + 1):
            # Step A: Interaction Agent executes probe
            interaction_data = await self.prober.execute_interaction(
                url=current_url,
                method=current_method,
                headers=current_headers,
                params=current_params,
                json_body=current_body
            )

            # Step B: Analysis Agent inspects response
            analysis_data = await self.analyzer.analyze_response(
                interaction_result=interaction_data,
                custom_analysis_prompt=user_prompt
            )

            cycle_record = {
                "cycle": step,
                "interaction": interaction_data,
                "analysis": analysis_data
            }

            # If not the last iteration, Agent 3 plans the updated test
            if step < max_iterations:
                adaptation_plan = await self.adapter.plan_next_interaction(
                    target_url=target_url,
                    current_step=step,
                    history=history + [cycle_record],
                    custom_goal_prompt=user_prompt
                )
                cycle_record["adaptation"] = adaptation_plan

                # Update state for next cycle
                current_method = adaptation_plan.get("next_method", "GET")
                current_headers = adaptation_plan.get("next_headers", {})
                current_params = adaptation_plan.get("next_params", {})
                current_body = adaptation_plan.get("next_json_body")

            history.append(cycle_record)

        return {
            "status": "COMPLETED",
            "target_url": target_url,
            "total_cycles_executed": len(history),
            "cycles": history
        }


# Global Singleton instance
agent_feedback_loop = MultiAgentFeedbackLoop()
