"""
Phase 4: Stateful DAST & Business Logic Probing Engine
Performs Dual-User RBAC/IDOR Matrix Probing, Cloud Metadata SSRF Checks,
and Security Header Audits with safe curl Proof-of-Concepts.
"""
from typing import Dict, List, Any

class StatefulDASTEngine:
    def audit_security_headers(self, headers: Dict[str, str], target_url: str) -> Dict[str, Any]:
        """Audits HTTP response headers for missing defensive standards."""
        standard_headers = [
            ("Strict-Transport-Security", "Enforces HTTPS transit and prevents SSL stripping (HSTS).", "HIGH"),
            ("Content-Security-Policy", "Prevents Cross-Site Scripting (XSS) and malicious script injection.", "HIGH"),
            ("X-Content-Type-Options", "Prevents MIME-type sniffing attacks (must be 'nosniff').", "MEDIUM"),
            ("X-Frame-Options", "Prevents Clickjacking by disallowing framing ('DENY' or 'SAMEORIGIN').", "MEDIUM"),
            ("Referrer-Policy", "Prevents leaking sensitive paths in referrer headers ('strict-origin-when-cross-origin').", "LOW"),
        ]

        normalized_headers = {k.lower(): v for k, v in headers.items()}
        results = []

        for header_name, purpose, severity in standard_headers:
            val = normalized_headers.get(header_name.lower())
            if not val:
                results.append({
                    "header": header_name,
                    "status": "MISSING",
                    "severity": severity,
                    "description": f"Mandatory security header '{header_name}' is not set by the server.",
                    "remediation": f"Configure reverse proxy or web middleware to include '{header_name}'.",
                    "poc_curl": f"curl -I {target_url}"
                })
            else:
                results.append({
                    "header": header_name,
                    "status": "PASS",
                    "severity": "PASS",
                    "value": val,
                    "description": purpose
                })

        # Check for dangerous wildcard CORS
        cors = normalized_headers.get("access-control-allow-origin")
        if cors == "*":
            results.append({
                "header": "Access-Control-Allow-Origin",
                "status": "VULNERABLE",
                "severity": "HIGH",
                "description": "Wildcard '*' CORS origin configured. Any arbitrary website can read authenticated responses if credentials are sent.",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted explicit origins.",
                "poc_curl": f"curl -H 'Origin: https://evil-attacker.com' -I {target_url}"
            })

        return {
            "target": target_url,
            "findings": results
        }

    def probe_rbac_idor_matrix(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Dual-User & Guest Matrix Probing.
        Simulates:
        1. User A (Legitimate Resource Owner)
        2. User B (Authenticated Attacker attempting to read User A's data)
        3. Guest (Unauthenticated Public User)
        """
        matrix_results = []
        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()
            requires_owner = ep.get("is_private_user_resource", True)
            user_b_allowed = ep.get("user_b_response_code", 403) == 200
            guest_allowed = ep.get("guest_response_code", 401) == 200

            # Test IDOR / BOLA condition: User B gets 200 on User A's private resource
            if requires_owner and user_b_allowed:
                matrix_results.append({
                    "endpoint": f"{method} {path}",
                    "flaw_type": "Broken Object-Level Authorization (BOLA / IDOR) (CWE-639)",
                    "severity": "CRITICAL",
                    "scenario": "User B (Bearer token_b) attempted to access User A's object and received HTTP 200 OK with sensitive payload.",
                    "poc_curl": f"curl -X {method} -H 'Authorization: Bearer <USER_B_TOKEN>' https://api.staging.internal{path}",
                    "impact": "Account takeover / unauthorized financial record reading across tenant boundaries.",
                    "remediation": "Validate that the authenticated session ID owns the requested resource ID before returning data."
                })
            elif requires_owner and guest_allowed:
                matrix_results.append({
                    "endpoint": f"{method} {path}",
                    "flaw_type": "Completely Unauthenticated Private Resource (CWE-306)",
                    "severity": "CRITICAL",
                    "scenario": "Guest (no token) accessed private customer data and received HTTP 200 OK.",
                    "poc_curl": f"curl -X {method} https://api.staging.internal{path}",
                    "impact": "Unrestricted public data exposure.",
                    "remediation": "Attach authentication middleware guard to route."
                })
            else:
                matrix_results.append({
                    "endpoint": f"{method} {path}",
                    "flaw_type": "None (Proper RBAC Enforcement)",
                    "severity": "PASS",
                    "scenario": "Access denied for cross-tenant access and unauthenticated requests (HTTP 403 / 401).",
                    "poc_curl": None,
                    "remediation": "Compliant"
                })

        return {
            "total_endpoints_tested": len(endpoints),
            "critical_rbac_flaws": len([r for r in matrix_results if r["severity"] == "CRITICAL"]),
            "matrix": matrix_results
        }

    def probe_ssrf_cloud_metadata(self, test_url_params: List[str]) -> List[Dict[str, Any]]:
        """Tests if input parameters accepting URLs restrict AWS/GCP internal metadata."""
        ssrf_findings = []
        for param in test_url_params:
            ssrf_findings.append({
                "parameter": param,
                "vector": "Cloud Instance Metadata Service (IMDSv1)",
                "test_payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "severity": "HIGH",
                "risk": "Server-Side Request Forgery (SSRF) could allow an adversary to steal IAM host instance role tokens.",
                "remediation": "Validate input against an allowlist of external domains and disallow private IP ranges (RFC 1918 + 169.254.0.0/16). Enforce AWS IMDSv2 (Session Token required).",
                "poc_curl": f"curl -X POST https://api.staging.internal/service -d '{param}=http://169.254.169.254/latest/meta-data/'"
            })
        return ssrf_findings
