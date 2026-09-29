"""
Phase 1: Architecture & System Design Threat Modeling Engine
Implements STRIDE-as-Code, Trust Boundary Mapping, and PII/Regulatory Classification.
"""
from typing import Dict, List, Any
import json
import re

class ThreatModelingEngine:
    def __init__(self):
        self.pii_keywords = [
            "password", "ssn", "social_security", "credit_card", "card_number",
            "cvv", "dob", "birth_date", "passport", "email", "phone_number", "tax_id"
        ]

    def analyze_architecture(self, spec_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes an OpenAPI or architecture specification.
        Evaluates endpoints, data flows, trust boundaries, and flags STRIDE threats.
        """
        title = spec_data.get("info", {}).get("title", "Project Architecture")
        paths = spec_data.get("paths", {})
        
        trust_boundaries = []
        pii_flows = []
        stride_threats = []
        
        # Analyze each endpoint/route
        for path_name, path_item in paths.items():
            for method, details in path_item.items():
                if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    continue
                
                endpoint_desc = f"{method.upper()} {path_name}"
                security = details.get("security", spec_data.get("security", []))
                is_authenticated = bool(security)
                
                # Trust Boundary Crossing Check
                if not is_authenticated:
                    trust_boundaries.append({
                        "boundary": "Public Internet ➔ Internal API",
                        "endpoint": endpoint_desc,
                        "risk": "Unauthenticated entry point directly touching backend handlers"
                    })
                    stride_threats.append({
                        "category": "Spoofing (S)",
                        "severity": "HIGH",
                        "component": endpoint_desc,
                        "description": "Endpoint has no authentication requirement defined. Adversaries can spoof requests.",
                        "mitigation": "Enforce OAuth2/OIDC JWT Bearer validation at the API Gateway."
                    })
                
                # Check for sensitive data in URL paths (Information Disclosure)
                if re.search(r"/(token|key|secret|password|ssn)/", path_name, re.IGNORECASE):
                    stride_threats.append({
                        "category": "Information Disclosure (I)",
                        "severity": "HIGH",
                        "component": endpoint_desc,
                        "description": "Sensitive credential token exposed in URL path, vulnerable to logging in proxy/access logs.",
                        "mitigation": "Move sensitive tokens to HTTP Authorization header or request body."
                    })

                # Check Request Body and Query Params for PII
                parameters = details.get("parameters", [])
                for param in parameters:
                    param_name = param.get("name", "").lower()
                    for pii in self.pii_keywords:
                        if pii in param_name:
                            pii_flows.append({
                                "field": param.get("name"),
                                "endpoint": endpoint_desc,
                                "type": "URL/Query Parameter",
                                "compliance": "GDPR / PCI-DSS Sensitive",
                                "warning": "PII passed in query strings may be cached in browser history and proxy access logs."
                            })
                            stride_threats.append({
                                "category": "Information Disclosure (I)",
                                "severity": "MEDIUM",
                                "component": f"{endpoint_desc} [{param.get('name')}]",
                                "description": f"PII field '{param.get('name')}' sent in clear URL query parameters.",
                                "mitigation": "Encapsulate sensitive fields inside encrypted POST request body over TLS."
                            })

                # Financial / State Mutating Action without Idempotency or Audit
                if method.upper() in ["POST", "PUT", "DELETE"] and any(k in path_name.lower() for k in ["transfer", "payment", "payout", "balance", "order", "delete"]):
                    stride_threats.append({
                        "category": "Repudiation (R)",
                        "severity": "MEDIUM",
                        "component": endpoint_desc,
                        "description": "Critical state-mutating transaction lacks declared cryptographic audit trail / idempotency key.",
                        "mitigation": "Implement non-repudiation audit logging and mandatory Idempotency-Key headers."
                    })
                    
                # Elevation of Privilege check on admin paths
                if any(k in path_name.lower() for k in ["admin", "internal", "config", "debug", "actuator"]):
                    stride_threats.append({
                        "category": "Elevation of Privilege (E)",
                        "severity": "CRITICAL" if not is_authenticated else "HIGH",
                        "component": endpoint_desc,
                        "description": "Administrative route detected. Requires strict Role-Based Access Control (RBAC) validation.",
                        "mitigation": "Enforce strict 'role: admin' claim checks and internal subnet IP restriction."
                    })

                # Denial of Service check for pagination
                if method.upper() == "GET" and any(k in path_name.lower() for k in ["list", "search", "all", "users", "items"]):
                    has_limit = any("limit" in p.get("name", "").lower() or "page" in p.get("name", "").lower() for p in parameters)
                    if not has_limit:
                        stride_threats.append({
                            "category": "Denial of Service (D)",
                            "severity": "MEDIUM",
                            "component": endpoint_desc,
                            "description": "Unbounded collection query. An attacker can request excessive data causing database resource exhaustion.",
                            "mitigation": "Implement mandatory pagination with max limit (e.g. limit=50)."
                        })

        summary = {
            "title": title,
            "endpoints_analyzed": sum(len(methods) for methods in paths.values()),
            "total_stride_threats": len(stride_threats),
            "threat_breakdown": {
                "Critical": len([t for t in stride_threats if t["severity"] == "CRITICAL"]),
                "High": len([t for t in stride_threats if t["severity"] == "HIGH"]),
                "Medium": len([t for t in stride_threats if t["severity"] == "MEDIUM"]),
            },
            "trust_boundaries": trust_boundaries,
            "pii_data_flows": pii_flows,
            "stride_matrix": stride_threats
        }
        return summary
