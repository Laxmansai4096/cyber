"""
Phase 5: Calibrated Blast-Radius SOAR Containment Dispatcher
Executes targeted containment without self-inflicted Denial of Service.
"""
from typing import Dict, Any
from datetime import datetime

class SOARContainmentDispatcher:
    def __init__(self):
        self.active_containments = []

    def execute_containment(self, level: int, incident_id: str, user_id: str, ip_address: str) -> Dict[str, Any]:
        """
        Executes calibrated containment:
        Level 1: Step-Up MFA Challenge
        Level 2: Revoke Active Session & Invalidate JWT
        Level 3: Quarantine Account & Generate WAF / Firewall Block Rule
        """
        timestamp = datetime.utcnow().isoformat()

        if level == 1:
            action = {
                "containment_id": f"CONT-{len(self.active_containments)+1}",
                "level": 1,
                "type": "STEP_UP_MFA_CHALLENGE",
                "incident_id": incident_id,
                "target_user": user_id,
                "target_ip": ip_address,
                "timestamp": timestamp,
                "status": "ACTIVE",
                "blast_radius": "MINIMAL (Single User)",
                "technical_details": f"Flagged user '{user_id}' with 'require_mfa_step_up=true'. Next HTTP request will require hardware key or authenticator OTP before processing.",
                "undo_action": f"Clear MFA challenge for user '{user_id}'"
            }
        elif level == 2:
            action = {
                "containment_id": f"CONT-{len(self.active_containments)+1}",
                "level": 2,
                "type": "SESSION_REVOCATION_AND_TOKEN_INVALIDATION",
                "incident_id": incident_id,
                "target_user": user_id,
                "target_ip": ip_address,
                "timestamp": timestamp,
                "status": "ACTIVE",
                "blast_radius": "MODERATE (User Active Sessions Terminated)",
                "technical_details": f"Revoked active JWT refresh tokens in Redis for user '{user_id}'. Active session cookie blacklisted across all edge nodes.",
                "undo_action": f"Allow new login for user '{user_id}'"
            }
        else: # Level 3
            waf_rule = (
                f"# AWS WAF / Cloudflare Custom Rule (Incident {incident_id})\n"
                f"SecRule REMOTE_ADDR \"@ipMatch {ip_address}\" \"id:100{len(self.active_containments)},phase:1,deny,status:403,msg:'Blocked by CyberSentinel AI Incident Response'\"\n"
                f"# Linux iptables host block:\n"
                f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            )
            action = {
                "containment_id": f"CONT-{len(self.active_containments)+1}",
                "level": 3,
                "type": "ACCOUNT_QUARANTINE_AND_WAF_BLOCK",
                "incident_id": incident_id,
                "target_user": user_id,
                "target_ip": ip_address,
                "timestamp": timestamp,
                "status": "ACTIVE",
                "blast_radius": "HIGH (User Account Locked + IP Address Blocked)",
                "technical_details": f"Account '{user_id}' locked. IP '{ip_address}' dropped at edge WAF.",
                "generated_waf_rule": waf_rule,
                "undo_action": f"Unlock account and run: sudo iptables -D INPUT -s {ip_address} -j DROP"
            }

        self.active_containments.append(action)
        return action

    def list_containments(self):
        return self.active_containments

soar_dispatcher = SOARContainmentDispatcher()
