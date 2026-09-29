"""
Phase 5: Blue Team UEBA & Real-Time Session Telemetry SOC Engine
Detects Account Takeover (ATO), Stolen Credentials, Impossible Travel,
Session Hijacking, Mass Data Exfiltration / Scraping, and Honeytoken triggers.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
import math

class BlueTeamSOCEngine:
    def __init__(self):
        # Known honeytokens planted in code/configs
        self.honeytokens = {
            "AKIAIOSFODNN7EXAMPLE": "AWS Canary Key in .env.example",
            "postgres://canary_user:DecoyPass123@db.internal/vault": "Canary Database Connection String",
            "/api/v1/internal/debug-keys": "Decoy Internal Endpoint"
        }

    def analyze_session_logs(self, session_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes a chronological stream of user session events and API requests.
        Raises real-time security incidents with MITRE ATT&CK mappings.
        """
        incidents = []
        user_history: Dict[str, List[Dict[str, Any]]] = {}

        # 1. Group events by user_id and session_token
        for ev in session_events:
            uid = ev.get("user_id", "anonymous")
            if uid not in user_history:
                user_history[uid] = []
            user_history[uid].append(ev)

        # 2. Analyze user behaviors and detect mischief
        for uid, events in user_history.items():
            failed_logins = 0
            login_times = []
            
            # Sort events by timestamp
            events.sort(key=lambda x: x.get("timestamp", ""))

            for i in range(len(events)):
                curr = events[i]
                action = curr.get("action", "")
                ip = curr.get("ip_address", "")
                user_agent = curr.get("user_agent", "")
                path = curr.get("endpoint", "")
                payload = curr.get("payload", {})
                geo = curr.get("location", {})

                # Check A: Honeytoken / Canary Trigger (0% False Positive!)
                for token_val, desc in self.honeytokens.items():
                    if token_val in str(payload) or token_val in path or token_val == curr.get("token_used"):
                        incidents.append({
                            "id": f"INC-HONEYTOKEN-{len(incidents)+1}",
                            "timestamp": curr.get("timestamp", datetime.utcnow().isoformat()),
                            "user_id": uid,
                            "severity": "CRITICAL",
                            "title": "Active Canary Honeytoken Accessed! Intrusion Confirmed",
                            "mitre_technique": "T1078 - Valid Accounts (Compromised Credential)",
                            "source_ip": ip,
                            "user_agent": user_agent,
                            "description": f"Adversary attempted to use synthetic decoy asset: '{desc}'. This credential is never used by legitimate systems.",
                            "recommended_action": "Level 3: Immediately Quarantine Account & Block Source IP on Firewall.",
                            "containment_ready": True
                        })

                # Check B: Credential Stuffing / Brute Force
                if action == "login_failed":
                    failed_logins += 1
                elif action == "login_success":
                    if failed_logins >= 5:
                        incidents.append({
                            "id": f"INC-BRUTEFORCE-{len(incidents)+1}",
                            "timestamp": curr.get("timestamp", datetime.utcnow().isoformat()),
                            "user_id": uid,
                            "severity": "HIGH",
                            "title": "Credential Stuffing / Brute-Force Succeeded (T1110)",
                            "mitre_technique": "T1110 - Brute Force",
                            "source_ip": ip,
                            "user_agent": user_agent,
                            "description": f"Account experienced {failed_logins} failed attempts immediately before a successful login. Possible password compromise.",
                            "recommended_action": "Level 1: Trigger Step-Up MFA Challenge on next request.",
                            "containment_ready": True
                        })
                    failed_logins = 0

                # Check C: Session Fingerprint Drift / Session Hijacking (T1539)
                if i > 0 and curr.get("session_token") == events[i-1].get("session_token"):
                    prev = events[i-1]
                    # Sudden change in User Agent or IP without re-auth
                    ua_changed = (user_agent != prev.get("user_agent")) and bool(user_agent and prev.get("user_agent"))
                    ip_changed = (ip != prev.get("ip_address")) and bool(ip and prev.get("ip_address"))

                    if ua_changed and ip_changed:
                        incidents.append({
                            "id": f"INC-SESSION-HIJACK-{len(incidents)+1}",
                            "timestamp": curr.get("timestamp", datetime.utcnow().isoformat()),
                            "user_id": uid,
                            "severity": "CRITICAL",
                            "title": "Session Token Hijacking / Replay Detected (T1539)",
                            "mitre_technique": "T1539 - Steal Web Session Cookie",
                            "source_ip": ip,
                            "user_agent": user_agent,
                            "description": f"Active session cookie switched from {prev.get('ip_address')} ({prev.get('user_agent')}) to {ip} ({user_agent}) mid-stream. Token likely stolen.",
                            "recommended_action": "Level 2: Invalidate JWTs & Revoke Active Session immediately.",
                            "containment_ready": True
                        })

                # Check D: Impossible Travel Anomaly
                if i > 0:
                    prev = events[i-1]
                    prev_geo = prev.get("location", {})
                    curr_geo = geo
                    if prev_geo and curr_geo and prev_geo.get("country") != curr_geo.get("country"):
                        # Calculate time delta in minutes
                        try:
                            t1 = datetime.fromisoformat(prev.get("timestamp", "").replace("Z", ""))
                            t2 = datetime.fromisoformat(curr.get("timestamp", "").replace("Z", ""))
                            delta_mins = abs((t2 - t1).total_seconds()) / 60.0
                            if delta_mins < 45: # Under 45 minutes across different nations
                                incidents.append({
                                    "id": f"INC-IMPOSSIBLE-TRAVEL-{len(incidents)+1}",
                                    "timestamp": curr.get("timestamp", datetime.utcnow().isoformat()),
                                    "user_id": uid,
                                    "severity": "HIGH",
                                    "title": "Impossible Travel Velocity Anomaly",
                                    "mitre_technique": "T1078.004 - Cloud Administration & Account Access",
                                    "source_ip": ip,
                                    "user_agent": user_agent,
                                    "description": f"User session jumped from {prev_geo.get('city')}, {prev_geo.get('country')} to {curr_geo.get('city')}, {curr_geo.get('country')} in {delta_mins:.1f} minutes. Physically impossible velocity.",
                                    "recommended_action": "Level 1: Force Step-Up MFA challenge or verify session.",
                                    "containment_ready": True
                                })
                        except Exception:
                            pass

                # Check E: Mass Data Scraping / Exfiltration (T1048)
                records_fetched = curr.get("records_fetched", 0)
                if records_fetched >= 500 or any(kw in path.lower() for kw in ["dump", "export_all", "download_all", "all_customers"]):
                    incidents.append({
                        "id": f"INC-EXFILTRATION-{len(incidents)+1}",
                        "timestamp": curr.get("timestamp", datetime.utcnow().isoformat()),
                        "user_id": uid,
                        "severity": "CRITICAL",
                        "title": "Mass Data Exfiltration & Database Scraping (T1048)",
                        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol / Bulk Download",
                        "source_ip": ip,
                        "user_agent": user_agent,
                        "description": f"User initiated bulk export of {records_fetched} records from endpoint '{path}'. Exceeds standard baseline of 5-10 records/day.",
                        "recommended_action": "Level 2: Revoke active session, terminate export task, and notify Data Protection Officer (DPO).",
                        "containment_ready": True
                    })

        return {
            "total_events_processed": len(session_events),
            "incidents_raised": len(incidents),
            "threat_levels": {
                "Critical": len([i for i in incidents if i["severity"] == "CRITICAL"]),
                "High": len([i for i in incidents if i["severity"] == "HIGH"]),
                "Medium": len([i for i in incidents if i["severity"] == "MEDIUM"]),
            },
            "incidents": incidents
        }
