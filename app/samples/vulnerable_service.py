"""
Sample Vulnerable Service (Used for Phase 2 White-Hat SAST Testing)
Contains intentional security flaws to validate detection and auto-patching:
- SQL Injection (CWE-89)
- Hardcoded Secret (CWE-798)
- Command Injection (CWE-78)
- Broken Object-Level Authorization (IDOR) (CWE-639)
"""
import os
import sqlite3
import subprocess
import yaml

# CRITICAL FLAW 1: Hardcoded AWS Access Key (CWE-798)
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:SuperSecretPass123!@db.internal:5432/production"

def query_user_account(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # CRITICAL FLAW 2: Raw string interpolation leading to SQL Injection (CWE-89)
    query = f"SELECT * FROM accounts WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

def diagnostic_ping(target_host):
    # CRITICAL FLAW 3: Untrusted shell command concatenation (CWE-78)
    cmd = f"ping -c 1 {target_host}"
    return os.system(cmd)

def view_order_details(order_id, current_user):
    # HIGH FLAW 4: BOLA / IDOR - Fetches without checking current_user ownership (CWE-639)
    order = Order.query.get(order_id)
    return order

def parse_config(raw_yaml):
    # CRITICAL FLAW 5: PyYAML unsafe load (CVE-2020-14343)
    return yaml.load(raw_yaml)
