"""
CyberSentinel AI - Application Launcher
Starts the FastAPI server with Uvicorn.
"""
import uvicorn
import os
import sys

if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  CYBERSENTINEL AI: AUTONOMOUS WHITE-HAT & BLUE TEAM SECOPS")
    print("=" * 70)
    print("  Initializing engines across all 5 phases...")
    print("  Access Command Center: http://localhost:8000")
    print("=" * 70)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
