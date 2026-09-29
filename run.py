"""
CyberSentinel AI - Application Launcher
Starts the FastAPI server with Uvicorn.
"""
import sys
import io
import uvicorn

# Ensure utf-8 encoding for console output on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

if __name__ == "__main__":
    print("=" * 70)
    print("  [+] CYBERSENTINEL AI: AUTONOMOUS WHITE-HAT & BLUE TEAM SECOPS")
    print("=" * 70)
    print("  Initializing engines across all 5 phases...")
    print("  Access Command Center: http://localhost:8000")
    print("=" * 70)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
