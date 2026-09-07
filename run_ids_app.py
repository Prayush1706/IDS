import sys
import os
import time
import webbrowser
import threading
import uvicorn

if __name__=="__main__":
    port=8000
    host="127.0.0.1"
    url=f"http://{host}:{port}"
    print("="*70)
    print("🛡️  IDS // AI CYBER DEFENSE & LOCAL DETECTION SYSTEM")
    print(f"🚀 Starting server at {url}")
    print("🔔 Windows Defender Native Toast Alerts: ACTIVE")
    print("="*70)
    def open_browser():
        time.sleep(1.2)
        print(f"🌐 Opening dashboard at {url}...")
        webbrowser.open(url)
    threading.Thread(target=open_browser,daemon=True).start()
    uvicorn.run("server:app",host=host,port=port,log_level="info")
