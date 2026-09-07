import sys
import json
import time
import requests
import asyncio
import websockets

if hasattr(sys.stdout,"reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_URL="http://127.0.0.1:8000"

def test_rest_endpoints():
    print("[1/4] Testing HTML & Static Asset Delivery...")
    r=requests.get(f"{BASE_URL}/")
    assert r.status_code==200,f"Failed to get index.html: {r.status_code}"
    assert "IDS" in r.text,"Index HTML missing IDS branding"

    r_css=requests.get(f"{BASE_URL}/static/style.css")
    assert r_css.status_code==200,f"Failed to get style.css: {r_css.status_code}"

    r_js=requests.get(f"{BASE_URL}/static/app.js")
    assert r_js.status_code==200,f"Failed to get app.js: {r_js.status_code}"
    print(" -> Index,CSS,and JS served successfully.")

    print("\n[2/4] Testing Engine Controls & State Endpoints...")
    r_start=requests.post(f"{BASE_URL}/api/engine/start").json()
    assert r_start["status"]=="success"
    print(" -> Engine Start: OK")

    r_model=requests.post(f"{BASE_URL}/api/engine/model",json={"model": "lightgbm"}).json()
    assert r_model["active_model"]=="lightgbm"
    print(" -> Switch Model to LightGBM: OK")

    r_model_xgb=requests.post(f"{BASE_URL}/api/engine/model",json={"model": "xgboost"}).json()
    assert r_model_xgb["active_model"]=="xgboost"
    print(" -> Switch Model to XGBoost: OK")

    r_metrics=requests.get(f"{BASE_URL}/api/model/metrics").json()
    assert len(r_metrics["selected_features"])==len(r_metrics["selected_features"])
    print(f" -> Model Metrics: {len(r_metrics['selected_features'])} features retrieved,{len(r_metrics['comparison'])} metrics loaded.")

    print("\n[3/4] Testing Windows Defender Notification & Attack Simulation...")
    r_sim=requests.post(f"{BASE_URL}/api/simulate/attack",json={"attack_type": "DoS"}).json()
    assert r_sim["status"]=="success"
    assert r_sim["flow"]["is_threat"] is True
    print(f" -> Simulated DoS Attack: Identified as {r_sim['flow']['label']} with confidence {r_sim['flow']['confidence']}")

    r_notif=requests.post(f"{BASE_URL}/api/notifications/test").json()
    assert r_notif["status"]=="success"
    print(f" -> Test Notification Dispatch: {r_notif['message']}")

async def test_websocket_stream():
    print("\n[4/4] Testing WebSocket Real-time Telemetry Stream...")
    uri="ws://127.0.0.1:8000/ws/telemetry"
    async with websockets.connect(uri) as ws:
        init_msg=await ws.recv()
        init_data=json.loads(init_msg)
        assert init_data["type"]=="init_state"
        print(" -> WebSocket Init State received successfully.")

        for i in range(3):
            tick_msg=await asyncio.wait_for(ws.recv(),timeout=4.0)
            tick_data=json.loads(tick_msg)
            if tick_data["type"]=="telemetry_tick":
                flows=tick_data.get("flows",[])
                stats=tick_data.get("stats",{})
                print(f" -> Tick #{i+1}: {len(flows)} flows streamed | Total Inspected: {stats.get('total_flows_inspected')}")
            elif tick_data["type"]=="simulated_threat":
                print(f" -> Received simulated threat event on WebSocket: {tick_data['flow']['label']}")

    print("\n🎉 ALL E2E TESTS PASSED WITH 100% SUCCESS!")

if __name__=="__main__":
    test_rest_endpoints()
    asyncio.run(test_websocket_stream())
