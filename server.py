import os
import time
import json
import asyncio
import logging
from typing import Dict,Any,Optional
import pandas as pd
from fastapi import FastAPI,WebSocket,WebSocketDisconnect,HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse,JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ids_engine import IDSEngine
from notifications import NotificationManager

logger=logging.getLogger("ids_server")
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

BASE_DIR=os.path.dirname(os.path.abspath(__file__))
STATIC_DIR=os.path.join(BASE_DIR,"static")
os.makedirs(STATIC_DIR,exist_ok=True)

app=FastAPI(title="ML-Based Intrusion Detection System",version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ids_engine=IDSEngine(base_dir=BASE_DIR)
notification_mgr=NotificationManager()
stream_task:Optional[asyncio.Task]=None
connected_websockets=set()

class ModelSelectRequest(BaseModel):
    model:str

class SensitivityRequest(BaseModel):
    threshold:float

class SpeedRequest(BaseModel):
    speed:float

class AttackSimulationRequest(BaseModel):
    attack_type:str

class NotificationConfigRequest(BaseModel):
    enabled:Optional[bool]=None
    desktop_toasts:Optional[bool]=None
    sound_enabled:Optional[bool]=None
    cooldown_seconds:Optional[float]=None
    min_confidence:Optional[float]=None
    min_severity:Optional[str]=None
    webhook_enabled:Optional[bool]=None
    webhook_url:Optional[str]=None

@app.get("/")
async def serve_index():
    index_path=os.path.join(STATIC_DIR,"index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"status":"error","message":"Frontend index.html not yet initialized"})

@app.post("/api/engine/start")
async def start_engine():
    ids_engine.start()
    return {"status":"success","state":ids_engine.stats["engine_state"]}

@app.post("/api/engine/stop")
async def stop_engine():
    ids_engine.stop()
    return {"status":"success","state":ids_engine.stats["engine_state"]}

@app.post("/api/engine/pause")
async def pause_engine():
    ids_engine.pause()
    return {"status":"success","state":ids_engine.stats["engine_state"]}

@app.post("/api/engine/resume")
async def resume_engine():
    ids_engine.resume()
    return {"status":"success","state":ids_engine.stats["engine_state"]}

@app.post("/api/engine/model")
async def change_model(req:ModelSelectRequest):
    success=ids_engine.set_model(req.model)
    if not success:
        raise HTTPException(status_code=400,detail="Invalid model name. Must be 'xgboost', 'lightgbm', or 'ensemble'.")
    return {"status":"success","active_model":ids_engine.active_model_name}

@app.post("/api/engine/sensitivity")
async def change_sensitivity(req:SensitivityRequest):
    ids_engine.set_sensitivity(req.threshold)
    return {"status":"success","sensitivity":ids_engine.sensitivity_threshold}

@app.post("/api/engine/speed")
async def change_speed(req:SpeedRequest):
    ids_engine.set_stream_speed(req.speed)
    return {"status":"success","stream_speed":ids_engine.stream_speed}

@app.post("/api/simulate/attack")
async def simulate_attack(req:AttackSimulationRequest):
    flow_event=ids_engine.process_next_cycle(injected_attack=req.attack_type)
    notif_res=notification_mgr.notify_threat(flow_event)
    payload=json.dumps({
        "type":"simulated_threat",
        "flow":flow_event,
        "notification":notif_res,
        "stats":ids_engine.stats,
    })
    for ws in list(connected_websockets):
        try:
            await ws.send_text(payload)
        except Exception:
            pass
    return {
        "status":"success",
        "attack_type":req.attack_type,
        "flow":flow_event,
        "notification":notif_res,
    }

@app.get("/api/engine/status")
async def get_engine_status():
    return ids_engine.get_dashboard_summary()

@app.get("/api/model/metrics")
async def get_model_metrics():
    csv_path=os.path.join(BASE_DIR,"comparison_results.csv")
    metrics_data=[]
    if os.path.exists(csv_path):
        df=pd.read_csv(csv_path)
        metrics_data=df.to_dict(orient="records")
    return {
        "comparison":metrics_data,
        "selected_features":ids_engine.selected_features,
        "scaler_features":ids_engine.scaler_features,
        "classes":ids_engine.classes,
        "active_model":ids_engine.active_model_name,
    }

@app.get("/api/notifications/config")
async def get_notification_config():
    return notification_mgr.get_config()

@app.post("/api/notifications/config")
async def update_notification_config(req:NotificationConfigRequest):
    cfg=req.dict(exclude_unset=True)
    notification_mgr.update_config(cfg)
    return {"status":"success","config":notification_mgr.get_config()}

@app.post("/api/notifications/test")
async def test_notification():
    return notification_mgr.send_test_notification()

@app.get("/api/notifications/history")
async def get_notification_history():
    return {"history":notification_mgr.get_history()}

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket:WebSocket):
    await websocket.accept()
    connected_websockets.add(websocket)
    logger.info(f"WebSocket client connected. Total clients: {len(connected_websockets)}")
    try:
        init_payload={
            "type":"init_state",
            "dashboard":ids_engine.get_dashboard_summary(),
            "notification_config":notification_mgr.get_config(),
        }
        await websocket.send_text(json.dumps(init_payload))
    except Exception as e:
        logger.error(f"Error sending init state to WebSocket: {e}")
    try:
        while True:
            data=await websocket.receive_text()
            try:
                msg=json.loads(data)
                cmd=msg.get("command")
                if cmd=="start":
                    ids_engine.start()
                elif cmd=="stop":
                    ids_engine.stop()
                elif cmd=="pause":
                    ids_engine.pause()
                elif cmd=="resume":
                    ids_engine.resume()
                elif cmd=="set_model":
                    ids_engine.set_model(msg.get("model"))
                elif cmd=="set_sensitivity":
                    ids_engine.set_sensitivity(msg.get("threshold"))
                elif cmd=="set_speed":
                    ids_engine.set_stream_speed(msg.get("speed"))
                elif cmd=="simulate_attack":
                    attack_type=msg.get("attack_type","DoS")
                    flow=ids_engine.process_next_cycle(injected_attack=attack_type)
                    notif=notification_mgr.notify_threat(flow)
                    await websocket.send_text(json.dumps({
                        "type":"simulated_threat",
                        "flow":flow,
                        "notification":notif,
                        "stats":ids_engine.stats,
                    }))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)
        logger.info("WebSocket client disconnected.")
    except Exception as e:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
        logger.warning(f"WebSocket closed: {e}")

async def telemetry_broadcast_loop():
    while True:
        try:
            if ids_engine.is_running and not ids_engine.is_paused and len(connected_websockets)>0:
                flow_events=[]
                for _ in range(10):
                    flow=ids_engine.process_next_cycle()
                    if flow is None:
                        break
                    flow_events.append(flow)
                    if flow["is_threat"]:
                        notification_mgr.notify_threat(flow)
                host_stats=ids_engine.get_system_telemetry()
                payload=json.dumps({
                    "type":"telemetry_tick",
                    "flows":flow_events,
                    "stats":ids_engine.stats,
                    "host":host_stats,
                })
                for ws in list(connected_websockets):
                    try:
                        await ws.send_text(payload)
                    except Exception:
                        pass
            await asyncio.sleep(0.15)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in telemetry broadcast loop: {e}",exc_info=True)
            await asyncio.sleep(1.0)

@app.on_event("startup")
async def startup_event():
    global stream_task
    app.mount("/static",StaticFiles(directory=STATIC_DIR),name="static")
    stream_task=asyncio.create_task(telemetry_broadcast_loop())
    logger.info("FastAPI IDS Application started successfully.")

@app.on_event("shutdown")
async def shutdown_event():
    global stream_task
    if stream_task:
        stream_task.cancel()
    logger.info("FastAPI IDS Application shut down.")
