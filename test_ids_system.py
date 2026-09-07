import sys
import os
import time

if hasattr(sys.stdout,"reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_tests():
    print("Testing IDS Engine...")
    from ids_engine import IDSEngine
    engine=IDSEngine()
    assert len(engine.scaler_features)==31,f"Expected 31 scaler features, got {len(engine.scaler_features)}"
    assert len(engine.selected_features)==15,f"Expected 15 selected features, got {len(engine.selected_features)}"
    assert len(engine.classes)==21,f"Expected 21 classes, got {len(engine.classes)}"
    print(f"[PASS] Resources loaded: {len(engine.classes)} classes, {len(engine.selected_features)} features.")
    sim_flow=engine.generate_simulated_attack_flow("DoS")
    pred_res=engine.predict(sim_flow["raw_features"],model_override="xgboost")
    print(f"[PASS] XGBoost prediction: label={pred_res['label']}, conf={pred_res['confidence']}, latency={pred_res['latency_ms']}ms")
    pred_lgb=engine.predict(sim_flow["raw_features"],model_override="lightgbm")
    print(f"[PASS] LightGBM prediction: label={pred_lgb['label']}, conf={pred_lgb['confidence']}, latency={pred_lgb['latency_ms']}ms")
    dos_event=engine.process_next_cycle(injected_attack="DoS")
    assert dos_event["is_threat"] is True,"DoS event should be flagged as threat"
    print(f"[PASS] Simulated DoS threat: is_threat={dos_event['is_threat']}, severity={dos_event['severity']}")
    print("Testing Notification Manager...")
    from notifications import NotificationManager
    notif_mgr=NotificationManager()
    cfg=notif_mgr.get_config()
    print(f"[PASS] Notification config: toasts={cfg['desktop_toasts']}, sound={cfg['sound_enabled']}")
    res=notif_mgr.notify_threat(dos_event)
    print(f"[PASS] Threat notification dispatched: {res['dispatched']}")
    print("\nALL UNIT TESTS PASSED SUCCESSFULLY!")

if __name__=="__main__":
    run_tests()
