import os
import sys
import time
import json
import logging
import threading
import subprocess

logger=logging.getLogger("ids_notifications")
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

try:
    from win11toast import toast
    WIN11TOAST_AVAILABLE=True
except ImportError:
    WIN11TOAST_AVAILABLE=False

try:
    from plyer import notification as plyer_notification
    PLYER_AVAILABLE=True
except ImportError:
    PLYER_AVAILABLE=False

class NotificationManager:
    def __init__(self):
        self.enabled=True
        self.desktop_toasts=True
        self.sound_enabled=True
        self.cooldown_seconds=10.0
        self.min_confidence=0.80
        self.min_severity="HIGH"
        self.webhook_enabled=False
        self.webhook_url=""
        self.last_alert_times={}
        self.history=[]
        self.max_history=50
        self.lock=threading.Lock()

    def update_config(self,config_dict):
        with self.lock:
            if "enabled" in config_dict:
                self.enabled=bool(config_dict["enabled"])
            if "desktop_toasts" in config_dict:
                self.desktop_toasts=bool(config_dict["desktop_toasts"])
            if "sound_enabled" in config_dict:
                self.sound_enabled=bool(config_dict["sound_enabled"])
            if "cooldown_seconds" in config_dict:
                self.cooldown_seconds=max(1.0,float(config_dict["cooldown_seconds"]))
            if "min_confidence" in config_dict:
                self.min_confidence=max(0.1,min(0.99,float(config_dict["min_confidence"])))
            if "min_severity" in config_dict:
                self.min_severity=str(config_dict["min_severity"])
            if "webhook_enabled" in config_dict:
                self.webhook_enabled=bool(config_dict["webhook_enabled"])
            if "webhook_url" in config_dict:
                self.webhook_url=str(config_dict["webhook_url"]).strip()
            logger.info("Notification configuration updated.")

    def get_config(self):
        with self.lock:
            return {
                "enabled":self.enabled,
                "desktop_toasts":self.desktop_toasts,
                "sound_enabled":self.sound_enabled,
                "cooldown_seconds":self.cooldown_seconds,
                "min_confidence":self.min_confidence,
                "min_severity":self.min_severity,
                "webhook_enabled":self.webhook_enabled,
                "webhook_url":self.webhook_url,
                "win11toast_available":WIN11TOAST_AVAILABLE,
                "plyer_available":PLYER_AVAILABLE,
            }

    def _should_notify(self,threat_event):
        if not self.enabled:
            return False
        if not threat_event.get("is_threat",False) or threat_event.get("label")=="Benign":
            return False
        if threat_event.get("is_infrastructure",False) or threat_event.get("src_is_gateway",False) or threat_event.get("dst_is_gateway",False):
            return False
        is_simulated=(threat_event.get("simulated_type") is not None) or (not threat_event.get("is_live_capture",True))
        if not is_simulated:
            if threat_event.get("src_is_local",False) or threat_event.get("src_is_gateway",False):
                return False
        confidence=threat_event.get("confidence",0.0)
        if confidence<self.min_confidence:
            return False
        severity_ranks={"INFO":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
        event_rank=severity_ranks.get(threat_event.get("severity","MEDIUM"),1)
        required_rank=severity_ranks.get(self.min_severity,1)
        if event_rank<required_rank:
            return False
        label=threat_event.get("label","Threat")
        now=time.time()
        last_time=self.last_alert_times.get(label,0)
        if (now-last_time)<self.cooldown_seconds:
            return False
        return True

    def notify_threat(self,threat_event):
        with self.lock:
            if not self._should_notify(threat_event):
                return {"dispatched":False,"reason":"cooldown_or_threshold"}
            label=threat_event.get("label","Malicious Flow")
            self.last_alert_times[label]=time.time()
            title=f"🛡️ Windows Defender Alert: {label} Detected!"
            confidence_pct=round(threat_event.get("confidence",0.95)*100,1)
            src_ip=threat_event.get("src_ip","Unknown")
            dst_port=threat_event.get("dst_port","80")
            proto=threat_event.get("protocol","TCP")
            severity=threat_event.get("severity","HIGH")
            body=(
                f"[{severity} RISK] {label} detected from {src_ip} -> Port {dst_port}/{proto}\n"
                f"Confidence: {confidence_pct}% | Action: Packet Flagged & Logged."
            )
            record={
                "timestamp":time.time(),
                "time_formatted":time.strftime("%H:%M:%S"),
                "title":title,
                "body":body,
                "label":label,
                "severity":severity,
                "confidence":threat_event.get("confidence",0.0),
                "src_ip":src_ip,
                "status":"dispatched",
            }
            self.history.insert(0,record)
            if len(self.history)>self.max_history:
                self.history.pop()
        threading.Thread(target=self._send_toast_async,args=(title,body,severity),daemon=True).start()
        if self.webhook_enabled and self.webhook_url:
            threading.Thread(target=self._send_webhook_async,args=(record,),daemon=True).start()
        return {"dispatched":True,"record":record}

    def _send_toast_async(self,title,body,severity):
        if not self.desktop_toasts:
            return
        try:
            if WIN11TOAST_AVAILABLE:
                audio_src="ms-winsoundevent:Notification.Looping.Alarm" if self.sound_enabled else None
                toast(
                    title,
                    body,
                    audio=audio_src,
                    scenario="alarm" if severity=="CRITICAL" else "reminder",
                )
                logger.info(f"Dispatched Win11/10 Toast: {title}")
                return
        except Exception as e:
            logger.warning(f"win11toast failed: {e}. Falling back to plyer/PowerShell.")
        try:
            if PLYER_AVAILABLE:
                plyer_notification.notify(
                    title=title,
                    message=body,
                    app_name="ML-Based IDS Defender",
                    timeout=6,
                )
                logger.info(f"Dispatched Plyer Toast: {title}")
                return
        except Exception as e:
            logger.warning(f"Plyer toast failed: {e}. Falling back to PowerShell WinRT.")
        try:
            ps_script=f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $template = @"
            <toast>
                <visual>
                    <binding template='ToastGeneric'>
                        <text>{title}</text>
                        <text>{body}</text>
                    </binding>
                </visual>
            </toast>
            "@
            $xml.LoadXml($template)
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ML-Based IDS Defender').Show($toast)
            """
            subprocess.run(["powershell","-Command",ps_script],capture_output=True,timeout=5)
            logger.info("Dispatched PowerShell Toast alert.")
        except Exception as e:
            logger.error(f"Failed all desktop toast mechanisms: {e}")

    def _send_webhook_async(self,record):
        try:
            import requests
            requests.post(self.webhook_url,json=record,timeout=5)
            logger.info(f"Webhook alert posted to {self.webhook_url}")
        except Exception as e:
            logger.warning(f"Failed to send webhook notification: {e}")

    def send_test_notification(self):
        title="🛡️ Windows Defender Test Alert: IDS Protection Active"
        body="Test Notification: ML-Based IDS is actively monitoring network flows and ready to defend your device!"
        record={
            "timestamp":time.time(),
            "time_formatted":time.strftime("%H:%M:%S"),
            "title":title,
            "body":body,
            "label":"Test Alert",
            "severity":"CRITICAL",
            "confidence":1.0,
            "src_ip":"127.0.0.1",
            "status":"test_dispatched",
        }
        with self.lock:
            self.history.insert(0,record)
            if len(self.history)>self.max_history:
                self.history.pop()
        threading.Thread(target=self._send_toast_async,args=(title,body,"CRITICAL"),daemon=True).start()
        return {"status":"success","message":"Test notification dispatched to your device."}

    def get_history(self):
        with self.lock:
            return list(self.history)
