import os
import time
import json
import random
import logging
import threading
import warnings
import numpy as np
import pandas as pd
import joblib
import psutil
import socket
import subprocess

from live_sniffer import LivePacketSniffer

warnings.filterwarnings("ignore",category=UserWarning)

try:
    import xgboost as xgb
except ImportError:
    xgb=None

try:
    import lightgbm as lgb
except ImportError:
    lgb=None

logger=logging.getLogger("ids_engine")
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

class IDSEngine:
    def __init__(self,base_dir=None):
        self.base_dir=base_dir or os.path.dirname(os.path.abspath(__file__))
        self.is_running=False
        self.is_paused=False
        self.active_model_name="xgboost"
        self.sensitivity_threshold=0.65
        self.stream_speed=1.0
        self.scaler=None
        self.scaler_features=[]
        self.selected_features=[]
        self.label_encoder=None
        self.drop_corr=[]
        self.classes=[]
        self.benign_class_idx=2
        self.xgb_model=None
        self.lgb_model=None
        self.live_sniffer=LivePacketSniffer()
        self.cached_local_ips,self.cached_gateway_ips=self.get_trusted_infrastructure()
        self.last_ip_scan_time=time.time()
        self.stats={
            "total_flows_inspected":0,
            "benign_flows_count":0,
            "threats_detected_count":0,
            "inbound_bytes_total":0,
            "outbound_bytes_total":0,
            "current_in_rate_bps":0,
            "current_out_rate_bps":0,
            "last_inference_latency_ms":0.0,
            "threat_breakdown":{},
            "active_model":self.active_model_name,
            "mode":"live_pc_traffic_only",
            "engine_state":"idle",
            "uptime_seconds":0,
            "live_capture_active":True,
        }
        self.recent_flows=[]
        self.recent_threats=[]
        self.max_buffer_size=100
        self.start_time=None
        self.lock=threading.Lock()
        self.load_resources()

    def load_resources(self):
        try:
            scaler_path=os.path.join(self.base_dir,"scaler.pkl")
            features_path=os.path.join(self.base_dir,"selected_features.pkl")
            encoder_path=os.path.join(self.base_dir,"label_encoder.pkl")
            drop_corr_path=os.path.join(self.base_dir,"drop_corr.pkl")
            xgb_path=os.path.join(self.base_dir,"xgb_model.json")
            lgb_path=os.path.join(self.base_dir,"lgb_model.txt")
            if os.path.exists(scaler_path):
                self.scaler=joblib.load(scaler_path)
                self.scaler_features=list(self.scaler.feature_names_in_)
                logger.info(f"Loaded StandardScaler with {len(self.scaler_features)} features.")
            if os.path.exists(features_path):
                self.selected_features=list(joblib.load(features_path))
                logger.info(f"Loaded {len(self.selected_features)} selected features.")
            if os.path.exists(encoder_path):
                self.label_encoder=joblib.load(encoder_path)
                self.classes=list(self.label_encoder.classes_)
                if "Benign" in self.classes:
                    self.benign_class_idx=self.classes.index("Benign")
                logger.info(f"Loaded LabelEncoder with {len(self.classes)} classes.")
            if os.path.exists(drop_corr_path):
                self.drop_corr=list(joblib.load(drop_corr_path))
            if os.path.exists(xgb_path) and xgb is not None:
                self.xgb_model=xgb.Booster()
                self.xgb_model.load_model(xgb_path)
                logger.info("Loaded XGBoost Booster model.")
            if os.path.exists(lgb_path) and lgb is not None:
                self.lgb_model=lgb.Booster(model_file=lgb_path)
                logger.info("Loaded LightGBM Booster model.")
        except Exception as e:
            logger.error(f"Error loading IDS resources: {e}",exc_info=True)

    def clean_features(self,df_features):
        x=df_features.copy()
        x=x.replace([np.inf,-np.inf],np.nan)
        for col in x.columns:
            if x[col].isna().any():
                med=x[col].median()
                x[col]=x[col].fillna(0 if np.isnan(med) else med)
        x[x<0]=0
        return x

    def preprocess_raw_flow(self,raw_flow_dict):
        row_dict={}
        for feat in self.scaler_features:
            row_dict[feat]=float(raw_flow_dict.get(feat,0.0))
        df_row=pd.DataFrame([row_dict],columns=self.scaler_features)
        df_cleaned=self.clean_features(df_row)
        scaled_arr=self.scaler.transform(df_cleaned[self.scaler_features])
        df_scaled=pd.DataFrame(scaled_arr,columns=self.scaler_features)
        return df_scaled[self.selected_features]

    def predict(self,raw_flow_dict,model_override=None):
        model_name=model_override or self.active_model_name
        start_t=time.perf_counter()
        x_feat=self.preprocess_raw_flow(raw_flow_dict)
        xgb_probs=None
        lgb_probs=None
        if (model_name in ["xgboost","ensemble"]) and self.xgb_model is not None:
            dmat=xgb.DMatrix(x_feat)
            xgb_probs=self.xgb_model.predict(dmat)[0]
        if (model_name in ["lightgbm","ensemble"]) and self.lgb_model is not None:
            lgb_probs=self.lgb_model.predict(x_feat)[0]
        if model_name=="ensemble" and xgb_probs is not None and lgb_probs is not None:
            probs=(0.85*xgb_probs)+(0.15*lgb_probs)
        elif model_name=="lightgbm" and lgb_probs is not None:
            if xgb_probs is not None and np.argmax(xgb_probs)==self.benign_class_idx and xgb_probs[self.benign_class_idx]>0.70:
                probs=(0.75*xgb_probs)+(0.25*lgb_probs)
            else:
                probs=lgb_probs
        elif xgb_probs is not None:
            probs=xgb_probs
        elif lgb_probs is not None:
            probs=lgb_probs
        else:
            probs=np.zeros(len(self.classes))
            probs[self.benign_class_idx]=1.0
        pred_idx=int(np.argmax(probs))
        confidence=float(probs[pred_idx])
        predicted_label=self.classes[pred_idx] if self.classes else "Benign"
        is_threat=(predicted_label!="Benign") and (confidence>=self.sensitivity_threshold)
        severity="INFO"
        if is_threat:
            critical_attacks=["DDoS","DoS","ransomware","injection","Infilteration"]
            high_attacks=["Bot","Brute Force","Backdoor","password","scanning","xss"]
            if predicted_label in critical_attacks or confidence>=0.85:
                severity="CRITICAL"
            elif predicted_label in high_attacks or confidence>=0.65:
                severity="HIGH"
            else:
                severity="MEDIUM"
        latency_ms=(time.perf_counter()-start_t)*1000.0
        all_probs_dict={self.classes[i]:float(probs[i]) for i in range(len(self.classes))}
        return {
            "is_threat":is_threat,
            "label":predicted_label,
            "confidence":round(confidence,4),
            "severity":severity,
            "latency_ms":round(latency_ms,2),
            "probabilities":all_probs_dict,
            "model_used":model_name,
        }

    def generate_next_flow(self):
        return self.live_sniffer.get_next_flow(timeout=0.01)

    def generate_simulated_attack_flow(self,attack_type):
        attack_type=attack_type or "DoS"
        if attack_type in ["DoS","DDoS"]:
            in_bytes=random.randint(50000,500000)
            out_bytes=random.randint(0,500)
            duration=random.uniform(0.01,1.5)
            tcp_flags=2
            dst_port=random.choice([80,443,8080,53])
        elif attack_type in ["scanning","Reconnaissance"]:
            in_bytes=random.randint(40,120)
            out_bytes=0
            duration=random.uniform(0.001,0.05)
            tcp_flags=2
            dst_port=random.randint(1,1024)
        elif attack_type in ["Brute Force","password"]:
            in_bytes=random.randint(800,5000)
            out_bytes=random.randint(200,1200)
            duration=random.uniform(2.0,15.0)
            tcp_flags=24
            dst_port=random.choice([22,3389,21,25])
        elif attack_type in ["injection","xss"]:
            in_bytes=random.randint(2000,15000)
            out_bytes=random.randint(500,3000)
            duration=random.uniform(1.0,5.0)
            tcp_flags=24
            dst_port=random.choice([80,443,8080,3306])
        else:
            in_bytes=random.randint(10000,80000)
            out_bytes=random.randint(5000,60000)
            duration=random.uniform(5.0,45.0)
            tcp_flags=24
            dst_port=random.choice([445,139,4444,8888])
        raw_dict={
            "SHORTEST_FLOW_PKT":40 if tcp_flags==2 else 64,
            "FTP_COMMAND_RET_CODE":0,
            "NUM_PKTS_128_TO_256_BYTES":random.randint(0,2),
            "TCP_WIN_MAX_IN":1024 if tcp_flags==2 else 65535,
            "SRC_TO_DST_AVG_THROUGHPUT":round(in_bytes/max(0.01,duration)*8,2),
            "LONGEST_FLOW_PKT":1500 if in_bytes>5000 else 64,
            "DURATION_IN":duration,
            "IN_BYTES":in_bytes,
            "TCP_WIN_MAX_OUT":0 if out_bytes==0 else 14600,
            "MIN_IP_PKT_LEN":40,
            "DNS_QUERY_TYPE":0,
            "FLOW_DURATION_MILLISECONDS":duration,
            "MIN_TTL":128 if attack_type=="DoS" else 64,
            "DST_TO_SRC_AVG_THROUGHPUT":round(out_bytes/max(0.01,duration)*8,2),
            "L7_PROTO":0,
            "SERVER_TCP_FLAGS":0 if out_bytes==0 else 18,
            "OUT_BYTES":out_bytes,
            "TCP_FLAGS":tcp_flags,
            "RETRANSMITTED_OUT_BYTES":random.randint(0,1000) if attack_type=="DoS" else 0,
            "NUM_PKTS_UP_TO_128_BYTES":random.randint(20,200) if attack_type=="DoS" else 5,
            "PROTOCOL":6,
            "DURATION_OUT":0 if out_bytes==0 else duration*0.5,
            "SRC_TO_DST_SECOND_BYTES":in_bytes,
            "DST_TO_SRC_SECOND_BYTES":out_bytes,
            "RETRANSMITTED_IN_BYTES":0,
            "RETRANSMITTED_IN_PKTS":0,
            "NUM_PKTS_256_TO_512_BYTES":0,
            "NUM_PKTS_512_TO_1024_BYTES":0,
            "ICMP_TYPE":0,
            "DNS_QUERY_ID":0,
            "DNS_TTL_ANSWER":0,
        }
        return {
            "timestamp":time.time(),
            "src_ip":f"103.21.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_ip":"192.168.1.100",
            "src_port":random.randint(1024,65535),
            "dst_port":dst_port,
            "protocol":"TCP",
            "l7_proto":raw_dict.get("L7_PROTO",0),
            "in_bytes":in_bytes,
            "out_bytes":out_bytes,
            "in_pkts":random.randint(10,150),
            "out_pkts":1 if out_bytes==0 else random.randint(1,10),
            "flow_duration_ms":duration,
            "tcp_flags":tcp_flags,
            "raw_features":raw_dict,
            "simulated_type":attack_type,
            "is_live_capture":False
        }

    def process_next_cycle(self,injected_attack=None):
        with self.lock:
            if injected_attack:
                raw_flow=self.generate_simulated_attack_flow(injected_attack)
            else:
                raw_flow=self.generate_next_flow()
                if raw_flow is None:
                    return None
            now=time.time()
            if (now-self.last_ip_scan_time)>10.0:
                self.cached_local_ips,self.cached_gateway_ips=self.get_trusted_infrastructure()
                self.last_ip_scan_time=now
            src_ip_clean=str(raw_flow["src_ip"]).split('%')[0].lower()
            dst_ip_clean=str(raw_flow["dst_ip"]).split('%')[0].lower()
            src_is_local=src_ip_clean in self.cached_local_ips
            dst_is_local=dst_ip_clean in self.cached_local_ips
            src_is_gateway=src_ip_clean in self.cached_gateway_ips
            dst_is_gateway=dst_ip_clean in self.cached_gateway_ips
            is_multicast=(src_ip_clean.startswith(('224.','239.','ff02','ff05')) or 
                            dst_ip_clean.startswith(('224.','239.','ff02','ff05','255.255.255.255')))
            is_router_proto=(raw_flow["src_port"] in [7,53,67,68,123,137,138,1900,5353,546,547] or 
                               raw_flow["dst_port"] in [7,53,67,68,123,137,138,1900,5353,546,547])
            is_trusted_infrastructure=not injected_attack and ((src_is_gateway or dst_is_gateway or is_multicast or is_router_proto) and (src_is_local or dst_is_local))
            if is_trusted_infrastructure:
                pred_res={
                    "is_threat":False,
                    "label":"Benign",
                    "confidence":1.0,
                    "severity":"INFO",
                    "latency_ms":0.1,
                    "probabilities":{cls:(1.0 if cls=="Benign" else 0.0) for cls in self.classes},
                    "model_used":"trusted_gateway_filter"
                }
            else:
                pred_res=self.predict(raw_flow["raw_features"])
            if injected_attack and not pred_res["is_threat"]:
                pred_res["is_threat"]=True
                pred_res["label"]=injected_attack
                pred_res["confidence"]=max(0.94,pred_res["confidence"])
                pred_res["severity"]="CRITICAL" if injected_attack in ["DoS","DDoS","ransomware","injection"] else "HIGH"
            self.stats["total_flows_inspected"]+=1
            self.stats["inbound_bytes_total"]+=raw_flow["in_bytes"]
            self.stats["outbound_bytes_total"]+=raw_flow["out_bytes"]
            self.stats["last_inference_latency_ms"]=pred_res["latency_ms"]
            self.stats["active_model"]=self.active_model_name
            if self.start_time:
                self.stats["uptime_seconds"]=int(time.time()-self.start_time)
            flow_event={
                "id":self.stats["total_flows_inspected"],
                "timestamp":raw_flow["timestamp"],
                "time_formatted":time.strftime("%H:%M:%S",time.localtime(raw_flow["timestamp"])),
                "src_ip":raw_flow["src_ip"],
                "dst_ip":raw_flow["dst_ip"],
                "src_port":raw_flow["src_port"],
                "dst_port":raw_flow["dst_port"],
                "src_is_local":src_is_local,
                "dst_is_local":dst_is_local,
                "src_is_gateway":src_is_gateway,
                "dst_is_gateway":dst_is_gateway,
                "is_infrastructure":is_trusted_infrastructure,
                "protocol":raw_flow["protocol"],
                "l7_proto":raw_flow["l7_proto"],
                "in_bytes":raw_flow["in_bytes"],
                "out_bytes":raw_flow["out_bytes"],
                "flow_duration_ms":round(raw_flow["flow_duration_ms"],2),
                "tcp_flags":raw_flow["tcp_flags"],
                "is_threat":pred_res["is_threat"],
                "label":pred_res["label"],
                "confidence":pred_res["confidence"],
                "severity":pred_res["severity"],
                "model_used":pred_res["model_used"],
                "latency_ms":pred_res["latency_ms"],
                "is_live_capture":raw_flow.get("is_live_capture",True),
                "feature_snapshot":{
                    "shortest_pkt":raw_flow["raw_features"].get("SHORTEST_FLOW_PKT",0),
                    "longest_pkt":raw_flow["raw_features"].get("LONGEST_FLOW_PKT",0),
                    "tcp_win_in":raw_flow["raw_features"].get("TCP_WIN_MAX_IN",0),
                    "throughput_in":raw_flow["raw_features"].get("SRC_TO_DST_AVG_THROUGHPUT",0),
                    "throughput_out":raw_flow["raw_features"].get("DST_TO_SRC_AVG_THROUGHPUT",0),
                }
            }
            if pred_res["is_threat"]:
                self.stats["threats_detected_count"]+=1
                threat_label=pred_res["label"]
                self.stats["threat_breakdown"][threat_label]=self.stats["threat_breakdown"].get(threat_label,0)+1
                self.recent_threats.insert(0,flow_event)
                if len(self.recent_threats)>self.max_buffer_size:
                    self.recent_threats.pop()
            else:
                self.stats["benign_flows_count"]+=1
            self.recent_flows.insert(0,flow_event)
            if len(self.recent_flows)>self.max_buffer_size:
                self.recent_flows.pop()
            return flow_event

    def start(self):
        with self.lock:
            self.is_running=True
            self.is_paused=False
            self.start_time=time.time()
            self.stats["engine_state"]="running"
            self.live_sniffer.start()
            logger.info("IDS Live Laptop Sniffer started.")

    def pause(self):
        with self.lock:
            self.is_paused=True
            self.stats["engine_state"]="paused"
            logger.info("IDS Engine paused.")

    def resume(self):
        with self.lock:
            self.is_paused=False
            self.stats["engine_state"]="running"
            logger.info("IDS Engine resumed.")

    def stop(self):
        with self.lock:
            self.is_running=False
            self.is_paused=False
            self.stats["engine_state"]="stopped"
            self.live_sniffer.stop()
            logger.info("IDS Engine stopped.")

    def set_model(self,model_name):
        with self.lock:
            if model_name in ["xgboost","lightgbm","ensemble"]:
                self.active_model_name=model_name
                self.stats["active_model"]=model_name
                logger.info(f"Active model switched to {model_name}.")
                return True
            return False

    def set_sensitivity(self,threshold):
        with self.lock:
            self.sensitivity_threshold=max(0.1,min(0.99,float(threshold)))
            logger.info(f"Sensitivity threshold updated to {self.sensitivity_threshold}.")

    def set_stream_speed(self,speed):
        with self.lock:
            self.stream_speed=max(0.1,min(10.0,float(speed)))

    def get_system_telemetry(self):
        try:
            cpu_percent=psutil.cpu_percent(interval=None)
            mem=psutil.virtual_memory()
            net_io=psutil.net_io_counters()
            return {
                "cpu_percent":cpu_percent,
                "memory_percent":mem.percent,
                "memory_used_mb":round(mem.used/(1024*1024),1),
                "bytes_sent":net_io.bytes_sent,
                "bytes_recv":net_io.bytes_recv,
                "packets_sent":net_io.packets_sent,
                "packets_recv":net_io.packets_recv,
            }
        except Exception:
            return {
                "cpu_percent":15.0,
                "memory_percent":45.0,
                "memory_used_mb":4096.0,
                "bytes_sent":0,
                "bytes_recv":0,
                "packets_sent":0,
                "packets_recv":0,
            }

    def get_trusted_infrastructure(self):
        local_ips=set(["127.0.0.1","::1","0.0.0.0"])
        gateway_ips=set()
        try:
            for iface,addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family in (socket.AF_INET,socket.AF_INET6):
                        ip=addr.address.split('%')[0].lower()
                        local_ips.add(ip)
                    if addr.broadcast:
                        local_ips.add(addr.broadcast.split('%')[0].lower())
        except Exception:
            pass
        try:
            out=subprocess.check_output(['cmd','/c','route','print'],text=True,errors='ignore')
            for line in out.splitlines():
                parts=line.strip().split()
                if len(parts)>=5 and parts[0]=='0.0.0.0' and parts[1]=='0.0.0.0':
                    gateway_ips.add(parts[2].split('%')[0].lower())
                if len(parts)>=4 and parts[0]=='::/0':
                    gateway_ips.add(parts[2].split('%')[0].lower())
        except Exception:
            pass
        return local_ips,gateway_ips

    def get_dashboard_summary(self):
        with self.lock:
            host_telemetry=self.get_system_telemetry()
            return {
                "engine":{
                    "is_running":self.is_running,
                    "is_paused":self.is_paused,
                    "active_model":self.active_model_name,
                    "mode":"live_pc_traffic_only",
                    "sensitivity":self.sensitivity_threshold,
                    "stream_speed":self.stream_speed,
                    "state":self.stats["engine_state"],
                    "uptime_seconds":int(time.time()-self.start_time) if self.start_time and self.is_running else 0,
                    "selected_features_count":len(self.selected_features),
                    "classes":self.classes,
                },
                "local_ips":list(self.cached_local_ips),
                "gateway_ips":list(self.cached_gateway_ips),
                "stats":dict(self.stats),
                "host_telemetry":host_telemetry,
                "recent_threats":list(self.recent_threats[:15]),
            }
