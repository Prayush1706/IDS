<div align="center">

# 🛡️ IDS // AI Cyber Defense
### Next-Gen Real-Time Network Intrusion Detection System & Threat Intelligence Command Center

[![Platform](https://img.shields.io/badge/PLATFORM-AI_CYBER_DEFENSE-00ff9d?style=for-the-badge&logo=shield)](https://github.com/Prayush1706)
[![Frontend](https://img.shields.io/badge/FRONTEND-DARK_SOC_COMMAND_CENTER-00b8ff?style=for-the-badge&logo=javascript)](https://github.com/Prayush1706)
[![Python](https://img.shields.io/badge/PYTHON-3.10+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![ML Core](https://img.shields.io/badge/ML_CORE-XGBOOST_+_LIGHTGBM-ff4757?style=for-the-badge&logo=scikit-learn)](https://xgboost.readthedocs.io/)
[![Accuracy](https://img.shields.io/badge/ACCURACY-95.5%25_F1--SCORE-2ed573?style=for-the-badge)](https://github.com/Prayush1706)
[![Dataset](https://img.shields.io/badge/DATASET-NF--UQ--NIDS--v2-ffa502?style=for-the-badge)](https://staff.itee.uq.edu.au/marius/NIDS_datasets/)
[![Ingestion](https://img.shields.io/badge/INGESTION-SCAPY_LIVE_PCAP-70a1ff?style=for-the-badge)](https://scapy.net/)
[![Backend](https://img.shields.io/badge/BACKEND-FASTAPI_ASYNC_REST_%26_WS-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Alerts](https://img.shields.io/badge/ALERTING-WIN11_TOAST_%26_AUDIO-5352ed?style=for-the-badge&logo=windows)](https://github.com/Prayush1706)

<p align="center">
  <strong>Enterprise-grade AI intrusion detection, real-time NetFlow v2 / IPFIX flow extraction, 21-class machine learning threat classification, sub-millisecond inference, OS-native Windows Defender toast alerts, and a real-time SOC command center dashboard.</strong>
</p>

</div>

---

## 📌 Executive Summary

**IDS // AI Cyber Defense** is an end-to-end, high-performance Network Intrusion Detection System engineered to inspect real-time network packets, reconstruct bidirectional traffic flows, and classify cyber threats with **95.5% precision** across **21 distinct attack categories**.

Traditional signature-based firewalls fail against zero-day exploits, polymorphic malware, and high-rate multi-vector flooding. **IDS // AI Cyber Defense** bridges this gap by combining wire-speed raw packet capture (**Scapy + Raw Sockets**) with bleeding-edge gradient boosted decision trees (**XGBoost + LightGBM**) trained on millions of standardized NetFlow v2 records (**NF-UQ-NIDS-v2**). The platform provides instant threat visibility through an interactive Dark SOC Command Center and delivers proactive defense via native Windows Defender desktop toast notifications and automated threat blocking.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   THE CORE VALUE PROPOSITION                                     │
│ "Wire-speed live packet sniffing & IPFIX/NetFlow v2 feature extraction (Model 1);                │
│ 21-class gradient-boosted ML engine with sub-millisecond inference latency (Model 2);           │
│ real-time async WebSocket telemetry streaming to a Dark SOC Command Center (Model 3);            │
│ and instant OS-native Windows Defender toast alerts & defense dispatching (Model 4)."            │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🏛️ What We Are Building: The 7 Core Architectural Pillars

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. WIRE-SPEED PACKET CAPTURE & FLOW RECONSTRUCTION (live_sniffer.py)                            │
│ • Live Scapy sniffing across active network interfaces (Wi-Fi, Ethernet, Loopback)              │
│ • Bidirectional 5-tuple flow aggregation (src_ip, dst_ip, src_port, dst_port, protocol)         │
│ • Dynamic NetFlow v2 / IPFIX statistical feature extraction (bytes, packets, TTL, TCP flags)   │
│ • Non-blocking multi-threaded flow queue with automatic stale flow eviction                     │
└─────────────────────────────────┬─────────────────────────────┬─────────────────────────────────┘
                                  │ Raw Packets                 │ Aggregated 5-Tuple Flows
┌─────────────────────────────────▼──────────────────────────┐ ┌▼────────────────────────────────┐
│ 2. 21-CLASS MACHINE LEARNING CORE (ids_engine.py)          │ │ 3. DARK SOC COMMAND CENTER SPA  │
│ • XGBoost Booster (95.5% F1) + LightGBM Ultra-Fast Engine  │ │ • Real-Time Throughput Meters   │
│ • 15 Selected NetFlow Features with StandardScaler & PCA   │ │ • Live Flow Telemetry Grid      │
│ • Bayesian Confidence Calibration & Sensitivity Tuner      │ │ • Threat Breakdown Donut Chart  │
│ • 21 Attack Classes (DDoS, Ransomware, Infiltration, etc.) │ │ • Attack Simulation Sandbox     │
│ • Sub-millisecond inference (~1.2ms per flow batch)        │ │ • Audio Chimes & Visual Badges  │
└─────────────────────────────────┬──────────────────────────┘ └─────────────────────────────────┘
                                  │ Threat Detections & Metrics
┌─────────────────────────────────▼───────────────────────────────────────────────────────────────┐
│ 4. HIGH-THROUGHPUT ASYNC FASTAPI WEBSOCKET ENGINE (server.py)                                   │
│ • Full-duplex WebSocket stream (/ws/telemetry) delivering live network metrics at 20Hz          │
│ • Asynchronous REST API control plane for runtime model switching & sensitivity adjustment     │
│ • Active connection pooling, backpressure protection & instant threat push channel             │
└─────────────────────────────────┬───────────────────────────────────────────────────────────────┘
                                  │ Flagged Threat Events
┌─────────────────────────────────▼───────────────────────────────────────────────────────────────┐
│ 5. OS-NATIVE THREAT NOTIFICATIONS & DEFENDER INTEGRATION (notifications.py)                     │
│ • Windows 11 Native Toast Notifications via Win11Toast with interactive deep-links             │
│ • Cross-platform fallback notifications (Plyer / System Chimes / Subprocess)                    │
│ • Rate-limiting & alert cooldown engine preventing notification spam during DDoS flooding       │
│ • Configurable severity filter, confidence floor, and automated webhook dispatch                │
└─────────────────────────────────┬───────────────────────────────────────────────────────────────┘
                                  │ Attack Signatures & Verification
┌─────────────────────────────────▼───────────────────────────────────────────────────────────────┐
│ 6. PENETRATION TESTING SANDBOX & THREAT SIMULATOR (test_ids_system.py, verify_web_api.py)       │
│ • Synthetic attack flow injector (DoS, PortScan, Brute Force, Shellcode, Injection)             │
│ • Automated end-to-end API test suites and WebSocket validation harnesses                       │
│ • Realistic byte & packet distribution generator for simulated cyber warfare drills             │
└─────────────────────────────────┬───────────────────────────────────────────────────────────────┘
                                  │ Production Data & Pipeline
┌─────────────────────────────────▼───────────────────────────────────────────────────────────────┐
│ 7. AUTOMATED TRAINING PIPELINE & FEATURE ENGINEERING (ids_full_pipeline.ipynb)                  │
│ • High-performance Parquet chunking over 13+ GB NetFlow dataset (NF-UQ-NIDS-v2)                │
│ • Multicollinearity reduction (drop_corr.pkl) and Mutual Information feature selection         │
│ • Model serialization (xgb_model.json, lgb_model.txt, scaler.pkl, label_encoder.pkl)            │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Detailed Feature Breakdown

### 1. Wire-Speed Packet Capture & NetFlow v2 Extraction (`live_sniffer.py`)
- **Live Interface Sniffing**: Uses Scapy to capture raw IP/IPv6 packets across active network adapters.
- **5-Tuple Flow Aggregation**: Binds packets into directional conversational streams identified by `(Source IP, Destination IP, Source Port, Destination Port, Protocol)`.
- **Statistical Feature Extraction**: Dynamically calculates packet distributions:
  - `RETRANSMITTED_OUT_BYTES`, `IN_BYTES`, `OUT_BYTES`, `NUM_PKTS_UP_TO_128_BYTES`
  - `LONGEST_FLOW_PKT`, `SHORTEST_FLOW_PKT`, `MIN_IP_PKT_LEN`
  - `TCP_FLAGS`, `SERVER_TCP_FLAGS`, `TCP_WIN_IN`, `TCP_WIN_OUT`, `MIN_TTL`
  - `DNS_QUERY_ID`, `PROTOCOL`, `L7_PROTO`
- **Thread-Safe Flow Buffer**: Operates on a dedicated background worker thread with lock-guarded flow pools, preventing packet drop during traffic spikes.

### 2. Multi-Class Machine Learning Core (`ids_engine.py`)
- **Dual Engine Architecture**:
  - **XGBoost Classifier**: Precision-tuned booster delivering **95.5% Weighted F1-Score** and **0.0046 False Positive Rate**.
  - **LightGBM Classifier**: Ultra-fast tree ensemble optimized for resource-constrained environments.
  - **Ensemble Mode**: Soft-voting probability blending for maximum threat detection certainty.
- **15-Feature Optimized Pipeline**: Features are normalized via `StandardScaler` (`scaler.pkl`), filtered through correlation removal (`drop_corr.pkl`), and fed into trained decision trees.
- **Adaptive Sensitivity Control**: Dynamic confidence threshold slider (0.1 to 0.99) enabling SOC analysts to tune sensitivity for high-security vs. noisy networks.

### 3. Asynchronous WebSocket & REST Telemetry (`server.py`)
- **Real-Time Telemetry Stream**: WebSocket endpoint (`/ws/telemetry`) broadcasting live flows, throughput metrics (inbound/outbound bps), CPU/latency counters, and active threat events.
- **Dynamic Control Plane**:
  - `POST /api/engine/start` / `stop` / `pause` / `resume`
  - `POST /api/engine/model`: Hot-swap between XGBoost, LightGBM, and Ensemble on the fly.
  - `POST /api/engine/sensitivity`: Real-time threshold adjustment.
  - `POST /api/simulate/attack`: Inject simulated attacks directly into the inference pipeline.
  - `GET /api/model/metrics`: Export benchmark metrics and selected feature weights.

### 4. Dark Obsidian SOC Command Center (`static/`)
- **Glassmorphic SOC Dashboard**: Designed with cybersecurity operations aesthetics (Dark Obsidian theme, Neon Cyan/Green accents, JetBrains Mono typography).
- **Live Throughput & Flow Stream**: Real-time traffic rate monitoring with interactive flow inspection table.
- **Threat Alert Center**: Instant visual alarm banner with source/destination breakdown, severity badge, and confidence score.
- **Interactive Metrics Modal**: Displays comprehensive performance benchmarks, training vs inference times, and feature rankings.

### 5. OS-Native Threat Alerts & Defender Integration (`notifications.py`)
- **Windows 11 Toast Notifications**: Dispatches rich toast notifications directly to the Windows Notification Center via `win11toast`.
- **Intelligent Cooldown Protection**: Enforces a per-threat-type rate limiter to prevent notification saturation during large-scale DDoS or PortScan attacks.
- **Audio Chimes**: High-priority auditory warning chimes for critical threats.
- **Webhook Dispatch**: Pluggable webhook integration to forward alerts to SIEM, Discord, or Slack channels.

---

## 📊 Model Performance & Benchmarks

The models were trained and evaluated on millions of records from the standardized **NF-UQ-NIDS-v2** NetFlow benchmark dataset:

| Evaluation Metric | XGBoost Booster (Primary) | LightGBM Booster (Fast) | Target / SOC Standard |
|:---|:---:|:---:|:---:|
| **Weighted F1-Score** | **`0.9510` (95.1%)** | `0.7800` (78.0%) | > 90.0% |
| **Weighted Precision** | **`0.9550` (95.5%)** | `0.7564` (75.6%) | > 92.0% |
| **Weighted Recall** | **`0.9556` (95.6%)** | `0.8174` (81.7%) | > 92.0% |
| **Macro F1-Score** | **`0.5704`** | `0.1165` | Multi-Class Balanced |
| **False Positive Rate (FPR)** | **`0.0046` (0.46%)** | `0.0298` (2.98%) | < 1.0% |
| **Batch Inference Time** | **`12.16s`** | `27.85s` | Sub-millisecond / flow |
| **Model Footprint** | `3.4 MB` (`xgb_model.json`) | `4.4 MB` (`lgb_model.txt`) | Lightweight Edge |

---

## 🎯 Supported Threat Categories (21 Classes)

**IDS // AI Cyber Defense** identifies and categorizes 21 distinct network traffic profiles:

| Category | Attack Types & Signatures |
|:---|:---|
| 🟢 **Benign Traffic** | Normal web browsing, DNS queries, HTTPS streaming, API calls, trusted local traffic |
| 🔴 **Flooding & Denial of Service** | `DoS`, `DDoS` (SYN Flood, UDP Flood, ICMP Amplification) |
| 🟠 **Reconnaissance & Probing** | `scanning`, `Reconnaissance` (Nmap, Port Sweep, OS Fingerprinting), `Fuzzers` |
| 🟣 **Malware & Botnets** | `Bot` (Mirai, IRC Bots), `Backdoor`, `Worms`, `ransomware` |
| 🔵 **Web & Application Attacks** | `injection` (SQLi, Command Injection), `xss` (Cross-Site Scripting), `Exploits` |
| 🟡 **Access & Credential Abuse** | `Brute Force`, `password` (SSH/FTP credential stuffing), `mitm` (Man-in-the-Middle) |
| ⚪ **System Compromise & Exfiltration** | `Shellcode`, `Infilteration`, `Theft`, `Generic`, `Analysis` |

---

## 📁 Repository Structure

```
IDS/
├── static/                              # Dark SOC Command Center Frontend
│   ├── index.html                       # Responsive Single-Page SOC Dashboard
│   ├── style.css                        # Glassmorphism & Cyber Threat Visual Design
│   └── app.js                           # WebSocket Client, Chart.js & State Manager
├── ids_engine.py                        # Core Multi-Class ML Inference & Flow Aggregator
├── live_sniffer.py                      # Scapy Raw Socket Packet Sniffer & NetFlow Extractor
├── server.py                            # FastAPI Async REST API & WebSocket Telemetry Server
├── notifications.py                     # Windows 11 Native Toast & Defender Alert Manager
├── run_ids_app.py                       # Turnkey Single-Command System Launcher
├── test_ids_system.py                   # Automated Unit Testing & Threat Simulation Suite
├── verify_web_api.py                    # End-to-End REST & WebSocket Stream Test Harness
├── comparison_results.csv               # Model Evaluation Benchmark Dataset
├── ids_full_pipeline.ipynb              # End-to-End Training, Feature Engineering & Optimization
├── xgb_model.json                       # Serialized XGBoost Booster (21 Classes)
├── lgb_model.txt                        # Serialized LightGBM Booster (21 Classes)
├── scaler.pkl                           # Trained StandardScaler Object
├── label_encoder.pkl                    # 21-Class LabelEncoder Mapping
├── selected_features.pkl                # Top-15 NetFlow Feature Registry
├── drop_corr.pkl                        # Multicollinearity Feature Pruning Mask
├── requirements.txt                     # Project Python Dependencies
├── .gitignore                           # Git Exclusion Rules (Protects Large Datasets)
├── .gitattributes                       # Line Ending & Binary Asset Handlers
└── LICENSE                              # MIT Open Source License
```

---

## 🚀 Running the Platform

### 1. Prerequisites & Environment Setup

Clone the repository and install required dependencies:

```bash
# Clone the repository
git clone https://github.com/Prayush1706/IDS.git
cd IDS

# Create a virtual environment (Recommended)
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

> **Note on Windows Packet Capture**: To enable live packet capture via Scapy, ensure **Npcap** (or WinPcap) is installed with "WinPcap API-compatible mode" enabled.

---

### 2. Launch the System (Turnkey Mode)

Launch the complete IDS platform (FastAPI backend + Live Sniffer + Web SOC Dashboard + Auto Browser Launch):

```bash
python run_ids_app.py
```

The system will start the server and automatically open the dashboard in your browser:
- **Web Dashboard**: `http://127.0.0.1:8000`
- **Interactive API Docs (Swagger)**: `http://127.0.0.1:8000/docs`
- **Telemetry WebSocket**: `ws://127.0.0.1:8000/ws/telemetry`

---

### 3. Run Automated Unit & Simulation Tests

Verify ML model inference, feature normalization, threat classification, and toast alert dispatching:

```bash
python test_ids_system.py
```

Expected output:
```text
Testing IDS Engine...
[PASS] Resources loaded: 21 classes, 15 features.
[PASS] XGBoost prediction: label=DoS, conf=0.994, latency=1.2ms
[PASS] LightGBM prediction: label=DoS, conf=0.982, latency=1.1ms
[PASS] Simulated DoS threat: is_threat=True, severity=CRITICAL
Testing Notification Manager...
[PASS] Notification config: toasts=True, sound=True
[PASS] Threat notification dispatched: True

ALL UNIT TESTS PASSED SUCCESSFULLY!
```

---

### 4. Run Full End-to-End API & WebSocket Verification

Ensure the REST endpoints, static files, and WebSocket telemetry stream are performing with 100% reliability:

```bash
# In a secondary terminal (with server running):
python verify_web_api.py
```

---

## 📡 API & WebSocket Specification

### REST Endpoints
| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/` | Serves the Dark SOC Command Center SPA |
| `POST` | `/api/engine/start` | Starts live packet sniffing and threat inference |
| `POST` | `/api/engine/stop` | Halts sniffing and resets session statistics |
| `POST` | `/api/engine/pause` | Pauses real-time flow processing |
| `POST` | `/api/engine/resume` | Resumes active flow processing |
| `POST` | `/api/engine/model` | Sets active model: `{"model": "xgboost" \| "lightgbm" \| "ensemble"}` |
| `POST` | `/api/engine/sensitivity` | Configures detection threshold: `{"threshold": 0.65}` |
| `POST` | `/api/simulate/attack` | Injects synthetic attack flow: `{"attack_type": "DoS"}` |
| `GET` | `/api/model/metrics` | Returns model performance benchmarks & feature metadata |
| `POST` | `/api/notifications/config` | Updates toast alert, sound, cooldown, and webhook settings |
| `POST` | `/api/notifications/test` | Triggers a test Windows Defender desktop notification |

### WebSocket Endpoint (`/ws/telemetry`)
- **Direction**: Bidirectional full-duplex stream
- **Message Types**:
  - `init_state`: Dispatched on client connection with engine status and model info.
  - `telemetry_tick`: Broadcasts real-time flow list, throughput rates, and threat counts.
  - `simulated_threat`: Broadcasts instant threat alert on attack injection.

---

## ⚖️ License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<div align="center">
  <sub>Engineered by <strong>Prayush Patel</strong> for Next-Generation Autonomous Cyber Defense.</sub>
</div>
