<p align="center">
  <h1 align="center">🛡️ SmartGrid FDIA Shield</h1>
  <p align="center">
    <strong>IoT-Based False Data Injection Attack Detection, IP Spoofing Simulation & Data Recovery for Smart Grid Energy Monitoring</strong>
  </p>
  <p align="center">
    <a href="#-architecture">Architecture</a> •
    <a href="#-hardware-requirements">Hardware</a> •
    <a href="#-installation">Installation</a> •
    <a href="#-usage">Usage</a> •
    <a href="#-attack-scenarios">Attacks</a> •
    <a href="#-results">Results</a>
  </p>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Hardware Requirements](#-hardware-requirements)
- [Network Topology](#-network-topology)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
  - [Step 1 — Hardware Wiring](#step-1--hardware-wiring)
  - [Step 2 — ESP32 Firmware](#step-2--esp32-firmware)
  - [Step 3 — Raspberry Pi Setup](#step-3--raspberry-pi-setup)
  - [Step 4 — Attacker Machine Setup](#step-4--attacker-machine-setup)
- [Configuration](#-configuration)
- [Usage](#-usage)
  - [Starting the Gateway](#starting-the-gateway)
  - [Running Tests](#running-tests)
  - [Generating Plots](#generating-plots)
- [Attack Scenarios](#-attack-scenarios)
- [Detection Methods](#-detection-methods)
- [Data Recovery Strategies](#-data-recovery-strategies)
- [Results & Visualization](#-results--visualization)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)
- [Authors](#-authors)

---

## 🔍 Overview

This project implements a complete end-to-end testbed for detecting and recovering from **False Data Injection (FDI) attacks** and **IP Spoofing attacks** targeting IoT-based smart grid energy monitoring systems.

A real ESP32 sensor node reads AC power measurements via the PZEM-004T energy module and publishes them over MQTT to a Raspberry Pi edge gateway. The gateway runs a **5-signal fusion detection engine** that combines physics-based validation, statistical analysis, machine learning (Isolation Forest), HMAC-SHA256 cryptographic verification, and TCP/IP network fingerprinting to detect attacks in real time. When an attack is detected, three recovery strategies (temporal interpolation, physics reconstruction, and Kalman filtering) reconstruct the corrupted data.

An attacker machine simulates IP spoofing, replay attacks, and firmware-level data injection using Python Scapy — all on an isolated lab network.

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHYSICAL LAYER                                      │
│  [AC Mains 230V] ──→ [AC Load 60W] ──→ [PZEM-004T CT Clamp]              │
│                                               │ UART 9600 baud             │
│                                        [ESP32 (192.168.1.101)]             │
│                                               │                            │
│                             Wi-Fi 802.11b/g/n │ MQTT PUBLISH               │
│                                               │ smartgrid/node01/telemetry │
└───────────────────────────────────────────────┼────────────────────────────┘
                                                │
┌───────────────────────────────────────────────▼────────────────────────────┐
│                     NETWORK LAYER (Attack Surface)                         │
│                                                                            │
│  NORMAL:   ESP32 (real IP) ──TCP:1883──→ Raspberry Pi MQTT Broker         │
│  SPOOFED:  Attacker ──→ forged src IP = 192.168.1.101 ──→ Broker          │
└───────────────────────────────────────────────┬────────────────────────────┘
                                                │
┌───────────────────────────────────────────────▼────────────────────────────┐
│              EDGE COMPUTING (Raspberry Pi 192.168.1.100)                   │
│                                                                            │
│  Mosquitto ──→ mqtt_subscriber.py ──→ hmac_verifier.py                    │
│                                    ──→ network_fingerprint.py              │
│                                    ──→ fdi_detector.py (5-signal fusion)   │
│                                    ──→ data_recovery.py (3 strategies)     │
│                                    ──→ db_manager.py (SQLite)              │
│                                    ──→ cloud_uploader.py (ThingSpeak)      │
│                                    ──→ alert_publisher.py                  │
└───────────────────────────────────────────────┬────────────────────────────┘
                                                │ HTTPS
                                     [ThingSpeak / Grafana Cloud]
```

### Detection Fusion Formula

```
ATTACK_CONFIDENCE = 0.25 × physics_score
                  + 0.20 × z_score_normalized
                  + 0.20 × isolation_forest_score
                  + 0.25 × hmac_score
                  + 0.10 × fingerprint_score
```

---

## 🔧 Hardware Requirements

| Component | Model | Quantity | Purpose |
|-----------|-------|----------|---------|
| Microcontroller | ESP32 WROOM-32 DevKit | 1 | Sensor node — reads energy data, publishes MQTT |
| Energy Module | PZEM-004T v3.0 | 1 | Measures V, I, P, E, Hz, PF via CT clamp |
| Edge Gateway | Raspberry Pi 4 Model B (4GB) | 1 | MQTT broker + detection engine |
| Attacker Machine | Any Linux laptop/PC (Ubuntu 22.04) | 1 | Runs IP spoofing & replay attack scripts |
| AC Test Load | 60W incandescent bulb or resistive heater | 1 | Provides measurable AC load |
| Power Supply | 5V USB (for ESP32) | 1 | Powers the ESP32 board |
| Misc | Breadboard, jumper wires, USB-TTL adapter | — | Prototyping & debugging |

---

## 🌐 Network Topology

All devices must be on the **same local network** (192.168.1.0/24):

| Device | Static IP | Role |
|--------|-----------|------|
| ESP32 Node | `192.168.1.101` | Legitimate sensor node (MQTT publisher) |
| Raspberry Pi | `192.168.1.100` | MQTT broker + edge detection gateway |
| Attacker Laptop | `192.168.1.200` | Runs IP spoofing & replay attacks |
| Home Router | `192.168.1.1` | Network gateway |

---

## 📁 Project Structure

```
Smartgrid-FDIA-Shield/
│
├── esp32/
│   └── smartgrid_node/
│       └── smartgrid_node.ino        # ESP32 firmware (PZEM + MQTT + HMAC)
│
├── raspberry_pi/
│   ├── main.py                       # Master orchestrator
│   ├── config.py                     # Central configuration (.env loader)
│   ├── setup.sh                      # One-command Raspberry Pi setup
│   ├── requirements.txt              # Python dependencies
│   ├── mqtt_subscriber.py            # MQTT client + HMAC hook + IP tracking
│   ├── hmac_verifier.py              # HMAC-SHA256 payload verification
│   ├── network_fingerprint.py        # Scapy-based TCP/IP fingerprinting
│   ├── fdi_detector.py               # 5-signal fusion detection engine
│   ├── data_recovery.py              # 3-strategy data recovery (Kalman/Physics/Interp)
│   ├── db_manager.py                 # SQLite database manager (6 tables)
│   ├── cloud_uploader.py             # ThingSpeak IoT cloud uploader
│   ├── alert_publisher.py            # MQTT alert back-channel
│   ├── test_runner.py                # Automated 6-scenario test orchestrator
│   └── analysis.py                   # 10 publication-quality plots + metrics
│
├── attacker/
│   ├── attack_ip_spoof.py            # Scapy IP spoofing (forged source IP)
│   ├── attack_replay.py              # Packet capture + replay attack
│   ├── attack_controller.py          # CLI menu for all attack types
│   └── requirements_attacker.txt     # Attacker machine dependencies
│
├── docs/
│   └── hardware_setup.md             # Wiring diagrams, assembly, troubleshooting
│
├── LICENSE
└── README.md
```

---

## 🚀 Installation

### Step 1 — Hardware Wiring

> ⚠️ **AC mains (230V) is LETHAL.** Wire the DC logic side first. Have a qualified person handle AC connections. Never touch AC wires while powered.

**PZEM-004T ↔ ESP32 Wiring (DC Logic Side):**

| PZEM-004T Pin | ESP32 Pin | Wire Color | Notes |
|---------------|-----------|------------|-------|
| 5V | VIN (5V) | Red | Power supply for PZEM |
| GND | GND | Black | Common ground |
| TX | GPIO16 (RX2) | Yellow | PZEM TX → ESP32 RX (cross-connect) |
| RX | GPIO17 (TX2) | Green | ESP32 TX → PZEM RX (cross-connect) |

**AC Side:**
- Pass the **LIVE wire only** through the CT clamp ring
- Connect Neutral to the screw terminal
- The CT clamp snaps around the Live conductor

**Verification:**
```bash
# Test PZEM-004T with a USB-TTL adapter at 9600 baud
# On PuTTY/minicom, send Modbus request: 01 04 00 00 00 0A 70 0D
# You should get a 25-byte response with voltage/current readings
```

For detailed wiring diagrams and step-by-step assembly, see [`docs/hardware_setup.md`](docs/hardware_setup.md).

---

### Step 2 — ESP32 Firmware

**Prerequisites:**
- [Arduino IDE 2.x](https://www.arduino.cc/en/software) installed
- ESP32 Board Package installed (Tools → Board Manager → search "esp32")

**Install Required Libraries** (Sketch → Include Library → Manage Libraries):
- `PubSubClient` by Nick O'Leary
- `ArduinoJson` by Benoit Blanchon (v6)
- `NTPClient` by Fabrice Weinberg

**Configure & Flash:**

1. Open `esp32/smartgrid_node/smartgrid_node.ino` in Arduino IDE

2. Edit the configuration section at the top of the file:
   ```cpp
   const char* WIFI_SSID = "YOUR_WIFI_SSID";      // ← Your Wi-Fi network name
   const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";   // ← Your Wi-Fi password
   const char* MQTT_SERVER = "192.168.1.100";      // ← Raspberry Pi IP
   ```

3. Select board: **Tools → Board → ESP32 Dev Module**

4. Select port: **Tools → Port → COMx** (your ESP32's USB port)

5. Click **Upload** (→ button)

6. Open **Serial Monitor** (115200 baud) to verify:
   ```
   [node_01] WiFi connected: 192.168.1.101
   [node_01] MQTT connected to 192.168.1.100:1883
   [node_01][12:34:56] V=230.1 I=0.261 P=60.0 PF=0.99 | MQTT OK | HMAC=a3f2...
   ```

---

### Step 3 — Raspberry Pi Setup

**Prerequisites:**
- Raspberry Pi 4 running **Raspberry Pi OS (64-bit, Bookworm)**
- Connected to the same network as ESP32
- SSH access enabled

**One-Command Setup:**

```bash
# SSH into your Raspberry Pi
ssh pi@192.168.1.100

# Clone the repository
git clone https://github.com/Hackyharish/Smartgrid-FDIA-Shield.git
cd Smartgrid-FDIA-Shield/raspberry_pi

# Run the setup script (installs everything)
sudo chmod +x setup.sh
sudo ./setup.sh
```

**What `setup.sh` does automatically:**
1. ✅ Updates system packages
2. ✅ Installs Mosquitto MQTT broker + configures it on port 1883
3. ✅ Installs Python 3, pip, venv, SQLite, tcpdump, net-tools
4. ✅ Creates project directory structure (`data/`, `logs/`, `models/`, `results/`)
5. ✅ Creates Python virtual environment and installs all dependencies
6. ✅ Sets up systemd service for auto-start on boot
7. ✅ Configures static IP (192.168.1.100)

**Create the `.env` file:**
```bash
cd /home/pi/smartgrid   # or wherever you cloned the repo's raspberry_pi folder
nano .env
```

Add the following:
```env
THINGSPEAK_WRITE_KEY=YOUR_THINGSPEAK_API_KEY
HMAC_SECRET_KEY=smartgrid_secret_key_2025
MQTT_BROKER_IP=192.168.1.100
MQTT_PORT=1883
EXPECTED_NODE_IP=192.168.1.101
NODE_ID=node_01
```

**Verify Mosquitto is running:**
```bash
sudo systemctl status mosquitto

# Test by subscribing to all topics
mosquitto_sub -h 192.168.1.100 -t '#' -v
# You should see ESP32 messages arriving every 5 seconds
```

**Verify network connectivity:**
```bash
ping 192.168.1.101   # ESP32 should respond
ping 192.168.1.1     # Router should respond
```

---

### Step 4 — Attacker Machine Setup

> ⚠️ **These scripts are for academic research on YOUR OWN isolated lab network ONLY.** IP spoofing on public networks is illegal.

**Prerequisites:**
- Ubuntu 22.04 (or any Linux with raw socket support)
- Connected to the same LAN (192.168.1.0/24)
- Static IP: `192.168.1.200`

```bash
# Clone the repo on the attacker machine
git clone https://github.com/Hackyharish/Smartgrid-FDIA-Shield.git
cd Smartgrid-FDIA-Shield/attacker

# Install dependencies
pip install -r requirements_attacker.txt

# Set static IP
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.1.200/24
sudo nmcli con mod "Wired connection 1" ipv4.gateway 192.168.1.1
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"

# Verify
ping 192.168.1.100   # Pi should respond
ping 192.168.1.101   # ESP32 should respond
```

---

## ⚙ Configuration

All configuration is centralized in `raspberry_pi/config.py` which loads from the `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `MQTT_BROKER_IP` | `192.168.1.100` | Raspberry Pi MQTT broker address |
| `MQTT_PORT` | `1883` | MQTT broker port |
| `EXPECTED_NODE_IP` | `192.168.1.101` | Legitimate ESP32 node IP |
| `HMAC_SECRET_KEY` | `smartgrid_secret_key_2025` | Shared HMAC signing key |
| `THINGSPEAK_WRITE_KEY` | (empty) | ThingSpeak API key for cloud dashboard |
| `NODE_ID` | `node_01` | Sensor node identifier |

**Detection thresholds** (in `config.py`):

| Parameter | Value | Description |
|-----------|-------|-------------|
| `ATTACK_CONFIDENCE_THRESHOLD` | `0.6` | Above this → `ATTACK_DETECTED` |
| `SUSPICIOUS_THRESHOLD` | `0.35` | Above this → `SUSPICIOUS` |
| `ROLLING_WINDOW_SIZE` | `20` | Samples for Z-score computation |
| `Z_SCORE_THRESHOLD` | `3.0` | Z-score anomaly threshold |

---

## 🖥 Usage

### Starting the Gateway

```bash
# SSH into Raspberry Pi
ssh pi@192.168.1.100

# Activate the virtual environment
cd Smartgrid-FDIA-Shield/raspberry_pi
source venv/bin/activate   # if using local venv

# Run the detection gateway
sudo python3 main.py
```

> **Note:** `sudo` is required because the network fingerprint module uses Scapy for raw packet sniffing (needs `CAP_NET_RAW`).

You should see:
```
╔══════════════════════════════════════════════════╗
║  SmartGrid FDI + IP Spoof Detection Gateway      ║
║  Node: node_01 | Broker: 192.168.1.100:1883      ║
║  Expected ESP32 IP: 192.168.1.101                ║
╚══════════════════════════════════════════════════╝
ALL CHECKS PASSED ✓
[12:34:51][node_01] V=230.1 I=0.261 P=60.0 | NORMAL
[12:34:56][node_01] V=230.2 I=0.260 P=59.8 | NORMAL
```

**Or run as a systemd service (auto-starts on boot):**
```bash
sudo systemctl enable smartgrid
sudo systemctl start smartgrid
sudo journalctl -u smartgrid -f   # Follow logs
```

---

### Running Tests

The automated test runner orchestrates all 6 attack scenarios sequentially:

```bash
# Run ALL 6 scenarios (takes ~10 minutes with defaults)
sudo python3 test_runner.py

# Customize durations
sudo python3 test_runner.py --baseline 300 --attack 60 --gap 30

# Run a single scenario
sudo python3 test_runner.py --scenario 2    # FDI voltage spike only
sudo python3 test_runner.py --scenario 4    # IP spoofing only

# Specify attacker machine IP
sudo python3 test_runner.py --attacker 192.168.1.200
```

---

### Generating Plots

After running tests, generate all 10 publication-quality plots:

```bash
sudo python3 analysis.py

# Analyze data from a specific time window
sudo python3 analysis.py --since 1693000000

# Custom output directory
sudo python3 analysis.py --output ./my_plots
```

Plots are saved to `raspberry_pi/results/`:
- `plot_01_vip_timeseries.png` — Voltage, current, power time-series
- `plot_02_confidence_timeline.png` — Attack confidence with thresholds
- `plot_03_roc_curve.png` — ROC curve with AUC
- `plot_04_recovery_accuracy.png` — Recovery vs original scatter
- `plot_05_detector_comparison.png` — 5-detector box plot
- `plot_06_confusion_matrix.png` — TP/FP/FN/TN heatmap
- `plot_07_attack_type_pie.png` — Attack type distribution
- `plot_08_detector_heatmap.png` — Which detectors fire when
- `plot_09_ip_spoof_detail.png` — TTL + HMAC + confidence timeline
- `plot_10_fingerprint_distribution.png` — Normal vs attack fingerprints

---

## ⚔ Attack Scenarios

### Using the Attack Controller (Interactive Menu)

On the attacker machine:
```bash
cd Smartgrid-FDIA-Shield/attacker
sudo python3 attack_controller.py
```
```
╔══════════════════════════════════════════════════════════════╗
║            SmartGrid Attack Controller                      ║
║            Target: 192.168.1.100:1883 (MQTT Broker)         ║
╠══════════════════════════════════════════════════════════════╣
║  1. FDI via MQTT Command (ESP32 falsifies own readings)     ║
║  2. IP Spoofing Attack (forged source IP packets)           ║
║  3. Replay Attack (capture + replay)                        ║
║  4. Stop All Attacks                                        ║
║  5. Status (show running attacks)                           ║
║  6. Exit                                                    ║
╚══════════════════════════════════════════════════════════════╝
```

### Manual Attack Execution

**Scenario 1 — FDI via MQTT Command:**
```bash
# From any machine with MQTT access
mosquitto_pub -h 192.168.1.100 -t "smartgrid/node01/cmd" \
  -m '{"cmd":"INJECT_FDI","voltage":1.5,"current":0.3,"duration_s":60}'
```

**Scenario 2 — IP Spoofing:**
```bash
# On the attacker machine (requires sudo)
sudo python3 attack_ip_spoof.py --duration 60 --interval 5 --voltage-scale 1.5

# Advanced mode: compute valid HMAC (insider threat - Scenario 5)
sudo python3 attack_ip_spoof.py --duration 60 --advanced-mode
```

**Scenario 3 — Replay Attack:**
```bash
sudo python3 attack_replay.py --duration 60 --interval 5
```

**Stop all attacks:**
```bash
mosquitto_pub -h 192.168.1.100 -t "smartgrid/node01/cmd" -m '{"cmd":"STOP_ATTACK"}'
```

### 6 Test Scenarios Summary

| # | Scenario | Method | Expected Detection | Key Detector |
|---|----------|--------|--------------------|--------------|
| 1 | Baseline | None (5 min) | All NORMAL | — |
| 2 | FDI Voltage Spike | MQTT cmd: V × 1.5 | `FDI_FIRMWARE` | Physics |
| 3 | FDI Subtle (5%) | MQTT cmd: all × 1.05 | `FDI_FIRMWARE` | ML + Z-score |
| 4 | IP Spoofing | Scapy forged packets | `IP_SPOOF_CONFIRMED` | HMAC |
| 5 | IP Spoof + Valid HMAC | Insider threat | `SUSPECTED_SPOOF` | Fingerprint |
| 6 | Replay Attack | Captured packet replay | `REPLAY` | Seq analysis |

---

## 🔬 Detection Methods

### 1. Physics-Based Consistency Check (Weight: 0.25)
Validates that electrical readings obey physical laws:
- **P ≈ V × I × PF** (within 10% tolerance)
- Voltage within [200V, 260V]
- Frequency within [49Hz, 51Hz]
- Power factor within [0, 1]
- Energy monotonically increasing

### 2. Statistical Z-Score + EWMA (Weight: 0.20)
Rolling-window statistical anomaly detection:
- Computes Z-score: `|value - μ| / σ` for V, I, P
- EWMA (Exponentially Weighted Moving Average) residual tracking
- Flags readings >3σ from the rolling baseline

### 3. Isolation Forest ML (Weight: 0.20)
Unsupervised machine learning anomaly detector:
- Trained on 500 clean baseline samples
- 7-feature vector: [V, I, P, Hz, PF, RSSI, power_error_%]
- Scikit-learn `IsolationForest(contamination=0.05)`

### 4. HMAC-SHA256 Verification (Weight: 0.25)
Cryptographic payload authentication:
- ESP32 signs every JSON payload with shared secret key
- Gateway verifies using constant-time `hmac.compare_digest()`
- **Strongest single detector** — spoofed packets cannot forge a valid HMAC

### 5. Network Fingerprint (Weight: 0.10)
TCP/IP stack fingerprinting via Scapy:
- **TTL**: ESP32 (FreeRTOS) = 128, Linux = 64
- **TCP Window Size**: ESP32 (lwIP) = 5744, Linux = varies
- **TCP Options**: ESP32 sends MSS only; Linux sends SACK/Timestamp
- **Packet Timing**: ESP32 publishes every 5.0s ± 1.0s
- **MAC Conflict**: Two MACs for same IP = confirmed spoof

---

## 🔄 Data Recovery Strategies

When an attack is detected, corrupted readings are replaced using attack-type-aware recovery:

| Attack Type | Recovery Strategy | Rationale |
|-------------|------------------|-----------|
| `IP_SPOOF_CONFIRMED` | **Kalman Filter** (prediction-only) | Entire packet is fabricated — no real sensor data exists |
| `TAMPERED_OR_SPOOFED` | **Kalman Filter** (prediction-only) | Cannot trust any values in the payload |
| `FDI_FIRMWARE` | **Physics Reconstruction** first, then interpolation | Physical sensor still attached — partial data is recoverable |
| `REPLAY` | **Temporal Interpolation** with corrected timestamp | Values are real but stale — extrapolate from history |

---

## 📊 Results & Visualization

After running the full test suite, `analysis.py` generates:

| Plot | Description |
|------|-------------|
| Plot 1 | V/I/P time-series colored by data source (original vs recovered) |
| Plot 2 | Attack confidence timeline with threshold lines |
| Plot 3 | ROC curve with AUC score |
| Plot 4 | Recovery accuracy — reported vs recovered values |
| Plot 5 | Box plot comparing 5 individual detector scores |
| Plot 6 | Confusion matrix (TP, FP, FN, TN) |
| Plot 7 | Attack type distribution pie chart |
| Plot 8 | Detector signal heatmap (which detectors fire during which attacks) |
| Plot 9 | IP spoofing episode detail (TTL, HMAC validity, confidence) |
| Plot 10 | Fingerprint score distribution (normal vs attack) |

Plus a structured metrics summary table and `results/test_report.json` with all raw data.

---

## 🛠 Troubleshooting

| Problem | Solution |
|---------|----------|
| PZEM-004T reads 0.0V | Check TX/RX cross-wiring. TX→RX, not TX→TX. Verify 9600 baud. |
| PZEM-004T reads NaN | CRC error — check wiring connections and grounding. |
| ESP32 won't connect to Wi-Fi | Verify SSID/password. ESP32 supports 2.4GHz only (not 5GHz). |
| MQTT connection refused | Ensure Mosquitto is running: `sudo systemctl status mosquitto` |
| Mosquitto rejects remote connections | Check `/etc/mosquitto/conf.d/smartgrid.conf` has `listener 1883 0.0.0.0` |
| Scapy permission denied | Run with `sudo`. Or add `CAP_NET_RAW` capability to Python. |
| IP spoof packets not reaching broker | Check firewall rules. Ensure no IP spoofing protection on router. |
| Isolation Forest not loaded | Run baseline data collection first (Scenario 1, 5 min). Model trains automatically. |
| ThingSpeak upload fails | Verify API key in `.env`. ThingSpeak has 15-second rate limit. |
| `ModuleNotFoundError` | Activate venv: `source venv/bin/activate`. Then `pip install -r requirements.txt`. |

For detailed hardware troubleshooting (brownouts, CT clamp orientation, etc.), see [`docs/hardware_setup.md`](docs/hardware_setup.md).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Authors

- **Harish R**
- **Karthik K**
- **Aryan Jaljith**

---

<p align="center">
  <i>Built for academic research in smart grid cybersecurity. All attack simulations must only be run on networks and devices you own and control.</i>
</p>
