"""
MODULE BRIEFING
Purpose: Central configuration loader for the SmartGrid project.
Inputs: Loads variables from the .env file.
Outputs: Configuration constants used across the project.
Dependencies: os, dotenv, pathlib
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Look for .env in current file's directory, current working directory, or standard install dir
env_paths = [
    Path(__file__).parent / '.env',
    Path.cwd() / '.env',
    Path('/home/smartgrid/smartgrid/.env')
]
for p in env_paths:
    if p.exists():
        load_dotenv(p, override=True)

# MQTT Configuration
MQTT_BROKER_IP = os.getenv('MQTT_BROKER_IP', '10.59.53.30')
MQTT_PORT = int(os.getenv('MQTT_PORT', '1883'))
MQTT_TOPIC_TELEMETRY = 'smartgrid/node01/telemetry'
MQTT_TOPIC_CMD = 'smartgrid/node01/cmd'
MQTT_TOPIC_ALERTS = 'smartgrid/alerts'

# Node Configuration
NODE_ID = os.getenv('NODE_ID', 'node_01')
EXPECTED_NODE_IP = os.getenv('EXPECTED_NODE_IP', '10.59.53.251')

# Security
HMAC_SECRET_KEY = os.getenv('HMAC_SECRET_KEY', 'smartgrid_secret_key_2025')

# ThingSpeak
THINGSPEAK_WRITE_KEY = os.getenv('THINGSPEAK_WRITE_KEY', '').strip().strip("'").strip('"')
THINGSPEAK_BASE_URL = 'https://api.thingspeak.com/update'

# Database
DB_PATH = Path(__file__).parent / 'data' / 'smartgrid.db'

# Logging
LOG_DIR = Path(__file__).parent / 'logs'
LOG_FILE = LOG_DIR / 'system.log'
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Detection Thresholds
ATTACK_CONFIDENCE_THRESHOLD = 0.6
SUSPICIOUS_THRESHOLD = 0.35
ROLLING_WINDOW_SIZE = 20
EWMA_ALPHA = 0.3
Z_SCORE_THRESHOLD = 3.0

# Detection Weights (5-signal fusion)
WEIGHT_PHYSICS = 0.25
WEIGHT_ZSCORE = 0.20
WEIGHT_ML = 0.20
WEIGHT_HMAC = 0.25
WEIGHT_FINGERPRINT = 0.10

# Network Fingerprint - Calibrated ESP32 (lwIP stack over Wi-Fi Hotspot) baseline
KNOWN_TTL = 64
KNOWN_TCP_WINDOW = 5500
KNOWN_MSS = 1460
KNOWN_TCP_OPTIONS = ['MSS']
KNOWN_PUBLISH_INTERVAL_S = 5.0
KNOWN_INTERVAL_TOLERANCE_S = 1.5

# Physics Bounds
VOLTAGE_MIN = 200.0
VOLTAGE_MAX = 260.0
FREQUENCY_MIN = 49.0
FREQUENCY_MAX = 51.0
POWER_FACTOR_MIN = 0.0
POWER_FACTOR_MAX = 1.0
POWER_TOLERANCE_PERCENT = 10.0

# Cloud Upload
CLOUD_UPLOAD_INTERVAL_S = 15

# Recovery
INTERPOLATION_WINDOW = 5
KALMAN_PROCESS_NOISE = 0.01
KALMAN_MEASUREMENT_NOISE = 0.1

# Isolation Forest
IF_CONTAMINATION = 0.05
IF_N_ESTIMATORS = 100
IF_MODEL_PATH = Path(__file__).parent / 'models' / 'isolation_forest.pkl'

# Results
RESULTS_DIR = Path(__file__).parent / 'results'

# ═══════════════════════════════════════════════════════
# DoS Detection Settings
# ═══════════════════════════════════════════════════════
DOS_RATE_WINDOW_S = int(os.getenv('DOS_RATE_WINDOW_S', '10'))
DOS_WARNING_RATE = int(os.getenv('DOS_WARNING_RATE', '10'))       # msg/s per IP
DOS_CRITICAL_RATE = int(os.getenv('DOS_CRITICAL_RATE', '20'))     # msg/s per IP → block
DOS_BLOCK_DURATION_S = int(os.getenv('DOS_BLOCK_DURATION_S', '300'))
DOS_ENABLE_IPTABLES = os.getenv('DOS_ENABLE_IPTABLES', 'false').lower() in ('true', '1', 'yes')

# ═══════════════════════════════════════════════════════
# InfluxDB Settings (for Grafana dashboards)
# ═══════════════════════════════════════════════════════
INFLUXDB_HOST = os.getenv('INFLUXDB_HOST', 'localhost')
INFLUXDB_PORT = int(os.getenv('INFLUXDB_PORT', '8086'))
INFLUXDB_DATABASE = os.getenv('INFLUXDB_DATABASE', 'smartgrid')
INFLUXDB_ENABLED = os.getenv('INFLUXDB_ENABLED', 'true').lower() in ('true', '1', 'yes')

# ═══════════════════════════════════════════════════════
# Digital Twin Settings
# ═══════════════════════════════════════════════════════
TWIN_NODE_ID = os.getenv('TWIN_NODE_ID', 'twin_01')
TWIN_TOPIC = f'smartgrid/{TWIN_NODE_ID}/telemetry'
TWIN_PUBLISH_INTERVAL_S = float(os.getenv('TWIN_PUBLISH_INTERVAL_S', '5.0'))

# ═══════════════════════════════════════════════════════
# Industrial Modbus TCP Settings (SCADA Interface)
# ═══════════════════════════════════════════════════════
MODBUS_ENABLED = os.getenv('MODBUS_ENABLED', 'true').lower() in ('true', '1', 'yes')
MODBUS_HOST = os.getenv('MODBUS_HOST', '0.0.0.0')
MODBUS_PORT = int(os.getenv('MODBUS_PORT', '5020'))

# ═══════════════════════════════════════════════════════
# WLS State Estimation & Virtual PMU Settings
# ═══════════════════════════════════════════════════════
WLS_CHI2_THRESHOLD = float(os.getenv('WLS_CHI2_THRESHOLD', '11.34'))  # alpha=0.01, 3 DOF
PMU_REPORT_RATE_HZ = float(os.getenv('PMU_REPORT_RATE_HZ', '10.0'))   # 100ms sub-second stream

# Ensure directories exist
for d in [DB_PATH.parent, LOG_DIR, IF_MODEL_PATH.parent, RESULTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def print_config():
    """
    Prints all configuration settings in a formatted table for debugging purposes.
    """
    settings = {k: v for k, v in globals().items() if k.isupper()}
    
    print("-" * 60)
    print(f"{'SMARTGRID CONFIGURATION':^60}")
    print("-" * 60)
    print(f"{'SETTING':<30} | {'VALUE'}")
    print("-" * 60)
    
    for key, value in sorted(settings.items()):
        # Hide secret keys partially
        if 'KEY' in key or 'SECRET' in key:
            val_str = str(value)
            if len(val_str) > 4:
                val_str = val_str[:4] + '*' * (len(val_str) - 4)
            print(f"{key:<30} | {val_str}")
        else:
            print(f"{key:<30} | {value}")
            
    print("-" * 60)

if __name__ == '__main__':
    print_config()
