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

load_dotenv(Path(__file__).parent / '.env')

# MQTT Configuration
MQTT_BROKER_IP = os.getenv('MQTT_BROKER_IP', '192.168.1.100')
MQTT_PORT = int(os.getenv('MQTT_PORT', '1883'))
MQTT_TOPIC_TELEMETRY = 'smartgrid/node01/telemetry'
MQTT_TOPIC_CMD = 'smartgrid/node01/cmd'
MQTT_TOPIC_ALERTS = 'smartgrid/alerts'

# Node Configuration
NODE_ID = os.getenv('NODE_ID', 'node_01')
EXPECTED_NODE_IP = os.getenv('EXPECTED_NODE_IP', '192.168.1.101')

# Security
HMAC_SECRET_KEY = os.getenv('HMAC_SECRET_KEY', 'smartgrid_secret_key_2025')

# ThingSpeak
THINGSPEAK_WRITE_KEY = os.getenv('THINGSPEAK_WRITE_KEY', '')
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

# Network Fingerprint - Known ESP32 (FreeRTOS lwIP) baseline
KNOWN_TTL = 128
KNOWN_TCP_WINDOW = 5744
KNOWN_MSS = 1460
KNOWN_TCP_OPTIONS = ['MSS']
KNOWN_PUBLISH_INTERVAL_S = 5.0
KNOWN_INTERVAL_TOLERANCE_S = 1.0

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
