"""
MODULE BRIEFING
Purpose: Main Orchestrator for the SmartGrid project (Raspberry Pi gateway).
It wires together the MQTT subscriber, database manager, FDI detector, IP spoof detector, data recovery, and cloud uploader.
Inputs: Telemetry payloads from the MQTT subscriber queue.
Outputs: Processed payloads stored in the database, alerts sent to the cloud, and recovery logs.
Dependencies: config, db_manager, hmac_verifier, network_fingerprint, mqtt_subscriber, fdi_detector, data_recovery, cloud_uploader, alert_publisher
Note: Research disclaimer: Any attack/security detection scripts are intended for use in a controlled lab testbed environment.
"""

import os
import sys
import json
import time
import signal
import logging
import threading
import queue
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime

# Project modules
from config import *
from db_manager import DatabaseManager
from hmac_verifier import verify_payload_hmac, hmac_anomaly_score
from network_fingerprint import NetworkFingerprint
from mqtt_subscriber import MQTTSubscriber
from fdi_detector import FDIDetector
from data_recovery import DataRecovery
from cloud_uploader import CloudUploader
from alert_publisher import AlertPublisher

# Global flags and stats for shutdown
shutdown_event = threading.Event()
stats = {
    'start_time': time.time(),
    'packets_processed': 0,
    'attacks_detected': 0,
    'spoof_events': 0
}

def setup_logger():
    """Setup rotating file logger and console output."""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    logger = logging.getLogger('SmartGridGateway')
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] %(message)s')
    
    # File handler (10MB max, keep 5 backups)
    fh = RotatingFileHandler(
        log_dir / 'system.log',
        maxBytes=10*1024*1024,
        backupCount=5
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    return logger

logger = setup_logger()

def print_banner():
    """Print the ASCII startup banner."""
    print("╔══════════════════════════════════════════════════╗")
    print("║  SmartGrid FDI + IP Spoof Detection Gateway      ║")
    print(f"║  Node: {NODE_ID} | Broker: {MQTT_BROKER}:{MQTT_PORT}".ljust(51) + "║")
    print(f"║  Expected ESP32 IP: {EXPECTED_NODE_IP}".ljust(51) + "║")
    print("╚══════════════════════════════════════════════════╝")

def run_startup_assertions():
    """Run critical startup assertions."""
    try:
        assert DB_PATH.parent.exists(), f"Database directory {DB_PATH.parent} does not exist"
        assert Path('.env').exists() or Path(__file__).parent.joinpath('.env').exists(), ".env configuration file is missing"
        assert HMAC_SECRET_KEY and len(HMAC_SECRET_KEY) > 0, "HMAC_SECRET_KEY must be set"
        assert EXPECTED_NODE_IP is not None, "EXPECTED_NODE_IP must be set"
        print("ALL CHECKS PASSED ✓")
        logger.info("Startup assertions passed.")
    except AssertionError as e:
        logger.error(f"Startup check failed: {e}")
        sys.exit(1)

def _print_status_line(payload, status, recovery):
    """Print one-line status to console."""
    ts = datetime.now().strftime('%H:%M:%S')
    node = payload.get('node_id', '?')
    v = payload.get('voltage_V', 0)
    i = payload.get('current_A', 0)
    p = payload.get('power_W', 0)
    
    if status == 'NORMAL':
        print(f'[{ts}][{node}] V={v:.1f} I={i:.3f} P={p:.1f} | NORMAL')
    elif status == 'SPOOF_CONFIRMED':
        rv = recovery.get('recovered_voltage', 0) if recovery else 0
        print(f'[{ts}][{node}] HMAC=FAIL SPOOF=CONFIRMED | V={v:.1f}->R:{rv:.1f} | RECOVERED')
    else:
        rv = recovery.get('recovered_voltage', 0) if recovery else 0
        print(f'[{ts}][{node}] V={v:.1f} I={i:.3f} P={p:.1f} | {status} | R_V={rv:.1f}')

def process_payload(payload, db, detector, recovery, fingerprint, alert_pub, cloud):
    """Process a single telemetry payload through the security pipeline."""
    stats['packets_processed'] += 1
    
    # 1. Insert raw telemetry to DB
    telemetry_id = db.insert_raw_telemetry(payload)
    
    # 2. HMAC check (extracted from payload)
    hmac_valid = payload.get('hmac_valid', True)
    hmac_missing = payload.get('hmac_missing', False)
    hmac_score = 1.0 if (not hmac_valid or hmac_missing) else 0.0
    
    # 3. Network fingerprint check
    fp_result = fingerprint.get_latest_result()
    fp_score = fp_result.get('fingerprint_score', 0.0)
    fp_verdict = fp_result.get('verdict', 'UNKNOWN')
    
    # 4. FAST PATH: Confirmed IP spoof
    if fp_verdict == 'CONFIRMED_SPOOF' and hmac_score == 1.0:
        stats['spoof_events'] += 1
        stats['attacks_detected'] += 1
        
        # Log spoof event
        db.log_ip_spoof_event({
            'event_time': int(time.time()),
            'suspected_attacker_ip': fp_result.get('src_ip', 'UNKNOWN'),
            'spoofed_src_ip': EXPECTED_NODE_IP,
            'ttl_seen': fp_result.get('ttl_seen'),
            'window_seen': fp_result.get('window_seen'),
            'hmac_valid': 0,
            'packet_count': fp_result.get('packet_count', 1),
            'duration_s': 0,
            'fingerprint_score': fp_score,
            'verdict': 'CONFIRMED_SPOOF',
        })
        
        detection_result = {
            'node_id': payload.get('node_id', NODE_ID),
            'timestamp': payload.get('timestamp', int(time.time())),
            'status': 'ATTACK_DETECTED',
            'attack_type': 'IP_SPOOF_CONFIRMED',
            'attack_confidence': 1.0,
            'physics_score': 0.0,
            'z_score_normalized': 0.0,
            'ml_score': 0.0,
            'hmac_score': hmac_score,
            'fingerprint_score': fp_score,
            'physics_violations': {},
            'compromised_parameters': [],
        }
        detection_id = db.insert_detection_result(detection_result)
        
        # Recover and store
        recovery_result = recovery.recover(payload, detection_result)
        db.insert_recovery_log(recovery_result)
        db.insert_verified_telemetry(
            telemetry_id=telemetry_id,
            detection_id=detection_id,
            node_id=payload.get('node_id', NODE_ID),
            timestamp=payload.get('timestamp', int(time.time())),
            voltage=recovery_result.get('recovered_voltage', 0),
            current=recovery_result.get('recovered_current', 0),
            power=recovery_result.get('recovered_power', 0),
            energy=payload.get('energy_Wh', 0),
            frequency=payload.get('frequency_Hz', 50.0),
            pf=payload.get('power_factor', 1.0),
            data_source='RECOVERED',
            recovery_strategy=recovery_result.get('strategy_used'),
            recovery_confidence=recovery_result.get('recovery_confidence'),
        )
        
        # Alert
        alert_pub.publish_alert(detection_result)
        db.insert_alert(
            node_id=payload.get('node_id', NODE_ID),
            alert_type='IP_SPOOF',
            severity='CRITICAL',
            message=f'IP spoofing confirmed. TTL={fp_result.get("ttl_seen")}, HMAC=FAIL',
            attack_type='IP_SPOOF_CONFIRMED',
            confidence=1.0,
        )
        
        _print_status_line(payload, 'SPOOF_CONFIRMED', recovery_result)
        return
    
    # 5. NORMAL PATH: Run full FDI detection
    detection_result = detector.detect(
        payload=payload,
        hmac_score=hmac_score,
        fingerprint_score=fp_score,
        fingerprint_verdict=fp_verdict,
    )
    detection_id = db.insert_detection_result(detection_result)
    
    # 6. Handle result
    status = detection_result.get('status', 'NORMAL')
    
    if status == 'NORMAL':
        # Store original data as verified
        db.insert_verified_telemetry(
            telemetry_id=telemetry_id,
            detection_id=detection_id,
            node_id=payload.get('node_id', NODE_ID),
            timestamp=payload.get('timestamp', int(time.time())),
            voltage=payload.get('voltage_V', 0),
            current=payload.get('current_A', 0),
            power=payload.get('power_W', 0),
            energy=payload.get('energy_Wh', 0),
            frequency=payload.get('frequency_Hz', 50.0),
            pf=payload.get('power_factor', 1.0),
            data_source='ORIGINAL',
        )
        # Update recovery history with verified reading
        recovery.add_verified_reading(payload)
        _print_status_line(payload, 'NORMAL', None)
    
    else:  # SUSPICIOUS or ATTACK_DETECTED
        if status == 'ATTACK_DETECTED':
            stats['attacks_detected'] += 1
            
        recovery_result = recovery.recover(payload, detection_result)
        db.insert_recovery_log(recovery_result)
        db.insert_verified_telemetry(
            telemetry_id=telemetry_id,
            detection_id=detection_id,
            node_id=payload.get('node_id', NODE_ID),
            timestamp=payload.get('timestamp', int(time.time())),
            voltage=recovery_result.get('recovered_voltage', 0),
            current=recovery_result.get('recovered_current', 0),
            power=recovery_result.get('recovered_power', 0),
            energy=payload.get('energy_Wh', 0),
            frequency=payload.get('frequency_Hz', 50.0),
            pf=payload.get('power_factor', 1.0),
            data_source='RECOVERED',
            recovery_strategy=recovery_result.get('strategy_used'),
            recovery_confidence=recovery_result.get('recovery_confidence'),
        )
        
        if status == 'ATTACK_DETECTED':
            alert_pub.publish_alert(detection_result)
            db.insert_alert(
                node_id=payload.get('node_id', NODE_ID),
                alert_type=detection_result.get('attack_type', 'UNKNOWN'),
                severity='CRITICAL',
                message=f'Attack detected: {detection_result.get("attack_type", "UNKNOWN")} '
                        f'(confidence={detection_result.get("attack_confidence", 0.0):.2f})',
                attack_type=detection_result.get('attack_type'),
                confidence=detection_result.get('attack_confidence'),
            )
        
        _print_status_line(payload, status, recovery_result)

def shutdown_handler(signum, frame):
    """Handle graceful shutdown signals."""
    logger.info(f"Received signal {signum}. Initiating graceful shutdown...")
    shutdown_event.set()

def main():
    # Load env vars handled via config import
    print_banner()
    run_startup_assertions()
    
    # Initialize Core Components
    logger.info("Initializing Database Manager...")
    db = DatabaseManager(DB_PATH)
    
    logger.info("Initializing FDI Detector...")
    detector = FDIDetector(db)
    
    logger.info("Initializing Data Recovery...")
    recovery = DataRecovery()
    
    logger.info("Initializing Alert Publisher...")
    alert_pub = AlertPublisher()
    
    logger.info("Initializing Network Fingerprint...")
    fingerprint = NetworkFingerprint(EXPECTED_NODE_IP)
    fingerprint.start()
    
    logger.info("Initializing MQTT Subscriber...")
    subscriber = MQTTSubscriber(broker=MQTT_BROKER, port=MQTT_PORT, topic=MQTT_TOPIC)
    subscriber.start()
    
    logger.info("Initializing Cloud Uploader...")
    cloud = CloudUploader(db)
    cloud.start()
    
    # Register shutdown handlers
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    logger.info("Main processing loop started.")
    
    try:
        while not shutdown_event.is_set():
            try:
                # Wait for payload from MQTT subscriber
                payload = subscriber.payload_queue.get(timeout=1.0)
                process_payload(payload, db, detector, recovery, fingerprint, alert_pub, cloud)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing payload: {e}", exc_info=True)
                
    except Exception as e:
        logger.critical(f"Critical error in main loop: {e}", exc_info=True)
        
    finally:
        # Graceful Shutdown
        logger.info("Stopping system components...")
        subscriber.stop()
        fingerprint.stop()
        cloud.stop()
        
        uptime = time.time() - stats['start_time']
        
        logger.info("=== SHUTDOWN SUMMARY ===")
        logger.info(f"Uptime: {uptime:.1f} seconds")
        logger.info(f"Packets processed: {stats['packets_processed']}")
        logger.info(f"Attacks detected: {stats['attacks_detected']}")
        logger.info(f"Spoof events confirmed: {stats['spoof_events']}")
        logger.info("System safely stopped.")
        
        print("\nShutdown complete.")

if __name__ == '__main__':
    main()
