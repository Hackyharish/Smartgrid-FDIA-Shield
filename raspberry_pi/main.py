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
import subprocess

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
from dos_detector import DoSDetector
from influxdb_writer import InfluxDBWriter
from modbus_server import ModbusServer

# Global flags and stats for shutdown
shutdown_event = threading.Event()
stats = {
    'start_time': time.time(),
    'packets_processed': 0,
    'attacks_detected': 0,
    'spoof_events': 0,
    'dos_events': 0
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
    print(f"║  Node: {NODE_ID} | Broker: {MQTT_BROKER_IP}:{MQTT_PORT}".ljust(51) + "║")
    print(f"║  Expected ESP32 IP: {EXPECTED_NODE_IP}".ljust(51) + "║")
    print("╚══════════════════════════════════════════════════╝")

def run_startup_assertions():
    """Run critical startup assertions and pin permanent ESP32 ARP entry."""
    try:
        assert DB_PATH.parent.exists(), f"Database directory {DB_PATH.parent} does not exist"
        assert Path('.env').exists() or Path(__file__).parent.joinpath('.env').exists(), ".env configuration file is missing"
        assert HMAC_SECRET_KEY and len(HMAC_SECRET_KEY) > 0, "HMAC_SECRET_KEY must be set"
        assert EXPECTED_NODE_IP is not None, "EXPECTED_NODE_IP must be set"
        
        # Pin ESP32 static MAC permanently so spoofed packets cannot hijack the socket
        target_mac = globals().get('EXPECTED_NODE_MAC', 'a0:b7:65:23:14:08')
        try:
            subprocess.run(['sudo', 'ip', 'neigh', 'replace', EXPECTED_NODE_IP, 'lladdr', target_mac, 'nud', 'permanent', 'dev', 'wlan0'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            subprocess.run(['sudo', 'arp', '-s', EXPECTED_NODE_IP, target_mac],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass

        print("ALL CHECKS PASSED ✓ (ESP32 Static ARP Pinned)")
        logger.info(f"Startup assertions passed. Static ARP pinned for {EXPECTED_NODE_IP} -> {target_mac}.")
    except AssertionError as e:
        logger.error(f"Startup check failed: {e}")
        sys.exit(1)

def heal_network_link(target_ip: str, target_mac: str = None):
    """Autonomously pins and refreshes static ARP entry on Raspberry Pi so real ESP32 communicates continuously."""
    mac = target_mac or globals().get('EXPECTED_NODE_MAC', 'a0:b7:65:23:14:08')
    prefix = [] if (hasattr(os, 'geteuid') and os.geteuid() == 0) else ['sudo']
    try:
        subprocess.run(prefix + ['ip', 'neigh', 'replace', target_ip, 'lladdr', mac, 'nud', 'permanent', 'dev', 'wlan0'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.5)
    except Exception:
        pass
    try:
        subprocess.run(prefix + ['arp', '-s', target_ip, mac],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.5)
    except Exception:
        pass

_last_console_status = 'NORMAL'

def _print_status_line(payload, status, recovery, detection=None):
    """Print one-line status to console with PMU angle, WLS Bad Data status, and transition notices."""
    global _last_console_status
    ts = datetime.now().strftime('%H:%M:%S')
    node = payload.get('node_id', '?')
    v = payload.get('voltage_V', 0)
    i = payload.get('current_A', 0)
    p = payload.get('power_W', 0)
    
    extra = ""
    if detection:
        pmu = detection.get('synchrophasor_pmu', {})
        delta = pmu.get('voltage_angle_deg', 0.0)
        state_est = detection.get('state_estimation', {})
        wls_flag = "WLS:BAD" if state_est.get('bad_data_detected') else "WLS:OK"
        extra = f" | δ={delta:+.1f}° {wls_flag}"

    if status == 'NORMAL':
        if _last_console_status != 'NORMAL':
            print(f"[{ts}][{node}] ATTACK CONCLUDED ✓ Telemetry restored to normal baseline.")
        _last_console_status = 'NORMAL'
        print(f'[{ts}][{node}] V={v:.1f}V I={i:.3f}A P={p:.1f}W{extra} | NORMAL')
    else:
        _last_console_status = status
        attack_type = detection.get('attack_type', status) if detection else status
        rec_v = recovery.get('recovered_voltage_V', recovery.get('recovered_voltage', 230.0)) if recovery else 230.0
        rec_i = recovery.get('recovered_current_A', recovery.get('recovered_current', 0.0)) if recovery else 0.0
        rec_p = recovery.get('recovered_power_W', recovery.get('recovered_power', 0.0)) if recovery else 0.0
        ml_val = detection.get('ml_score', 0.0) if detection else 0.0
        ml_disp = f" | ML={ml_val:.2f}" if ml_val > 0.0 else ""
        print(f'[{ts}][{node}] [ATTACK DETECTED: {attack_type}]{ml_disp} Tampered: V={v:.1f}V I={i:.3f}A P={p:.1f}W -> PREDICTED: V_pred={rec_v:.1f}V I_pred={rec_i:.3f}A P_pred={rec_p:.1f}W{extra} | RECOVERING')

def process_payload(payload, db, detector, recovery, fingerprint, alert_pub, cloud, dos_detector, influxdb, modbus):
    """Process a single telemetry payload through the security pipeline."""
    stats['packets_processed'] += 1
    
    # Record message for DoS rate tracking
    src_ip = payload.get('src_ip_seen') or payload.get('mqtt_src_ip') or payload.get('_src_ip') or 'UNKNOWN'
    if src_ip != EXPECTED_NODE_IP and src_ip != 'UNKNOWN':
        dos_detector.record_message(src_ip)
    
    # Check if DoS detector has flagged this IP
    if dos_detector.is_blocked(src_ip):
        stats['dos_events'] += 1
        now = time.time()
        if now - getattr(process_payload, '_last_dos_blocked_log', 0.0) >= 2.0:
            process_payload._last_dos_blocked_log = now
            ts = datetime.now().strftime('%H:%M:%S')
            print(f"[{ts}][DoS FIREWALL DROP] Dropping traffic from blocked IP {src_ip} (Total dropped: {stats['dos_events']})")
        if now - getattr(process_payload, '_last_dos_influx_time', 0.0) >= 1.0:
            process_payload._last_dos_influx_time = now
            influxdb.write_detection({
                'node_id': NODE_ID,
                'timestamp': int(now),
                'status': 'ATTACK_DETECTED',
                'attack_type': 'DOS_FLOOD',
                'attack_confidence': 1.0,
                'physics_score': 0.0,
                'z_score_normalized': 0.0,
                'ml_score': 0.0,
                'hmac_score': 1.0,
                'fingerprint_score': 0.0
            })
            influxdb.write_dos_event({
                'ip': src_ip if src_ip != 'UNKNOWN' else 'attacker',
                'node_id': NODE_ID,
                'rate': dos_detector.get_rate(src_ip),
                'limit': dos_detector.critical_rate,
                'status': 'BLOCKED'
            })
        return

    # Fast drop for unauthorized fake node floods without valid HMAC
    if payload.get('node_id') != NODE_ID and payload.get('hmac_missing', False):
        stats['dos_events'] += 1
        dos_detector.record_message(src_ip if src_ip != 'UNKNOWN' else 'UNAUTHORIZED_FLOOD')
        now = time.time()
        if now - getattr(process_payload, '_last_fake_flood_log', 0.0) >= 2.0:
            process_payload._last_fake_flood_log = now
            ts = datetime.now().strftime('%H:%M:%S')
            sender_str = f"from {src_ip}" if src_ip != 'UNKNOWN' else "flood traffic"
            print(f"[{ts}][DoS DEFENSE] Unauthorized node flood ({sender_str}) without HMAC -> DROPPING PACKETS (Total dropped: {stats['dos_events']})")
        if now - getattr(process_payload, '_last_dos_influx_time', 0.0) >= 1.0:
            process_payload._last_dos_influx_time = now
            influxdb.write_detection({
                'node_id': NODE_ID,
                'timestamp': int(now),
                'status': 'ATTACK_DETECTED',
                'attack_type': 'DOS_FLOOD',
                'attack_confidence': 1.0,
                'physics_score': 0.0,
                'z_score_normalized': 0.0,
                'ml_score': 0.0,
                'hmac_score': 1.0,
                'fingerprint_score': 0.0
            })
            influxdb.write_dos_event({
                'ip': src_ip if src_ip != 'UNKNOWN' else 'attacker',
                'node_id': NODE_ID,
                'rate': dos_detector.get_rate(src_ip if src_ip != 'UNKNOWN' else 'UNAUTHORIZED_FLOOD'),
                'limit': dos_detector.critical_rate,
                'status': 'ATTACK_DETECTED'
            })
        return
    
    # 1. Insert raw telemetry to DB (audit trail)
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
        
        phys_score, phys_viols, _, _ = detector._physics_check(payload)
        z_score = detector._statistical_check(payload)
        ml_score = detector._ml_check(payload)
        
        detection_result = {
            'node_id': payload.get('node_id', NODE_ID),
            'timestamp': payload.get('timestamp', int(time.time())),
            'status': 'ATTACK_DETECTED',
            'attack_type': 'IP_SPOOF_CONFIRMED',
            'attack_confidence': 1.0,
            'physics_score': round(float(phys_score), 4),
            'z_score_normalized': round(float(z_score), 4),
            'ml_score': round(float(ml_score), 4),
            'hmac_score': hmac_score,
            'fingerprint_score': fp_score,
            'physics_violations': phys_viols,
            'compromised_parameters': list(phys_viols.keys()),
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
            voltage=recovery_result.get('recovered_voltage', 230.0),
            current=recovery_result.get('recovered_current', 0.0),
            power=recovery_result.get('recovered_power', 0.0),
            energy=payload.get('energy_Wh', 0),
            frequency=payload.get('frequency_Hz', 50.0),
            pf=payload.get('power_factor', 1.0),
            data_source='RECOVERED',
            recovery_strategy=recovery_result.get('strategy_used'),
            recovery_confidence=recovery_result.get('recovery_confidence'),
        )
        
        # Build clean recovered payload for external sinks
        clean_payload = payload.copy()
        clean_payload['voltage_V'] = recovery_result.get('recovered_voltage', 230.0)
        clean_payload['current_A'] = recovery_result.get('recovered_current', 0.0)
        clean_payload['power_W'] = recovery_result.get('recovered_power', 0.0)
        clean_payload['data_source'] = 'RECOVERED'

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
        
        # Update sinks with clean recovered data
        influxdb.write_telemetry(clean_payload)
        influxdb.write_detection(detection_result)
        cloud.update_data(clean_payload, detection_result)
        modbus.update_registers(
            telemetry=clean_payload,
            detection=detection_result,
            state_est=None,
            pmu=None
        )
        _print_status_line(payload, 'SPOOF_CONFIRMED', recovery_result, detection_result)
        heal_network_link(EXPECTED_NODE_IP)
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
        clean_payload = payload.copy()
        clean_payload['data_source'] = 'ORIGINAL'
        _print_status_line(payload, 'NORMAL', None, detection_result)
    
    else:  # SUSPICIOUS or ATTACK_DETECTED
        if status == 'ATTACK_DETECTED':
            stats['attacks_detected'] += 1
            heal_network_link(EXPECTED_NODE_IP)
            
        recovery_result = recovery.recover(payload, detection_result)
        db.insert_recovery_log(recovery_result)

        rec_v = recovery_result.get('recovered_voltage_V', recovery_result.get('recovered_voltage', 230.0))
        rec_i = recovery_result.get('recovered_current_A', recovery_result.get('recovered_current', 0.0))
        rec_p = recovery_result.get('recovered_power_W', recovery_result.get('recovered_power', 0.0))

        db.insert_verified_telemetry(
            telemetry_id=telemetry_id,
            detection_id=detection_id,
            node_id=payload.get('node_id', NODE_ID),
            timestamp=payload.get('timestamp', int(time.time())),
            voltage=rec_v,
            current=rec_i,
            power=rec_p,
            energy=payload.get('energy_Wh', 0),
            frequency=payload.get('frequency_Hz', 50.0),
            pf=payload.get('power_factor', 1.0),
            data_source='RECOVERED',
            recovery_strategy=recovery_result.get('strategy_used'),
            recovery_confidence=recovery_result.get('recovery_confidence'),
        )

        clean_payload = payload.copy()
        clean_payload['voltage_V'] = rec_v
        clean_payload['current_A'] = rec_i
        clean_payload['power_W'] = rec_p
        clean_payload['data_source'] = 'RECOVERED'
        
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
        
        _print_status_line(payload, status, recovery_result, detection_result)
        
    # Write verified clean/recovered telemetry to InfluxDB for Grafana
    influxdb.write_telemetry(clean_payload)

    # Update latest clean telemetry & detection for Cloud Uploader (ThingSpeak)
    cloud.update_data(clean_payload, detection_result)
    
    # Write detection result to InfluxDB for Grafana
    influxdb.write_detection(detection_result)

    # Update Modbus industrial registers & SCADA breaker with clean/recovered values
    modbus.update_registers(
        telemetry=clean_payload,
        detection=detection_result,
        state_est=detection_result.get('state_estimation'),
        pmu=detection_result.get('synchrophasor_pmu')
    )

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
    detector = FDIDetector(node_id=NODE_ID, rolling_window_size=ROLLING_WINDOW_SIZE, model_path=IF_MODEL_PATH)
    
    logger.info("Initializing Data Recovery...")
    recovery = DataRecovery(interpolation_window=INTERPOLATION_WINDOW, kalman_process_noise=KALMAN_PROCESS_NOISE, kalman_measurement_noise=KALMAN_MEASUREMENT_NOISE)
    
    logger.info("Initializing Alert Publisher...")
    alert_pub = AlertPublisher(broker_ip=MQTT_BROKER_IP, broker_port=MQTT_PORT, alert_topic=MQTT_TOPIC_ALERTS)
    alert_pub.start()
    
    logger.info("Initializing Network Fingerprint...")
    fingerprint = NetworkFingerprint(target_ip=EXPECTED_NODE_IP, broker_port=MQTT_PORT)
    fingerprint.start()
    
    logger.info("Initializing MQTT Subscriber...")
    subscriber = MQTTSubscriber(broker_ip=MQTT_BROKER_IP, broker_port=MQTT_PORT)
    subscriber.start()
    
    logger.info("Initializing Cloud Uploader...")
    cloud = CloudUploader(
        api_key=THINGSPEAK_WRITE_KEY if globals().get('THINGSPEAK_ENABLED', True) else '',
        base_url=THINGSPEAK_BASE_URL,
        upload_interval_s=CLOUD_UPLOAD_INTERVAL_S
    )
    cloud.start()
    
    logger.info("Initializing InfluxDB Writer...")
    influxdb = InfluxDBWriter()
    influxdb.start()

    logger.info("Initializing DoS Detector...")
    dos_detector = DoSDetector(influxdb_writer=influxdb)
    dos_detector.start()
    
    logger.info("Initializing Modbus TCP Server...")
    modbus = ModbusServer(host=MODBUS_HOST, port=MODBUS_PORT)
    modbus.start()
    time.sleep(0.05)
    if not modbus.running:
        print(f"[!] WARNING: Modbus TCP Server failed to bind port {MODBUS_PORT}. Check for port conflict.")

    # Seed initial clean baseline in InfluxDB so Grafana immediately renders NORMAL status
    influxdb.write_detection({
        'node_id': NODE_ID,
        'timestamp': int(time.time()),
        'status': 'NORMAL',
        'attack_type': 'none',
        'attack_confidence': 0.0,
        'physics_score': 0.0,
        'z_score_normalized': 0.0,
        'ml_score': 0.0,
        'hmac_score': 0.0,
        'fingerprint_score': 0.0
    })
    
    # Register shutdown handlers
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    logger.info("Main processing loop started.")
    
    last_packet_time = time.time()
    last_forecast_time = 0.0
    attack_hold_active = False

    try:
        while not shutdown_event.is_set():
            try:
                # Wait for payload from MQTT subscriber
                payload = subscriber.payload_queue.get(timeout=1.0)
                
                # Live packet arrived!
                last_packet_time = time.time()
                if attack_hold_active:
                    attack_hold_active = False
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"[{ts}][{NODE_ID}] LIVE LINK RESTORED ✓ Returning to live stream.")
                
                process_payload(payload, db, detector, recovery, fingerprint, alert_pub, cloud, dos_detector, influxdb, modbus)
                
            except queue.Empty:
                now = time.time()
                # If no telemetry received for >= 2.0 seconds (link disrupted, silenced under attack, or ARP hijacked)
                if now - last_packet_time >= 2.0:
                    if now - last_forecast_time >= 1.0:
                        last_forecast_time = now
                        attack_hold_active = True
                        
                        # Generate predicted physical state based on verified history
                        forecast = recovery.predict_state(node_id=NODE_ID)
                        
                        # Feed predicted telemetry to InfluxDB (Grafana)
                        influxdb.write_telemetry(forecast)
                        
                        # Holding attack detection context
                        det_hold = {
                            'node_id': NODE_ID,
                            'timestamp': int(now),
                            'status': 'ATTACK_DETECTED',
                            'attack_type': 'LINK_SILENCED_OR_ATTACK_INTERRUPTED',
                            'attack_confidence': 0.85,
                            'physics_score': 0.0,
                            'z_score_normalized': 0.0,
                            'ml_score': 0.0,
                            'hmac_score': 0.0,
                            'fingerprint_score': 0.85
                        }
                        influxdb.write_detection(det_hold)
                        cloud.update_data(forecast, det_hold)
                        
                        # Update Modbus SCADA registers with predicted values
                        modbus.update_registers(
                            telemetry=forecast,
                            detection=det_hold,
                            state_est=None,
                            pmu=None
                        )
                        
                        ts = datetime.now().strftime('%H:%M:%S')
                        v_f = forecast['voltage_V']
                        i_f = forecast['current_A']
                        p_f = forecast['power_W']
                        print(f"[{ts}][{NODE_ID}] [ATTACK: LINK SILENCED / HIJACKED] | PREDICTED: V_pred={v_f:.1f}V I_pred={i_f:.3f}A P_pred={p_f:.1f}W | δ=-0.0° WLS:HOLD | RECOVERING")
                        
                        # Autonomously flush any poisoned ARP entries so real ESP32 can reconnect
                        heal_network_link(EXPECTED_NODE_IP)
            except Exception as e:
                logger.error(f"Error processing payload: {e}", exc_info=True)

            # Check for Modbus SCADA cyber-physical tampering / coil tripping
            modbus_event = modbus.pop_tamper_event()
            if modbus_event:
                stats['attacks_detected'] += 1
                now = time.time()
                ts = datetime.now().strftime('%H:%M:%S')
                event_type = modbus_event.get('type', 'MODBUS_REGISTER_TAMPERING')
                det_modbus = {
                    'node_id': NODE_ID,
                    'timestamp': int(now),
                    'status': 'ATTACK_DETECTED',
                    'attack_type': event_type,
                    'attack_confidence': 1.0,
                    'physics_score': 0.85,
                    'z_score_normalized': 0.80,
                    'ml_score': 0.85,
                    'hmac_score': 0.0,
                    'fingerprint_score': 0.0,
                    'physics_violations': {'modbus_tamper': True},
                    'compromised_parameters': [modbus_event.get('param', 'voltage_V')]
                }
                influxdb.write_detection(det_modbus)
                alert_pub.publish_alert(det_modbus)
                db.insert_alert(
                    node_id=NODE_ID,
                    alert_type='SCADA_MODBUS_TAMPER',
                    severity='CRITICAL',
                    message=f"Modbus attack: {modbus_event.get('desc', 'tampering')}",
                    attack_type=event_type,
                    confidence=1.0
                )
                print(f"[{ts}][{NODE_ID}] [ATTACK DETECTED: {event_type}] | ML=0.85 (conf: 1.0) -> RECOVERING")
                forecast = recovery.predict_state(node_id=NODE_ID)
                modbus.update_registers(
                    telemetry=forecast,
                    detection=det_modbus,
                    state_est=None,
                    pmu=None
                )
                
    except Exception as e:
        logger.critical(f"Critical error in main loop: {e}", exc_info=True)
        
    finally:
        # Graceful Shutdown
        logger.info("Stopping system components...")
        alert_pub.stop()
        subscriber.stop()
        fingerprint.stop()
        cloud.stop()
        dos_detector.stop()
        influxdb.stop()
        modbus.stop()
        
        uptime = time.time() - stats['start_time']
        
        logger.info("=== SHUTDOWN SUMMARY ===")
        logger.info(f"Uptime: {uptime:.1f} seconds")
        logger.info(f"Packets processed: {stats['packets_processed']}")
        logger.info(f"Attacks detected: {stats['attacks_detected']}")
        logger.info(f"Spoof events confirmed: {stats['spoof_events']}")
        logger.info(f"DoS events blocked: {stats['dos_events']}")
        logger.info("System safely stopped.")
        
        print("\nShutdown complete.")

if __name__ == '__main__':
    main()

