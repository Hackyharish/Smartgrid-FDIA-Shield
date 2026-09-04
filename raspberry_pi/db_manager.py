"""
MODULE BRIEFING
Purpose: SQLite database manager for the Smart Grid FDI detection and recovery system.
Inputs: Dicts/values from MQTT handlers, detectors, and recoverers.
Outputs: Database rows, dicts of queried data.
Dependencies: sqlite3, json, time, threading, logging, os, pathlib
"""

import sqlite3
import json
import time
import threading
import logging
import os
from pathlib import Path

# Try to import DB_PATH from config, fallback if not available
try:
    from config import DB_PATH
except ImportError:
    # Fallback to local path if config is not present
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smartgrid.db")

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Manages SQLite database connections and operations for the Smart Grid project.
    Provides thread-safe write access and multi-threaded read access using WAL.
    """
    def __init__(self, db_path=None):
        self.db_path = db_path if db_path else DB_PATH
        
        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            # Enable WAL mode for concurrent reads/writes
            self.conn.execute("PRAGMA journal_mode=WAL")
            self._lock = threading.Lock()
            self._create_tables()
            logger.info(f"Database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def _create_tables(self):
        """Creates the necessary tables and indexes if they don't exist."""
        try:
            with self._lock:
                cursor = self.conn.cursor()

                # 1. raw_telemetry
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS raw_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    voltage_v REAL, current_a REAL, power_w REAL,
                    energy_wh REAL, frequency_hz REAL, power_factor REAL,
                    alarm INTEGER, rssi_dbm INTEGER, crc_errors INTEGER,
                    seq INTEGER,
                    hmac TEXT,
                    hmac_valid INTEGER,
                    mqtt_recv_timestamp INTEGER,
                    src_ip_seen TEXT,
                    raw_json TEXT,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
                """)

                # 2. detection_results
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS detection_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telemetry_id INTEGER REFERENCES raw_telemetry(id),
                    node_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    attack_type TEXT,
                    attack_confidence REAL,
                    physics_score REAL,
                    z_score_normalized REAL,
                    ml_score REAL,
                    hmac_score REAL,
                    fingerprint_score REAL,
                    physics_violations TEXT,
                    compromised_parameters TEXT,
                    src_ip_seen TEXT,
                    mac_conflict INTEGER,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
                """)

                # 3. verified_telemetry
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS verified_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    telemetry_id INTEGER REFERENCES raw_telemetry(id),
                    detection_id INTEGER REFERENCES detection_results(id),
                    node_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    voltage_v REAL, current_a REAL, power_w REAL,
                    energy_wh REAL, frequency_hz REAL, power_factor REAL,
                    data_source TEXT NOT NULL,
                    recovery_strategy TEXT,
                    recovery_confidence REAL,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
                """)

                # 4. recovery_log
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS recovery_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id INTEGER REFERENCES detection_results(id),
                    node_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    strategy_used TEXT,
                    original_voltage REAL, original_current REAL, original_power REAL,
                    recovered_voltage REAL, recovered_current REAL, recovered_power REAL,
                    recovery_confidence REAL,
                    attack_type_context TEXT,
                    recovery_note TEXT,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
                """)

                # 5. ip_spoof_events
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_spoof_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time INTEGER NOT NULL,
                    suspected_attacker_ip TEXT,
                    spoofed_src_ip TEXT,
                    ttl_seen INTEGER,
                    window_seen INTEGER,
                    hmac_valid INTEGER,
                    packet_count INTEGER,
                    duration_s REAL,
                    fingerprint_score REAL,
                    verdict TEXT,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
                """)

                # 6. alerts
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT,
                    attack_type TEXT,
                    attack_confidence REAL,
                    acknowledged INTEGER DEFAULT 0,
                    created_at INTEGER DEFAULT (strftime('%s','now'))
                )
                """)

                # Indexes
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_node_ts ON raw_telemetry(node_id, timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_det_node_ts ON detection_results(node_id, timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_det_attack ON detection_results(attack_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_spoof_time ON ip_spoof_events(event_time)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ver_node_ts ON verified_telemetry(node_id, timestamp)")

                self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error creating tables: {e}")

    def insert_raw_telemetry(self, payload_dict: dict) -> int:
        """Inserts a raw telemetry payload and returns the inserted row ID."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO raw_telemetry (
                        node_id, timestamp, voltage_v, current_a, power_w,
                        energy_wh, frequency_hz, power_factor, alarm, rssi_dbm,
                        crc_errors, seq, hmac, hmac_valid, mqtt_recv_timestamp,
                        src_ip_seen, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    payload_dict.get('node_id'),
                    payload_dict.get('timestamp'),
                    payload_dict.get('voltage_v'),
                    payload_dict.get('current_a'),
                    payload_dict.get('power_w'),
                    payload_dict.get('energy_wh'),
                    payload_dict.get('frequency_hz'),
                    payload_dict.get('power_factor'),
                    payload_dict.get('alarm'),
                    payload_dict.get('rssi_dbm'),
                    payload_dict.get('crc_errors'),
                    payload_dict.get('seq'),
                    payload_dict.get('hmac'),
                    payload_dict.get('hmac_valid'),
                    payload_dict.get('mqtt_recv_timestamp'),
                    payload_dict.get('src_ip_seen'),
                    payload_dict.get('raw_json') or json.dumps(payload_dict)
                ))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error inserting raw telemetry: {e}")
            return -1

    def insert_detection_result(self, result_dict: dict) -> int:
        """Inserts a detection result and returns the inserted row ID."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                
                phys_violations = result_dict.get('physics_violations')
                if isinstance(phys_violations, (dict, list)):
                    phys_violations = json.dumps(phys_violations)
                    
                comp_params = result_dict.get('compromised_parameters')
                if isinstance(comp_params, (dict, list)):
                    comp_params = json.dumps(comp_params)

                cursor.execute("""
                    INSERT INTO detection_results (
                        telemetry_id, node_id, timestamp, status, attack_type,
                        attack_confidence, physics_score, z_score_normalized,
                        ml_score, hmac_score, fingerprint_score, physics_violations,
                        compromised_parameters, src_ip_seen, mac_conflict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result_dict.get('telemetry_id'),
                    result_dict.get('node_id'),
                    result_dict.get('timestamp'),
                    result_dict.get('status'),
                    result_dict.get('attack_type'),
                    result_dict.get('attack_confidence'),
                    result_dict.get('physics_score'),
                    result_dict.get('z_score_normalized'),
                    result_dict.get('ml_score'),
                    result_dict.get('hmac_score'),
                    result_dict.get('fingerprint_score'),
                    phys_violations,
                    comp_params,
                    result_dict.get('src_ip_seen'),
                    result_dict.get('mac_conflict')
                ))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error inserting detection result: {e}")
            return -1

    def insert_verified_telemetry(self, telemetry_id, detection_id, node_id, timestamp, 
                                  voltage, current, power, energy, frequency, pf, 
                                  data_source, recovery_strategy=None, recovery_confidence=None) -> int:
        """Inserts verified telemetry (original or recovered) and returns the inserted row ID."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO verified_telemetry (
                        telemetry_id, detection_id, node_id, timestamp,
                        voltage_v, current_a, power_w, energy_wh,
                        frequency_hz, power_factor, data_source,
                        recovery_strategy, recovery_confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    telemetry_id, detection_id, node_id, timestamp,
                    voltage, current, power, energy, frequency, pf,
                    data_source, recovery_strategy, recovery_confidence
                ))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error inserting verified telemetry: {e}")
            return -1

    def insert_recovery_log(self, recovery_dict: dict) -> int:
        """Inserts a recovery log and returns the inserted row ID."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO recovery_log (
                        detection_id, node_id, timestamp, strategy_used,
                        original_voltage, original_current, original_power,
                        recovered_voltage, recovered_current, recovered_power,
                        recovery_confidence, attack_type_context, recovery_note
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    recovery_dict.get('detection_id'),
                    recovery_dict.get('node_id'),
                    recovery_dict.get('timestamp'),
                    recovery_dict.get('strategy_used'),
                    recovery_dict.get('original_voltage'),
                    recovery_dict.get('original_current'),
                    recovery_dict.get('original_power'),
                    recovery_dict.get('recovered_voltage'),
                    recovery_dict.get('recovered_current'),
                    recovery_dict.get('recovered_power'),
                    recovery_dict.get('recovery_confidence'),
                    recovery_dict.get('attack_type_context'),
                    recovery_dict.get('recovery_note')
                ))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error inserting recovery log: {e}")
            return -1

    def log_ip_spoof_event(self, event_dict: dict) -> int:
        """Inserts an IP spoof event and returns the inserted row ID."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                cursor.execute("""
                    INSERT INTO ip_spoof_events (
                        event_time, suspected_attacker_ip, spoofed_src_ip,
                        ttl_seen, window_seen, hmac_valid, packet_count,
                        duration_s, fingerprint_score, verdict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_dict.get('event_time'),
                    event_dict.get('suspected_attacker_ip'),
                    event_dict.get('spoofed_src_ip'),
                    event_dict.get('ttl_seen'),
                    event_dict.get('window_seen'),
                    event_dict.get('hmac_valid'),
                    event_dict.get('packet_count'),
                    event_dict.get('duration_s'),
                    event_dict.get('fingerprint_score'),
                    event_dict.get('verdict')
                ))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error logging ip spoof event: {e}")
            return -1

    def insert_alert(self, node_id, alert_type, severity, message, attack_type=None, confidence=None) -> int:
        """Inserts an alert and returns the inserted row ID."""
        try:
            with self._lock:
                cursor = self.conn.cursor()
                ts = int(time.time())
                cursor.execute("""
                    INSERT INTO alerts (
                        node_id, timestamp, alert_type, severity,
                        message, attack_type, attack_confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    node_id, ts, alert_type, severity, message, attack_type, confidence
                ))
                self.conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error inserting alert: {e}")
            return -1

    def get_recent_telemetry(self, node_id: str, count: int = 20) -> list[dict]:
        """Returns the last N verified telemetry rows as dictionaries."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM verified_telemetry
                WHERE node_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (node_id, count))
            rows = cursor.fetchall()
            # Reverse to be in chronological order
            return [dict(row) for row in reversed(rows)]
        except sqlite3.Error as e:
            logger.error(f"Error fetching recent verified telemetry: {e}")
            return []

    def get_recent_raw_telemetry(self, node_id: str, count: int = 20) -> list[dict]:
        """Returns the last N raw telemetry rows as dictionaries."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM raw_telemetry
                WHERE node_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (node_id, count))
            rows = cursor.fetchall()
            return [dict(row) for row in reversed(rows)]
        except sqlite3.Error as e:
            logger.error(f"Error fetching recent raw telemetry: {e}")
            return []

    def get_detection_stats(self, since_timestamp: int = 0) -> dict:
        """Returns detection statistics since the given timestamp."""
        stats = {
            'total_packets': 0,
            'normal_count': 0,
            'suspicious_count': 0,
            'attack_count': 0,
            'attack_types': {}
        }
        try:
            cursor = self.conn.cursor()
            
            # Total and statuses
            cursor.execute("""
                SELECT status, COUNT(*) as count 
                FROM detection_results 
                WHERE timestamp >= ?
                GROUP BY status
            """, (since_timestamp,))
            
            for row in cursor.fetchall():
                stats['total_packets'] += row['count']
                if row['status'] == 'NORMAL':
                    stats['normal_count'] = row['count']
                elif row['status'] == 'SUSPICIOUS':
                    stats['suspicious_count'] = row['count']
                elif row['status'] == 'ATTACK_DETECTED':
                    stats['attack_count'] = row['count']

            # Attack types
            cursor.execute("""
                SELECT attack_type, COUNT(*) as count 
                FROM detection_results 
                WHERE timestamp >= ? AND attack_type IS NOT NULL AND attack_type != 'NULL'
                GROUP BY attack_type
            """, (since_timestamp,))
            
            for row in cursor.fetchall():
                stats['attack_types'][row['attack_type']] = row['count']
                
            return stats
        except sqlite3.Error as e:
            logger.error(f"Error getting detection stats: {e}")
            return stats

    def get_spoof_summary(self, since_timestamp: int = 0) -> dict:
        """Returns a summary of IP spoofing events."""
        summary = {
            'total_spoof_episodes': 0,
            'avg_duration_s': 0.0,
            'packets_spoofed': 0,
            'detected_by_hmac': 0,
            'detected_by_fingerprint': 0,
            'detected_by_both': 0
        }
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT 
                    COUNT(*) as episodes,
                    AVG(duration_s) as avg_duration,
                    SUM(packet_count) as total_packets,
                    SUM(CASE WHEN hmac_valid = 0 THEN 1 ELSE 0 END) as hmac_detects,
                    SUM(CASE WHEN fingerprint_score > 0 THEN 1 ELSE 0 END) as fp_detects
                FROM ip_spoof_events
                WHERE event_time >= ?
            """, (since_timestamp,))
            
            row = cursor.fetchone()
            if row and row['episodes'] > 0:
                summary['total_spoof_episodes'] = row['episodes']
                summary['avg_duration_s'] = row['avg_duration'] or 0.0
                summary['packets_spoofed'] = row['total_packets'] or 0
                summary['detected_by_hmac'] = row['hmac_detects'] or 0
                summary['detected_by_fingerprint'] = row['fp_detects'] or 0
                
            # Both (intersection)
            cursor.execute("""
                SELECT COUNT(*) as both_count
                FROM ip_spoof_events
                WHERE event_time >= ? AND hmac_valid = 0 AND fingerprint_score > 0
            """, (since_timestamp,))
            row = cursor.fetchone()
            if row:
                summary['detected_by_both'] = row['both_count'] or 0
                
            return summary
        except sqlite3.Error as e:
            logger.error(f"Error getting spoof summary: {e}")
            return summary

    def get_all_detection_results(self, since_timestamp: int = 0) -> list[dict]:
        """Returns all detection results since the given timestamp for analysis."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM detection_results
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            """, (since_timestamp,))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching all detection results: {e}")
            return []

    def get_all_verified_telemetry(self, since_timestamp: int = 0) -> list[dict]:
        """Returns all verified telemetry since the given timestamp."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT * FROM verified_telemetry
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            """, (since_timestamp,))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching all verified telemetry: {e}")
            return []

    def get_baseline_data(self, node_id: str, count: int = 500) -> list[dict]:
        """Returns the oldest N NORMAL verified readings for ML training."""
        try:
            cursor = self.conn.cursor()
            # Join with detection_results to verify NORMAL status
            cursor.execute("""
                SELECT v.* 
                FROM verified_telemetry v
                JOIN detection_results d ON v.detection_id = d.id
                WHERE v.node_id = ? AND d.status = 'NORMAL'
                ORDER BY v.timestamp ASC
                LIMIT ?
            """, (node_id, count))
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Error fetching baseline data: {e}")
            return []

    def close(self):
        """Closes the database connection safely."""
        try:
            self.conn.close()
            logger.info("Database connection closed.")
        except sqlite3.Error as e:
            logger.error(f"Error closing database: {e}")

"""
