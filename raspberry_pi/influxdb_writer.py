"""
MODULE BRIEFING
---------------
Module: InfluxDB Writer
Description: Handles asynchronous, batch-writing of telemetry and detection data
to InfluxDB for Grafana visualization. Includes robust error handling and 
reconnection logic to ensure the main detection pipeline never blocks or crashes.
"""

import time
import logging
import threading
from queue import Queue, Empty
from typing import Dict, Any, Optional

try:
    from influxdb import InfluxDBClient
    from influxdb.exceptions import InfluxDBClientError, InfluxDBServerError
except ImportError:
    InfluxDBClient = None

# Fallback config imports
try:
    from config import INFLUXDB_HOST, INFLUXDB_PORT, INFLUXDB_DATABASE, INFLUXDB_ENABLED
except ImportError:
    INFLUXDB_HOST = 'localhost'
    INFLUXDB_PORT = 8086
    INFLUXDB_DATABASE = 'smartgrid'
    INFLUXDB_ENABLED = True

logger = logging.getLogger(__name__)

class InfluxDBWriter:
    def __init__(self, host=INFLUXDB_HOST, port=INFLUXDB_PORT, db=INFLUXDB_DATABASE, enabled=INFLUXDB_ENABLED):
        self.host = host
        self.port = port
        self.db = db
        self.enabled = enabled
        
        self.client = None
        self.queue = Queue(maxsize=10000)
        
        self._running = False
        self._worker_thread = None
        
        self.batch_size = 100
        self.flush_interval = 5.0 # seconds
        self.retry_interval = 10.0 # seconds

    def start(self):
        if not self.enabled:
            logger.info("InfluxDB writer is disabled in config.")
            return

        if InfluxDBClient is None:
            logger.error("influxdb library is not installed. Run: pip install influxdb")
            self.enabled = False
            return

        self._running = True
        self._connect()
        self._worker_thread = threading.Thread(target=self._flush_worker, daemon=True, name="InfluxDB-Flusher")
        self._worker_thread.start()
        logger.info(f"InfluxDB writer started (batch_size={self.batch_size}, interval={self.flush_interval}s)")

    def stop(self):
        if not self._running:
            return
        
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=self.flush_interval + 2)
        
        # Final flush
        self._flush_batch(force=True)
        
        if self.client:
            self.client.close()
        logger.info("InfluxDB writer stopped.")

    def _connect(self):
        if self.client:
            self.client.close()
        
        self.client = InfluxDBClient(host=self.host, port=self.port, database=self.db)
        
        try:
            # Check connection
            self.client.ping()
            # Try to create DB
            self.client.create_database(self.db)
            logger.info(f"Connected to InfluxDB at {self.host}:{self.port}/{self.db}")
        except Exception as e:
            logger.warning(f"Failed to connect to InfluxDB: {e}. Will retry later.")
            self.client = None

    def _flush_worker(self):
        last_flush = time.time()
        last_retry = time.time()

        while self._running:
            now = time.time()
            
            # Try reconnect if needed
            if self.client is None and (now - last_retry) > self.retry_interval:
                self._connect()
                last_retry = now

            if self.queue.qsize() >= self.batch_size or (now - last_flush) >= self.flush_interval:
                if self.queue.qsize() > 0:
                    self._flush_batch()
                last_flush = time.time()
                
            time.sleep(0.5)

    def _flush_batch(self, force=False):
        if not self.client:
            return

        points = []
        while not self.queue.empty() and (len(points) < self.batch_size or force):
            try:
                points.append(self.queue.get_nowait())
            except Empty:
                break
                
        if not points:
            return

        try:
            self.client.write_points(points)
        except Exception as e:
            logger.error(f"Failed to write batch to InfluxDB: {e}")
            # Could re-queue on error, but avoiding unbounded growth
            self.client = None # Trigger reconnect

    def _enqueue(self, point: Dict[str, Any]):
        if not self.enabled or not self._running:
            return
            
        try:
            self.queue.put_nowait(point)
        except Exception as e:
            logger.warning(f"InfluxDB queue full or error: {e}")

    def write_telemetry(self, payload: Dict[str, Any]):
        """Write raw sensor telemetry."""
        node_id = payload.get('node_id', 'node_01')
            
        fields = {}
        v = payload.get('voltage_V', payload.get('voltage', None))
        if v is not None:
            fields['voltage'] = float(v)

        i = payload.get('current_A', payload.get('current', None))
        if i is not None:
            fields['current'] = float(i)

        p = payload.get('power_W', payload.get('power', None))
        if p is not None:
            fields['power'] = float(p)

        e = payload.get('energy_Wh', payload.get('energy_kWh', payload.get('energy', None)))
        if e is not None:
            fields['energy'] = float(e)

        f = payload.get('frequency_Hz', payload.get('frequency', None))
        if f is not None:
            fields['frequency'] = float(f)

        pf = payload.get('power_factor', payload.get('pf', None))
        if pf is not None:
            fields['pf'] = float(pf)

        if not fields:
            return

        point = {
            "measurement": "telemetry",
            "tags": {
                "node_id": node_id
            },
            "fields": fields
        }
        self._enqueue(point)

    def write_detection(self, detection_result: Dict[str, Any]):
        """Write FDI detection results with WLS State Estimation and PMU metrics."""
        node_id = detection_result.get('node_id', 'node_01')
            
        fields = {
            "attack_confidence": float(detection_result.get('attack_confidence', 0.0)),
            "status": str(detection_result.get('status', 'NORMAL')),
            "attack_type": str(detection_result.get('attack_type', 'none')),
            "score_physics": float(detection_result.get('physics_score', 0.0)),
            "score_zscore": float(detection_result.get('z_score_normalized', 0.0)),
            "score_ml": float(detection_result.get('ml_score', 0.0)),
            "score_hmac": float(detection_result.get('hmac_score', 0.0)),
            "score_fingerprint": float(detection_result.get('fingerprint_score', 0.0)),
        }

        # WLS State Estimation fields
        state_est = detection_result.get('state_estimation')
        if state_est:
            fields["wls_chi_square"] = float(state_est.get('chi_square_stat', 0.0))
            fields["wls_max_residual"] = float(state_est.get('max_normalized_residual', 0.0))
            fields["wls_bad_data"] = 1.0 if state_est.get('bad_data_detected') else 0.0
            fields["wls_estimated_v"] = float(state_est.get('estimated_voltage', 0.0))

        # Synchrophasor PMU fields
        pmu = detection_result.get('synchrophasor_pmu')
        if pmu:
            fields["pmu_phase_angle_deg"] = float(pmu.get('voltage_angle_deg', 0.0))
            fields["pmu_rocof_Hz_s"] = float(pmu.get('rocof_Hz_s', 0.0))
            fields["pmu_tve_pct"] = float(pmu.get('total_vector_error_pct', 0.0))
                
        point = {
            "measurement": "detection",
            "tags": {
                "node_id": node_id
            },
            "fields": fields
        }
        self._enqueue(point)

    def write_dos_event(self, event_dict: Dict[str, Any]):
        """Write DoS detection events."""
        fields = {
            "rate": float(event_dict.get('rate', 0.0)),
            "limit": float(event_dict.get('limit', 0.0)),
            "status": str(event_dict.get('status', 'NORMAL')),
        }
        
        if 'severity' in event_dict:
            fields["severity"] = str(event_dict['severity'])

        point = {
            "measurement": "dos_events",
            "tags": {
                "ip": str(event_dict.get('ip', 'unknown')),
                "node_id": str(event_dict.get('node_id', 'unknown'))
            },
            "fields": fields
        }
        self._enqueue(point)
