"""
MODULE BRIEFING
Purpose: Uploads verified telemetry data to ThingSpeak IoT cloud for remote monitoring.
Inputs: Verified telemetry data and detection results.
Outputs: HTTP GET requests to ThingSpeak API.
Dependencies: requests, threading, time, logging, schedule
"""

import requests
import threading
import time
import logging
import schedule
from typing import Optional, Dict

logger = logging.getLogger(__name__)

class CloudUploader:
    def __init__(self, api_key: str, base_url: str = 'https://api.thingspeak.com/update',
                 upload_interval_s: int = 15):
        self.api_key = api_key
        self.base_url = base_url
        self.upload_interval = upload_interval_s
        self._running = False
        self._thread = None
        self._latest_data = None
        self._lock = threading.Lock()
        
        # Stats
        self.stats = {
            'uploads_attempted': 0,
            'uploads_success': 0,
            'uploads_failed': 0,
            'last_upload_time': None,
        }
    
    def start(self):
        """Start the upload scheduler in a background thread."""
        if not self.api_key or self.api_key == 'YOUR_KEY_HERE':
            logger.warning('ThingSpeak API key not configured. Cloud upload disabled.')
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True,
                                        name='CloudUploader')
        self._thread.start()
        logger.info(f'Cloud uploader started (interval: {self.upload_interval}s)')
    
    def stop(self):
        """Stop the background upload thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def update_data(self, telemetry: dict, detection: dict = None):
        """Update the latest data to be uploaded on next cycle."""
        with self._lock:
            self._latest_data = {
                'telemetry': telemetry,
                'detection': detection or {},
            }
    
    def _scheduler_loop(self):
        """Main loop for the background scheduler thread."""
        while self._running:
            try:
                self._upload()
            except Exception as e:
                logger.error(f'Upload error: {e}')
            time.sleep(self.upload_interval)
    
    def _upload(self):
        """Upload latest data to ThingSpeak."""
        with self._lock:
            data = self._latest_data
        
        if data is None:
            return
        
        tel = data.get('telemetry', {})
        det = data.get('detection', {})
        
        # ThingSpeak fields mapping:
        # field1: voltage, field2: current, field3: power,
        # field4: frequency, field5: power_factor,
        # field6: attack_confidence, field7: status (0=normal, 1=suspicious, 2=attack)
        # field8: attack_type encoded
        
        status_code = {'NORMAL': 0, 'SUSPICIOUS': 1, 'ATTACK_DETECTED': 2}.get(
            det.get('status', 'NORMAL'), 0
        )
        
        params = {
            'api_key': self.api_key,
            'field1': tel.get('voltage_V', tel.get('voltage_v', 0)),
            'field2': tel.get('current_A', tel.get('current_a', 0)),
            'field3': tel.get('power_W', tel.get('power_w', 0)),
            'field4': tel.get('frequency_Hz', tel.get('frequency_hz', 50.0)),
            'field5': tel.get('power_factor', 1.0),
            'field6': det.get('attack_confidence', 0.0),
            'field7': status_code,
            'field8': hash(det.get('attack_type', '')) % 100,
        }
        
        self.stats['uploads_attempted'] += 1
        
        try:
            resp = requests.get(self.base_url, params=params, timeout=10)
            if resp.status_code == 200 and resp.text.strip() != '0':
                self.stats['uploads_success'] += 1
                self.stats['last_upload_time'] = time.time()
                logger.debug(f'ThingSpeak upload OK (entry: {resp.text.strip()})')
            else:
                self.stats['uploads_failed'] += 1
                logger.warning(f'ThingSpeak upload failed: {resp.status_code} {resp.text}')
        except requests.RequestException as e:
            self.stats['uploads_failed'] += 1
            logger.error(f'ThingSpeak request failed: {e}')
    
    def get_stats(self) -> dict:
        """Return a copy of the uploader statistics."""
        return dict(self.stats)
