"""
MODULE BRIEFING
Purpose: Publishes attack alerts to MQTT back-channel for monitoring and fast incident response.
Inputs: Attack detection results containing scores and classifications.
Outputs: MQTT messages published to a specific alert topic.
Dependencies: paho-mqtt, json, time, logging
"""

import json
import time
import logging
import paho.mqtt.client as mqtt
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class AlertPublisher:
    def __init__(self, broker_ip='192.168.1.100', broker_port=1883,
                 alert_topic='smartgrid/alerts'):
        self.broker_ip = broker_ip
        self.broker_port = broker_port
        self.alert_topic = alert_topic
        self.client = None
        self._connected = False
        
        # Stats
        self.stats = {
            'alerts_published': 0,
            'alerts_failed': 0,
        }
    
    def start(self):
        """Connect to MQTT broker for publishing alerts."""
        try:
            self.client = mqtt.Client(client_id='smartgrid_alert_pub')
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.connect(self.broker_ip, self.broker_port, keepalive=60)
            self.client.loop_start()
        except Exception as e:
            logger.error(f'Alert publisher MQTT connect failed: {e}')
    
    def stop(self):
        """Disconnect and stop the MQTT client loop."""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
    
    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            logger.info('Alert publisher connected to MQTT broker')
        else:
            logger.error(f'Alert publisher connect failed: rc={rc}')
    
    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        logger.info('Alert publisher disconnected from MQTT broker')
    
    def publish_alert(self, detection_result: dict):
        """Publish an attack alert to the MQTT alerts topic."""
        if not self._connected or not self.client:
            logger.warning('Alert publisher not connected — alert not sent')
            self.stats['alerts_failed'] += 1
            return
        
        alert = {
            'node_id': detection_result.get('node_id', 'unknown'),
            'timestamp': int(time.time()),
            'status': detection_result.get('status', 'UNKNOWN'),
            'attack_type': detection_result.get('attack_type'),
            'attack_confidence': detection_result.get('attack_confidence', 0.0),
            'physics_score': detection_result.get('physics_score', 0.0),
            'hmac_score': detection_result.get('hmac_score', 0.0),
            'fingerprint_score': detection_result.get('fingerprint_score', 0.0),
            'source': 'smartgrid_gateway',
        }
        
        try:
            payload = json.dumps(alert)
            result = self.client.publish(self.alert_topic, payload, qos=1)
            result.wait_for_publish(timeout=5)
            self.stats['alerts_published'] += 1
            logger.info(f'Alert published: {detection_result.get("status")} — '
                       f'{detection_result.get("attack_type", "N/A")} '
                       f'(conf={detection_result.get("attack_confidence", 0):.2f})')
        except Exception as e:
            self.stats['alerts_failed'] += 1
            logger.error(f'Failed to publish alert: {e}')
    
    def get_stats(self) -> dict:
        """Return a copy of the publisher statistics."""
        return dict(self.stats)
