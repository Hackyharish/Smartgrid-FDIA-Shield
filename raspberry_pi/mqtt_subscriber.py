"""
MODULE BRIEFING
---------------
File: mqtt_subscriber.py
Project: IoT-Based False Data Injection Attack Detection and Data Recovery for Smart Grid Energy Monitoring
Purpose: 
    MQTT client that subscribes to telemetry and alert topics.
    It receives data from ESP32 nodes, parses JSON payloads, performs HMAC verification
    on every incoming message, and queues the processed payloads for further analysis.
    It also attempts to approximate the source IP of MQTT packets using a background Scapy sniffer.
    
Inputs:
    - MQTT messages on subscribed topics (e.g., 'smartgrid/node01/telemetry').
    - Network packets sniffed by Scapy for source IP tracking (requires root/admin permissions).
    
Outputs:
    - Thread-safe queue containing enriched telemetry payloads (parsed JSON + HMAC validation status + Source IP).
    - Alerts handled and logged directly.
    
Dependencies:
    - paho-mqtt
    - scapy (optional, for source IP tracking)
    - hmac_verifier (project module)
    
Note: The Scapy-based IP resolution is an approximation due to the decoupled nature of MQTT 
application messages and raw TCP packets, relying on timestamp correlation.
"""

import paho.mqtt.client as mqtt
import json
import time
import queue
import threading
import logging
from typing import Optional, Dict, Callable

# Import project modules
from hmac_verifier import verify_payload_hmac

logger = logging.getLogger(__name__)

class MQTTSubscriber:
    def __init__(self, broker_ip: str = '192.168.1.100', broker_port: int = 1883,
                 topics: list = None, queue_maxsize: int = 1000):
        """
        MQTT Subscriber with HMAC verification and source IP tracking.
        
        Args:
            broker_ip: MQTT broker IP address
            broker_port: MQTT broker port
            topics: List of (topic, qos) tuples to subscribe to
            queue_maxsize: Maximum items in the processing queue
        """
        self.broker_ip = broker_ip
        self.broker_port = broker_port
        self.topics = topics or [
            ('smartgrid/node01/telemetry', 1),
            ('smartgrid/alerts', 0),
        ]
        
        # Thread-safe processing queue
        self.payload_queue = queue.Queue(maxsize=queue_maxsize)
        self._queue_counter = 0
        self._queue_lock = threading.Lock()
        
        # Per-source-IP packet counts
        self.ip_packet_counts = {}  # {ip: count}
        self._ip_lock = threading.Lock()
        
        # Source IP resolution via Scapy (approximate)
        self._recent_packets = []  # [(timestamp, src_ip)] from Scapy
        self._packet_lock = threading.Lock()
        
        # MQTT client setup
        self.client = mqtt.Client(client_id='smartgrid_gateway', clean_session=True)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.reconnect_delay_set(min_delay=1, max_delay=30)
        
        # Stats
        self.stats = {
            'messages_received': 0,
            'hmac_valid': 0,
            'hmac_invalid': 0,
            'hmac_missing': 0,
            'parse_errors': 0,
            'queue_full_drops': 0,
        }
        
        self._connected = False
        self._running = False
        self._sniffer_thread = None

    def start(self):
        """Connect to MQTT broker and start receiving messages."""
        # Start the source IP sniffer first (optional - requires Scapy + permissions)
        self._start_ip_sniffer()
        
        # Connect MQTT client
        try:
            self.client.connect(self.broker_ip, self.broker_port, keepalive=60)
            self._running = True
            self.client.loop_start()  # Start background network thread
            logger.info(f'MQTT subscriber started, connecting to {self.broker_ip}:{self.broker_port}')
        except Exception as e:
            logger.error(f'Failed to connect to MQTT broker: {e}')
            raise

    def stop(self):
        """Disconnect and clean up."""
        self._running = False
        self.client.loop_stop()
        self.client.disconnect()
        logger.info('MQTT subscriber stopped')

    def _on_connect(self, client, userdata, flags, rc):
        """Callback when connected to broker. Subscribe to all topics."""
        if rc == 0:
            self._connected = True
            logger.info(f'Connected to MQTT broker at {self.broker_ip}:{self.broker_port}')
            for topic, qos in self.topics:
                client.subscribe(topic, qos)
                logger.info(f'Subscribed to {topic} (QoS {qos})')
        else:
            self._connected = False
            rc_meanings = {
                1: 'Incorrect protocol version',
                2: 'Invalid client identifier', 
                3: 'Server unavailable',
                4: 'Bad username or password',
                5: 'Not authorized',
            }
            logger.error(f'MQTT connect failed: {rc_meanings.get(rc, f"Unknown error {rc}")}')

    def _on_disconnect(self, client, userdata, rc):
        """Handle disconnection."""
        self._connected = False
        if rc != 0:
            logger.warning(f'Unexpected MQTT disconnect (rc={rc}), will auto-reconnect')
        else:
            logger.info('MQTT disconnected cleanly')

    def _on_message(self, client, userdata, msg):
        """Process incoming MQTT messages."""
        recv_timestamp = int(time.time())
        self.stats['messages_received'] += 1
        
        # Handle alert messages separately
        if msg.topic == 'smartgrid/alerts':
            self._handle_alert(msg)
            return
        
        # Parse JSON payload
        try:
            payload_str = msg.payload.decode('utf-8')
            payload = json.loads(payload_str)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.stats['parse_errors'] += 1
            logger.error(f'Failed to parse MQTT payload: {e}')
            return
        
        # HMAC verification (BEFORE queuing)
        hmac_result = verify_payload_hmac(payload)
        
        # Update HMAC stats
        if hmac_result['hmac_missing']:
            self.stats['hmac_missing'] += 1
        elif hmac_result['hmac_valid']:
            self.stats['hmac_valid'] += 1
        else:
            self.stats['hmac_invalid'] += 1
        
        # Try to resolve source IP from Scapy sniffer
        src_ip = self._resolve_src_ip(recv_timestamp)
        
        # Update IP packet counts
        if src_ip:
            with self._ip_lock:
                self.ip_packet_counts[src_ip] = self.ip_packet_counts.get(src_ip, 0) + 1
        
        # Build enriched payload for processing queue
        enriched_payload = dict(payload)  # copy original
        enriched_payload['hmac_valid'] = hmac_result['hmac_valid']
        enriched_payload['hmac_missing'] = hmac_result['hmac_missing']
        enriched_payload['mqtt_recv_timestamp'] = recv_timestamp
        enriched_payload['mqtt_src_ip'] = src_ip
        enriched_payload['mqtt_topic'] = msg.topic
        
        with self._queue_lock:
            self._queue_counter += 1
            enriched_payload['queue_position'] = self._queue_counter
        
        # Queue for processing
        try:
            self.payload_queue.put_nowait(enriched_payload)
        except queue.Full:
            self.stats['queue_full_drops'] += 1
            logger.warning('Payload queue full, dropping oldest entry')
            try:
                self.payload_queue.get_nowait()  # Drop oldest
                self.payload_queue.put_nowait(enriched_payload)
            except queue.Empty:
                pass
        
        # Log
        node_id = payload.get('node_id', 'unknown')
        hmac_status = 'VALID' if hmac_result['hmac_valid'] else ('MISSING' if hmac_result['hmac_missing'] else 'INVALID')
        logger.debug(f'[MQTT] {node_id} | HMAC={hmac_status} | src_ip={src_ip} | seq={payload.get("seq", "?")}')

    def _handle_alert(self, msg):
        """Handle messages on the alerts topic."""
        try:
            alert = json.loads(msg.payload.decode('utf-8'))
            logger.info(f'[ALERT RECEIVED] {alert}')
        except Exception as e:
            logger.error(f'Failed to parse alert message: {e}')

    def _start_ip_sniffer(self):
        """Start a Scapy sniffer to track source IPs of MQTT packets."""
        try:
            from scapy.all import sniff as scapy_sniff, TCP, IP as ScapyIP
            self._sniffer_thread = threading.Thread(target=self._ip_sniff_loop, daemon=True,
                                                    name='MQTT-IP-Sniffer')
            self._sniffer_thread.start()
            logger.info('Source IP sniffer started (Scapy-based)')
        except ImportError:
            logger.warning('Scapy not available - source IP tracking disabled')
        except Exception as e:
            logger.warning(f'Could not start IP sniffer: {e}')

    def _ip_sniff_loop(self):
        """Sniff TCP packets on MQTT port to record source IPs."""
        from scapy.all import sniff as scapy_sniff, TCP, IP as ScapyIP
        try:
            scapy_sniff(
                filter=f'tcp and dst port {self.broker_port}',
                prn=self._record_src_ip,
                stop_filter=lambda _: not self._running,
                store=False
            )
        except Exception as e:
            logger.error(f'IP sniffer error: {e}')

    def _record_src_ip(self, pkt):
        """Record source IP and timestamp from sniffed packet."""
        from scapy.all import IP as ScapyIP
        if pkt.haslayer(ScapyIP):
            src_ip = pkt[ScapyIP].src
            now = time.time()
            with self._packet_lock:
                self._recent_packets.append((now, src_ip))
                # Keep only last 100 entries
                if len(self._recent_packets) > 100:
                    self._recent_packets = self._recent_packets[-100:]

    def _resolve_src_ip(self, mqtt_timestamp: int) -> Optional[str]:
        """Cross-reference MQTT message timestamp with Scapy sniffer data."""
        with self._packet_lock:
            if not self._recent_packets:
                return None
            # Find the packet closest in time to the MQTT message (within 1 second)
            best_ip = None
            best_delta = float('inf')
            for pkt_time, pkt_ip in reversed(self._recent_packets):
                delta = abs(pkt_time - mqtt_timestamp)
                if delta < best_delta and delta < 1.0:
                    best_delta = delta
                    best_ip = pkt_ip
            return best_ip

    def get_stats(self) -> dict:
        """Return subscriber statistics."""
        return dict(self.stats)

    def get_ip_counts(self) -> dict:
        """Return packet counts per source IP."""
        with self._ip_lock:
            return dict(self.ip_packet_counts)

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def queue_size(self) -> int:
        return self.payload_queue.qsize()
