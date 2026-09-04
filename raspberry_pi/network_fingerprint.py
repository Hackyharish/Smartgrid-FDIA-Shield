"""
MODULE BRIEFING:
Purpose: Detects IP spoofing at the NETWORK layer by analyzing TCP/IP packet characteristics.
Inputs: Incoming packets from the target IP via Scapy sniffer on the Raspberry Pi interface.
Outputs: Fingerprint scores, spoofing verdicts (LEGITIMATE, SUSPECTED_SPOOF, CONFIRMED_SPOOF).
Dependencies: threading, time, logging, collections, scapy

RESEARCH DISCLAIMER:
This module is developed for a controlled university final-year project lab testbed: 
"IoT-Based False Data Injection Attack Detection and Data Recovery for Smart Grid Energy Monitoring".
Do not use this for malicious activities or outside of authorized testing environments.

NOTE ON MAC DETECTION:
MAC address conflict detection only works on a local LAN because MAC addresses are not preserved across routed networks.
"""

import threading
import time
import logging
from collections import defaultdict
from typing import Optional, Dict

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, TCP, IP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning('Scapy not available - network fingerprinting disabled')


# Default known ESP32 fingerprint (FreeRTOS + lwIP TCP stack)
DEFAULT_ESP32_FINGERPRINT = {
    'ttl': 128,
    'tcp_window': 5744,
    'mss': 1460,
    'tcp_options': ['MSS'],  # lwIP doesn't send SACK/Timestamp by default
    'publish_interval_s': 5.0,
    'interval_tolerance_s': 1.0,
}

class NetworkFingerprint:
    """
    NetworkFingerprint class runs a Scapy sniffer in a background thread and analyzes TCP/IP characteristics
    of incoming packets to identify potential IP spoofing attacks.
    """
    def __init__(self, target_ip: str, known_fingerprint: dict = None,
                 sniff_interface: str = None, broker_port: int = 1883):
        self.target_ip = target_ip
        self.fingerprint = known_fingerprint or DEFAULT_ESP32_FINGERPRINT
        self.interface = sniff_interface
        self.broker_port = broker_port
        
        # Tracking state
        self._lock = threading.Lock()
        self._running = False
        self._sniffer_thread = None
        
        # Per-IP tracking
        self._last_packet_time = {}  # {ip: timestamp}
        self._mac_addresses = defaultdict(set)  # {ip: {mac1, mac2}}
        self._latest_results = {}  # {ip: result_dict}
        self._packet_counts = defaultdict(int)  # {ip: count}
        
        # History for timing analysis
        self._arrival_times = defaultdict(list)  # {ip: [t1, t2, ...]}
        self._max_history = 50

    def start_sniffer(self) -> bool:
        """Start Scapy packet sniffer in a background daemon thread."""
        if not SCAPY_AVAILABLE:
            logger.error('Cannot start sniffer: Scapy not installed')
            return False
        if self._running:
            logger.warning('Sniffer already running')
            return True
        self._running = True
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True,
                                                 name='NetworkFingerprint-Sniffer')
        self._sniffer_thread.start()
        logger.info(f'Network fingerprint sniffer started for target IP {self.target_ip}')
        return True

    def stop_sniffer(self):
        """Stop the sniffer thread cleanly."""
        self._running = False
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=5.0)
        logger.info('Network fingerprint sniffer stopped')

    def _sniff_loop(self):
        """Main sniff loop - runs in background thread."""
        bpf_filter = f'tcp and dst port {self.broker_port}'
        try:
            sniff(
                filter=bpf_filter,
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda _: not self._running,
                store=False
            )
        except Exception as e:
            logger.error(f'Sniffer error: {e}')
            self._running = False

    def _process_packet(self, pkt):
        """Process each captured packet and update fingerprint analysis."""
        # Only process TCP packets with IP layer
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        
        src_ip = pkt[IP].src
        # Only analyze packets claiming to be from our target IP
        # But track ALL source IPs for anomaly detection
        
        now = time.time()
        
        with self._lock:
            self._packet_counts[src_ip] += 1
            
            # Track MAC addresses (Ether layer available on local LAN)
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                self._mac_addresses[src_ip].add(src_mac)
            
            # Track arrival times
            self._arrival_times[src_ip].append(now)
            if len(self._arrival_times[src_ip]) > self._max_history:
                self._arrival_times[src_ip] = self._arrival_times[src_ip][-self._max_history:]
            
            # Only do full fingerprint analysis for target IP
            if src_ip == self.target_ip:
                self._analyze_packet(pkt, src_ip, now)

    def _analyze_packet(self, pkt, src_ip: str, now: float):
        """Full fingerprint analysis for packets from target IP."""
        # Extract TCP/IP characteristics
        pkt_ttl = pkt[IP].ttl
        pkt_window = pkt[TCP].window
        
        # Extract TCP options
        pkt_options = []
        if pkt[TCP].options:
            for opt_name, opt_val in pkt[TCP].options:
                pkt_options.append(opt_name)
        
        # Check MSS in options
        pkt_mss = None
        for opt_name, opt_val in (pkt[TCP].options or []):
            if opt_name == 'MSS':
                pkt_mss = opt_val
        
        # Timing analysis
        timing_ok = True
        inter_arrival = None
        times = self._arrival_times[src_ip]
        if len(times) >= 2:
            inter_arrival = times[-1] - times[-2]
            expected = self.fingerprint['publish_interval_s']
            tolerance = self.fingerprint['interval_tolerance_s']
            timing_ok = abs(inter_arrival - expected) < tolerance
        
        # Fingerprint comparison scores
        ttl_match = (pkt_ttl == self.fingerprint['ttl'])
        window_match = (pkt_window == self.fingerprint['tcp_window'])
        
        # Options matching: check if observed options match known ESP32 options
        known_opts = set(self.fingerprint['tcp_options'])
        seen_opts = set(pkt_options)
        # If ESP32 only sends MSS but we see SACK/Timestamp, it's suspicious
        options_match = (seen_opts == known_opts) or (len(seen_opts) == 0 and len(known_opts) == 0)
        
        # Compute weighted fingerprint score (0.0 = legitimate, 1.0 = spoofed)
        fingerprint_score = (
            0.35 * (0.0 if ttl_match else 1.0) +
            0.25 * (0.0 if window_match else 1.0) +
            0.20 * (0.0 if options_match else 1.0) +
            0.20 * (0.0 if timing_ok else 1.0)
        )
        
        # MAC conflict detection (definitive spoof indicator on local LAN)
        mac_conflict = len(self._mac_addresses.get(src_ip, set())) > 1
        
        # Determine verdict
        if mac_conflict:
            verdict = 'CONFIRMED_SPOOF'
        elif fingerprint_score > 0.5:
            verdict = 'SUSPECTED_SPOOF'
        else:
            verdict = 'LEGITIMATE'
        
        # Store result
        self._latest_results[src_ip] = {
            'src_ip': src_ip,
            'fingerprint_score': round(fingerprint_score, 4),
            'ttl_seen': pkt_ttl,
            'ttl_expected': self.fingerprint['ttl'],
            'window_seen': pkt_window,
            'window_expected': self.fingerprint['tcp_window'],
            'options_seen': pkt_options,
            'mss_seen': pkt_mss,
            'inter_arrival_s': round(inter_arrival, 3) if inter_arrival else None,
            'timing_ok': timing_ok,
            'mac_addresses': list(self._mac_addresses.get(src_ip, set())),
            'mac_conflict': mac_conflict,
            'packet_count': self._packet_counts[src_ip],
            'verdict': verdict,
            'last_seen': now,
        }
        
        if verdict != 'LEGITIMATE':
            logger.warning(f'[FINGERPRINT] {verdict} for {src_ip}: '
                          f'TTL={pkt_ttl}(expect {self.fingerprint["ttl"]}), '
                          f'Window={pkt_window}(expect {self.fingerprint["tcp_window"]}), '
                          f'score={fingerprint_score:.3f}, MAC_conflict={mac_conflict}')

    def get_latest_result(self, src_ip: str = None) -> dict:
        """Get the latest fingerprint analysis result for a given IP."""
        ip = src_ip or self.target_ip
        with self._lock:
            result = self._latest_results.get(ip)
            if result:
                return dict(result)  # return a copy
        # Default result when no packets analyzed yet
        return {
            'src_ip': ip,
            'fingerprint_score': 0.0,
            'ttl_seen': None,
            'window_seen': None,
            'timing_ok': True,
            'mac_conflict': False,
            'verdict': 'UNKNOWN',
            'packet_count': 0,
        }

    def get_packet_counts(self) -> dict:
        """Return packet counts per source IP."""
        with self._lock:
            return dict(self._packet_counts)

    def get_all_mac_addresses(self) -> dict:
        """Return MAC addresses seen per IP."""
        with self._lock:
            return {ip: list(macs) for ip, macs in self._mac_addresses.items()}

    @property
    def is_running(self) -> bool:
        """Check if the sniffer is running."""
        return self._running
