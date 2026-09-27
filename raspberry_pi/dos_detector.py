"""
MODULE BRIEFING
---------------
DoS Attack Detection Module

This module monitors MQTT message rates per source IP address to detect Denial of Service (DoS) attacks.
It maintains a sliding window of message timestamps to calculate the current message rate for each IP.
When an IP exceeds the configured WARNING or CRITICAL thresholds, it triggers alerts.
If enabled, it can automatically block the offending IP using iptables (requires appropriate permissions)
and unblock it after a configured cooldown period.

Known trusted IPs (like EXPECTED_NODE_IP) are whitelisted and exempt from blocking.
"""

import logging
import time
import threading
import subprocess
from collections import defaultdict, deque

# Import configuration settings
# Note: These should be defined in config.py
try:
    from config import (
        DOS_RATE_WINDOW_S,
        DOS_WARNING_RATE,
        DOS_CRITICAL_RATE,
        DOS_BLOCK_DURATION_S,
        DOS_ENABLE_IPTABLES,
        EXPECTED_NODE_IP
    )
except ImportError:
    # Fallback defaults if not present in config.py
    DOS_RATE_WINDOW_S = 10
    DOS_WARNING_RATE = 10
    DOS_CRITICAL_RATE = 20
    DOS_BLOCK_DURATION_S = 300
    DOS_ENABLE_IPTABLES = False
    EXPECTED_NODE_IP = "10.59.53.251"

logger = logging.getLogger(__name__)

class DoSDetector:
    def __init__(self):
        self.rate_window = DOS_RATE_WINDOW_S
        self.warning_rate = DOS_WARNING_RATE
        self.critical_rate = DOS_CRITICAL_RATE
        self.block_duration = DOS_BLOCK_DURATION_S
        self.enable_iptables = DOS_ENABLE_IPTABLES
        
        # Message tracking: IP -> deque of timestamps
        self.message_history = defaultdict(deque)
        
        # Blocked IPs: IP -> unblock_timestamp
        self.blocked_ips = {}
        
        self.whitelist = {EXPECTED_NODE_IP, "127.0.0.1", "localhost"}
        
        # Statistics
        self.total_messages_processed = 0
        self.total_warnings = 0
        self.total_blocks = 0
        
        self.lock = threading.RLock()
        self.running = False
        self.monitor_thread = None

    def start(self):
        """Starts the background monitor thread."""
        with self.lock:
            if self.running:
                logger.warning("DoSDetector is already running.")
                return
            
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True, name="DoSMonitor")
            self.monitor_thread.start()
            logger.info(f"DoSDetector started. Window: {self.rate_window}s, Warn/Crit rates: {self.warning_rate}/{self.critical_rate} msg/s.")

    def stop(self):
        """Stops the background monitor thread."""
        with self.lock:
            if not self.running:
                return
            
            self.running = False
            
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
            
        logger.info("DoSDetector stopped.")

    def record_message(self, src_ip):
        """Records a message from a source IP."""
        if not src_ip:
            return

        now = time.time()
        with self.lock:
            self.total_messages_processed += 1
            
            # Don't track if already blocked (the firewall should drop it, but just in case)
            if src_ip in self.blocked_ips:
                return
                
            self.message_history[src_ip].append(now)

    def _monitor_loop(self):
        """Background loop to calculate rates, apply blocks, and unblock expired IPs."""
        while self.running:
            try:
                self._check_rates()
                self._process_unblocks()
            except Exception as e:
                logger.error(f"Error in DoS monitor loop: {e}", exc_info=True)
            
            time.sleep(1.0)  # Check every second

    def _check_rates(self):
        """Calculates current rates and applies thresholds."""
        now = time.time()
        cutoff_time = now - self.rate_window
        
        with self.lock:
            ips_to_check = list(self.message_history.keys())
            
            for ip in ips_to_check:
                history = self.message_history[ip]
                
                # Remove old timestamps
                while history and history[0] < cutoff_time:
                    history.popleft()
                    
                # If history is empty, we can clean up the dict entry
                if not history:
                    del self.message_history[ip]
                    continue
                
                # Calculate rate
                msg_count = len(history)
                rate = msg_count / float(self.rate_window)
                
                # Check thresholds
                if rate >= self.critical_rate:
                    if ip not in self.whitelist:
                        self._apply_block(ip, rate)
                    else:
                        logger.warning(f"CRITICAL DoS rate from whitelisted IP {ip}: {rate:.2f} msg/s")
                elif rate >= self.warning_rate:
                    if ip not in self.whitelist:
                        self.total_warnings += 1
                        logger.warning(f"WARNING DoS rate from IP {ip}: {rate:.2f} msg/s")

    def _apply_block(self, ip, rate):
        """Blocks an IP address."""
        now = time.time()
        self.blocked_ips[ip] = now + self.block_duration
        self.total_blocks += 1
        
        # Clear history since they are now blocked
        if ip in self.message_history:
            del self.message_history[ip]
            
        logger.critical(f"DoS ATTACK DETECTED! Blocking IP {ip}. Rate: {rate:.2f} msg/s. Duration: {self.block_duration}s.")
        
        if self.enable_iptables:
            try:
                # Require sudo/root privileges or CAP_NET_ADMIN
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, check=True, capture_output=True, text=True)
                logger.info(f"Successfully added iptables drop rule for {ip}.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to add iptables rule for {ip}. Error: {e.stderr}")
            except FileNotFoundError:
                logger.error("iptables command not found. Cannot block IP.")
        else:
            logger.info(f"iptables blocking is disabled in config. IP {ip} flagged but not blocked at OS level.")

    def _process_unblocks(self):
        """Unblocks IPs whose block duration has expired."""
        now = time.time()
        unblock_list = []
        
        with self.lock:
            for ip, unblock_time in list(self.blocked_ips.items()):
                if now >= unblock_time:
                    unblock_list.append(ip)
                    
            for ip in unblock_list:
                del self.blocked_ips[ip]
                
        for ip in unblock_list:
            logger.info(f"Block duration expired for {ip}. Unblocking.")
            if self.enable_iptables:
                try:
                    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    logger.info(f"Successfully removed iptables drop rule for {ip}.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to remove iptables rule for {ip}. Error: {e.stderr}")

    def get_status(self):
        """Returns a dictionary with the current status of the DoS detector."""
        now = time.time()
        cutoff_time = now - self.rate_window
        
        current_rates = {}
        with self.lock:
            for ip, history in self.message_history.items():
                # Count valid timestamps for accurate current reporting
                valid_count = sum(1 for t in history if t >= cutoff_time)
                rate = valid_count / float(self.rate_window)
                if rate > 0:
                    current_rates[ip] = round(rate, 2)
                    
            blocked_info = {
                ip: round(unblock_time - now, 1) 
                for ip, unblock_time in self.blocked_ips.items()
            }
            
            return {
                "running": self.running,
                "current_rates_msg_per_sec": current_rates,
                "blocked_ips_time_remaining": blocked_info,
                "total_messages_processed": self.total_messages_processed,
                "total_warnings": self.total_warnings,
                "total_blocks": self.total_blocks,
                "thresholds": {
                    "warning": self.warning_rate,
                    "critical": self.critical_rate,
                    "window_s": self.rate_window
                }
            }
