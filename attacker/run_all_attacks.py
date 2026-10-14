#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MODULE: run_all_attacks.py — Automated Multi-Attack Test Suite for Kali    ║
║  PURPOSE: Executes full multi-vector attack sequence sequentially,           ║
║           logs epoch timestamps for automated ground-truth scoring,          ║
║           and verifies SmartGrid FDIA Shield detection & recovery.           ║
║  REQUIRES: sudo / root on Kali Linux, paho-mqtt, scapy                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Auto-elevate to root if not already root
if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() != 0:
    print("[*] run_all_attacks requires root privileges for Scapy raw socket packet injection.")
    print("[*] Re-launching with sudo...")
    try:
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
    except Exception as e:
        print(f"[ERROR] Auto-elevation failed: {e}")
        sys.exit(1)

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("[ERROR] paho-mqtt is required. Run: pip install paho-mqtt")
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent

class AutomatedAttackSuite:
    def __init__(self, broker_ip: str, esp32_ip: str, modbus_port: int = 5020, quick_mode: bool = False):
        self.broker_ip = broker_ip
        self.esp32_ip = esp32_ip
        self.modbus_port = modbus_port
        self.quick = quick_mode
        self.phase_duration = 20 if quick_mode else 45
        self.cooldown_duration = 10 if quick_mode else 15
        
        self.cmd_topic = "smartgrid/node01/cmd"
        self.mqtt_client = None
        self.manifest = []
        self._setup_mqtt()

    def _setup_mqtt(self):
        try:
            self.mqtt_client = mqtt.Client(client_id="kali_attack_automator")
            self.mqtt_client.connect(self.broker_ip, 1883, keepalive=60)
            self.mqtt_client.loop_start()
            print(f"[+] MQTT connected to broker {self.broker_ip}:1883")
        except Exception as e:
            print(f"[-] MQTT connection failed: {e}")
            self.mqtt_client = None

    def send_cmd(self, cmd_dict: dict):
        if not self.mqtt_client:
            return False
        payload = json.dumps(cmd_dict)
        res = self.mqtt_client.publish(self.cmd_topic, payload, qos=1)
        res.wait_for_publish(timeout=5)
        print(f"  [MQTT CMD] -> {payload}")
        return True

    def countdown(self, seconds: int, phase_name: str):
        for remaining in range(seconds, 0, -1):
            sys.stdout.write(f"\r  [{phase_name}] {remaining:3d}s remaining... ")
            sys.stdout.flush()
            time.sleep(1)
        sys.stdout.write(f"\r  [{phase_name}] Completed!{' ' * 20}\n")
        sys.stdout.flush()

    def record_phase(self, name: str, start_ts: float, end_ts: float, desc: str):
        self.manifest.append({
            'phase': name,
            'start_epoch': start_ts,
            'end_epoch': end_ts,
            'duration_s': round(end_ts - start_ts, 2),
            'start_iso': datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S'),
            'end_iso': datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S'),
            'description': desc
        })

    def run_all(self):
        print("""
╔══════════════════════════════════════════════════════════════╗
║     SmartGrid FDIA Shield — Automated End-to-End Suite       ║
║     Executing 7 Attack Vectors + Clean Baseline Logging      ║
╚══════════════════════════════════════════════════════════════╝
""")
        print(f"Broker IP:       {self.broker_ip}")
        print(f"ESP32 IP:        {self.esp32_ip}")
        print(f"Phase Duration:  {self.phase_duration}s per attack")
        print(f"Cooldown:        {self.cooldown_duration}s between phases")
        print("=" * 64)

        suite_start = time.time()

        # -------------------------------------------------------------
        # PHASE 0: Clean Baseline Telemetry
        # -------------------------------------------------------------
        print("\n[PHASE 0] Collecting Clean Baseline Telemetry (No Attacks)")
        t0 = time.time()
        self.send_cmd({"cmd": "STOP_ATTACK"})
        self.countdown(self.phase_duration, "BASELINE")
        t1 = time.time()
        self.record_phase("BASELINE", t0, t1, "Clean operation without attacks")

        # -------------------------------------------------------------
        # PHASE 1: FDI Overvoltage Attack (345V)
        # -------------------------------------------------------------
        print("\n[PHASE 1] FDI Firmware Attack: Severe Overvoltage (345V Spike)")
        t0 = time.time()
        self.send_cmd({
            "cmd": "INJECT_FDI",
            "voltage": 1.5,
            "current": 0.3,
            "duration_s": self.phase_duration + 5
        })
        self.countdown(self.phase_duration, "FDI_OVERVOLTAGE")
        self.send_cmd({"cmd": "STOP_ATTACK"})
        t1 = time.time()
        self.record_phase("FDI_OVERVOLTAGE", t0, t1, "FDI injection 345V overvoltage via firmware")

        print("  [Cooldown] Allowing baseline stabilization...")
        self.countdown(self.cooldown_duration, "COOLDOWN")

        # -------------------------------------------------------------
        # PHASE 2: FDI Subtle Power Manipulation (+5%)
        # -------------------------------------------------------------
        print("\n[PHASE 2] FDI Firmware Attack: Subtle Parameter Manipulation (+5%)")
        t0 = time.time()
        self.send_cmd({
            "cmd": "INJECT_FDI",
            "voltage": 1.05,
            "current": 1.05,
            "power": 1.05,
            "duration_s": self.phase_duration + 5
        })
        self.countdown(self.phase_duration, "FDI_SUBTLE")
        self.send_cmd({"cmd": "STOP_ATTACK"})
        t1 = time.time()
        self.record_phase("FDI_SUBTLE", t0, t1, "Subtle +5% scaling across V, I, P")

        print("  [Cooldown] Allowing baseline stabilization...")
        self.countdown(self.cooldown_duration, "COOLDOWN")

        # -------------------------------------------------------------
        # PHASE 3: IP Spoofing (Standard - Invalid HMAC)
        # -------------------------------------------------------------
        print("\n[PHASE 3] IP Spoofing Attack: Forged ESP32 IP with Invalid HMAC")
        script = SCRIPT_DIR / "attack_ip_spoof.py"
        cmd = [
            sys.executable, str(script),
            "--duration", str(self.phase_duration),
            "--interval", "5.0",
            "--voltage-scale", "1.5",
            "--current-scale", "0.1",
            "--target-ip", self.broker_ip,
            "--spoof-ip", self.esp32_ip
        ]
        t0 = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.countdown(self.phase_duration, "IP_SPOOF_STD")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        t1 = time.time()
        self.record_phase("IP_SPOOF_STD", t0, t1, "Layer 3/4 IP spoofing with forged source IP and invalid HMAC")

        print("  [Cooldown] Waiting for ARP cache restore...")
        self.countdown(self.cooldown_duration + 5, "COOLDOWN")

        # -------------------------------------------------------------
        # PHASE 4: IP Spoofing (Advanced - Valid HMAC Insider Threat)
        # -------------------------------------------------------------
        print("\n[PHASE 4] IP Spoofing Attack: Forged ESP32 IP with Valid HMAC (Insider Threat)")
        cmd = [
            sys.executable, str(script),
            "--duration", str(self.phase_duration),
            "--interval", "5.0",
            "--voltage-scale", "1.5",
            "--current-scale", "0.1",
            "--target-ip", self.broker_ip,
            "--spoof-ip", self.esp32_ip,
            "--advanced-mode"
        ]
        t0 = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.countdown(self.phase_duration, "IP_SPOOF_ADV")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        t1 = time.time()
        self.record_phase("IP_SPOOF_ADV", t0, t1, "IP spoofing with forged IP and legitimate HMAC signature")

        print("  [Cooldown] Waiting for ARP cache restore...")
        self.countdown(self.cooldown_duration + 5, "COOLDOWN")

        # -------------------------------------------------------------
        # PHASE 5: Replay Attack (Frozen Values)
        # -------------------------------------------------------------
        print("\n[PHASE 5] Replay Attack: Sniffed Packet Injection")
        script = SCRIPT_DIR / "attack_replay.py"
        cmd = [
            sys.executable, str(script),
            "--duration", str(self.phase_duration),
            "--interval", "5.0",
            "--capture-timeout", "20",
            "--target-ip", self.broker_ip,
            "--esp32-ip", self.esp32_ip
        ]
        t0 = time.time()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.countdown(self.phase_duration, "REPLAY")
            proc.terminate()
            proc.wait(timeout=3)
        except Exception as e:
            print(f"  [-] Replay process error: {e}")
        t1 = time.time()
        self.record_phase("REPLAY", t0, t1, "Replaying static captured packet with frozen sequence")

        print("  [Cooldown] Allowing baseline stabilization...")
        self.countdown(self.cooldown_duration, "COOLDOWN")

        # -------------------------------------------------------------
        # PHASE 6: Industrial Modbus TCP SCADA Injection & Breaker Trip
        # -------------------------------------------------------------
        print("\n[PHASE 6] Industrial Modbus TCP SCADA Tampering & Breaker Trip")
        script = SCRIPT_DIR / "attack_modbus.py"
        t0 = time.time()
        # 1. Reconnaissance
        subprocess.run([sys.executable, str(script), "--target", self.broker_ip, "--port", str(self.modbus_port), "--action", "recon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # 2. Trip breaker coil
        subprocess.run([sys.executable, str(script), "--target", self.broker_ip, "--port", str(self.modbus_port), "--action", "trip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # 3. Inject forged voltage into holding register 40001
        subprocess.run([sys.executable, str(script), "--target", self.broker_ip, "--port", str(self.modbus_port), "--action", "inject", "--reg", "40001", "--val", "285.0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.countdown(self.phase_duration // 2, "MODBUS_ATTACK")
        # 4. Re-close breaker to restore grid feeder
        subprocess.run([sys.executable, str(script), "--target", self.broker_ip, "--port", str(self.modbus_port), "--action", "close"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t1 = time.time()
        self.record_phase("MODBUS_SCADA", t0, t1, "Unauthorized Modbus TCP coil trip and register overwrite")

        print("  [Cooldown] Allowing baseline stabilization...")
        self.countdown(self.cooldown_duration, "COOLDOWN")

        # -------------------------------------------------------------
        # PHASE 7: DoS Message Rate Flood
        # -------------------------------------------------------------
        print("\n[PHASE 7] DoS Message Rate Flood Attack")
        script = SCRIPT_DIR / "attack_dos.py"
        cmd = [
            sys.executable, str(script),
            "--target", self.broker_ip,
            "--port", "1883",
            "--duration", str(self.phase_duration),
            "--threads", "5",
            "--rate", "20",
            "--no-confirm"
        ]
        t0 = time.time()
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.countdown(self.phase_duration, "DOS_FLOOD")
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        t1 = time.time()
        self.record_phase("DOS_FLOOD", t0, t1, "High-rate MQTT publish flood (100 msg/s)")

        # -------------------------------------------------------------
        # SUMMARY & MANIFEST EXPORT
        # -------------------------------------------------------------
        suite_end = time.time()
        total_time = round(suite_end - suite_start, 1)

        print("\n" + "═" * 68)
        print("                 ALL ATTACK PHASES COMPLETED                  ")
        print("═" * 68)
        print(f"Total Test Time: {total_time}s")
        print(f"{'Phase Name':<16} | {'Start Time':<19} | {'Duration':<8} | Status")
        print("-" * 68)
        for item in self.manifest:
            print(f"{item['phase']:<16} | {item['start_iso']:<19} | {item['duration_s']:>6}s | COMPLETED")
        print("═" * 68)

        manifest_file = SCRIPT_DIR / "test_manifest.json"
        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump({
                "suite_start": suite_start,
                "suite_end": suite_end,
                "broker_ip": self.broker_ip,
                "esp32_ip": self.esp32_ip,
                "phases": self.manifest
            }, f, indent=2)
        print(f"\n[✓] Test session manifest saved to: {manifest_file}")
        print(f"[*] Use start epoch: {int(suite_start)} when generating plots on Raspberry Pi:")
        print(f"    python3 analysis.py --since {int(suite_start)}")

def main():
    parser = argparse.ArgumentParser(description="SmartGrid Automated Attack Suite for Kali Linux")
    parser.add_argument("--broker", default="10.175.107.30", help="Raspberry Pi Broker IP")
    parser.add_argument("--esp32", default="10.175.107.251", help="ESP32 Sensor IP")
    parser.add_argument("--port", type=int, default=5020, help="Modbus TCP Port")
    parser.add_argument("--quick", action="store_true", help="Quick run mode (20s per attack instead of 45s)")
    args = parser.parse_args()

    suite = AutomatedAttackSuite(
        broker_ip=args.broker,
        esp32_ip=args.esp32,
        modbus_port=args.port,
        quick_mode=args.quick
    )
    suite.run_all()

if __name__ == "__main__":
    main()
