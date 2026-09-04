#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MODULE BRIEFING: attack_controller.py — Unified Attack Control Center     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PURPOSE:   CLI menu for launching and managing all attack types against   ║
║             the SmartGrid MQTT testbed.                                    ║
║  INPUTS:    User menu selections, attack parameters                       ║
║  OUTPUTS:   Launches attack subprocesses, sends MQTT commands              ║
║  REQUIRES:  paho-mqtt (for FDI commands), sudo for IP spoof/replay        ║
╚══════════════════════════════════════════════════════════════════════════════╝

RESEARCH DISCLAIMER:
    This script is for academic research purposes only.
    Use only on networks and devices you own and control.
    All attacks target a controlled lab network (192.168.1.0/24).

ATTACK TYPES MANAGED:
    1. FDI via MQTT Command — Tells the ESP32 to falsify its own readings
    2. IP Spoofing — Sends forged MQTT PUBLISH packets (Scapy)
    3. Replay Attack — Captures and replays legitimate packets (Scapy)
"""

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("[WARNING] paho-mqtt not installed. FDI commands won't work.")
    print("[WARNING] Run: pip install paho-mqtt")
    mqtt = None

# ═══════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════

BROKER_IP = "192.168.1.100"
BROKER_PORT = 1883
CMD_TOPIC = "smartgrid/node01/cmd"
ALERTS_TOPIC = "smartgrid/alerts"
SCRIPT_DIR = Path(__file__).parent


# ═══════════════════════════════════════════════════════
# ATTACK PROCESS MANAGER
# ═══════════════════════════════════════════════════════

class AttackManager:
    """Manages attack subprocesses and MQTT command interface."""
    
    def __init__(self):
        self.active_attacks = {}  # {name: subprocess.Popen}
        self.mqtt_client = None
        self._setup_mqtt()
    
    def _setup_mqtt(self):
        """Initialize MQTT client for sending FDI commands."""
        if mqtt is None:
            return
        try:
            self.mqtt_client = mqtt.Client(client_id='attack_controller')
            self.mqtt_client.connect(BROKER_IP, BROKER_PORT, keepalive=60)
            self.mqtt_client.loop_start()
            print(f"[MQTT] Connected to broker at {BROKER_IP}:{BROKER_PORT}")
        except Exception as e:
            print(f"[MQTT] Connection failed: {e}")
            print("[MQTT] FDI commands will not work. Spoof/Replay still available.")
            self.mqtt_client = None
    
    def _send_mqtt_cmd(self, cmd_dict: dict):
        """Send a command to the ESP32 via MQTT."""
        if self.mqtt_client is None:
            print("[ERROR] MQTT client not connected. Cannot send command.")
            return False
        try:
            payload = json.dumps(cmd_dict)
            result = self.mqtt_client.publish(CMD_TOPIC, payload, qos=1)
            result.wait_for_publish(timeout=5)
            print(f"[MQTT] Sent command: {payload}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send MQTT command: {e}")
            return False
    
    # ═══════════════════════════════════════════════════
    # ATTACK LAUNCHERS
    # ═══════════════════════════════════════════════════
    
    def launch_fdi_attack(self):
        """Send FDI injection command to ESP32 via MQTT."""
        print("\n--- FDI Firmware Attack Configuration ---")
        try:
            voltage_scale = float(input("  Voltage scale factor [1.5]: ").strip() or "1.5")
            current_scale = float(input("  Current scale factor [0.3]: ").strip() or "0.3")
            duration = int(input("  Duration in seconds [60]: ").strip() or "60")
        except (ValueError, EOFError):
            print("[ERROR] Invalid input. Using defaults.")
            voltage_scale, current_scale, duration = 1.5, 0.3, 60
        
        cmd = {
            "cmd": "INJECT_FDI",
            "voltage": voltage_scale,
            "current": current_scale,
            "duration_s": duration
        }
        
        if self._send_mqtt_cmd(cmd):
            self.active_attacks['FDI_FIRMWARE'] = {
                'type': 'mqtt_cmd',
                'started': time.time(),
                'duration': duration,
                'params': cmd
            }
            print(f"[ATTACK] FDI firmware attack launched for {duration}s")
            print(f"[ATTACK] Voltage ×{voltage_scale}, Current ×{current_scale}")
    
    def launch_ip_spoof(self):
        """Launch IP spoofing attack as subprocess."""
        print("\n--- IP Spoofing Attack Configuration ---")
        try:
            duration = int(input("  Duration in seconds [60]: ").strip() or "60")
            interval = float(input("  Packet interval in seconds [5.0]: ").strip() or "5.0")
            voltage_scale = float(input("  Voltage scale [1.5]: ").strip() or "1.5")
            current_scale = float(input("  Current scale [0.1]: ").strip() or "0.1")
            advanced = input("  Advanced mode (valid HMAC)? [n]: ").strip().lower()
        except (ValueError, EOFError):
            duration, interval, voltage_scale, current_scale, advanced = 60, 5.0, 1.5, 0.1, 'n'
        
        script = SCRIPT_DIR / "attack_ip_spoof.py"
        if not script.exists():
            print(f"[ERROR] Script not found: {script}")
            return
        
        cmd = [
            "sudo", sys.executable, str(script),
            "--duration", str(duration),
            "--interval", str(interval),
            "--voltage-scale", str(voltage_scale),
            "--current-scale", str(current_scale),
        ]
        if advanced in ('y', 'yes'):
            cmd.append("--advanced-mode")
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            self.active_attacks['IP_SPOOF'] = {
                'type': 'subprocess',
                'process': proc,
                'started': time.time(),
                'duration': duration,
                'pid': proc.pid
            }
            print(f"[ATTACK] IP spoof attack launched (PID: {proc.pid})")
            
            # Print output in background (non-blocking)
            import threading
            def print_output():
                for line in proc.stdout:
                    print(f"  {line.rstrip()}")
            t = threading.Thread(target=print_output, daemon=True)
            t.start()
            
        except Exception as e:
            print(f"[ERROR] Failed to launch IP spoof: {e}")
    
    def launch_replay(self):
        """Launch replay attack as subprocess."""
        print("\n--- Replay Attack Configuration ---")
        try:
            duration = int(input("  Replay duration in seconds [60]: ").strip() or "60")
            interval = float(input("  Replay interval in seconds [5.0]: ").strip() or "5.0")
            capture_timeout = int(input("  Capture timeout in seconds [30]: ").strip() or "30")
        except (ValueError, EOFError):
            duration, interval, capture_timeout = 60, 5.0, 30
        
        script = SCRIPT_DIR / "attack_replay.py"
        if not script.exists():
            print(f"[ERROR] Script not found: {script}")
            return
        
        cmd = [
            "sudo", sys.executable, str(script),
            "--duration", str(duration),
            "--interval", str(interval),
            "--capture-timeout", str(capture_timeout),
        ]
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            self.active_attacks['REPLAY'] = {
                'type': 'subprocess',
                'process': proc,
                'started': time.time(),
                'duration': duration,
                'pid': proc.pid
            }
            print(f"[ATTACK] Replay attack launched (PID: {proc.pid})")
            
            import threading
            def print_output():
                for line in proc.stdout:
                    print(f"  {line.rstrip()}")
            t = threading.Thread(target=print_output, daemon=True)
            t.start()
            
        except Exception as e:
            print(f"[ERROR] Failed to launch replay: {e}")
    
    # ═══════════════════════════════════════════════════
    # ATTACK MANAGEMENT
    # ═══════════════════════════════════════════════════
    
    def stop_all_attacks(self):
        """Stop all running attacks."""
        print("\n[STOP] Stopping all attacks...")
        
        # Send STOP command to ESP32 (for FDI firmware attacks)
        self._send_mqtt_cmd({"cmd": "STOP_ATTACK"})
        
        # Kill all subprocesses
        killed = 0
        for name, info in list(self.active_attacks.items()):
            if info['type'] == 'subprocess':
                proc = info.get('process')
                if proc and proc.poll() is None:
                    try:
                        # Try graceful termination first
                        proc.terminate()
                        try:
                            proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait(timeout=2)
                        killed += 1
                        print(f"[STOP] Killed {name} (PID: {info['pid']})")
                    except Exception as e:
                        print(f"[STOP] Error killing {name}: {e}")
                        # Force kill with sudo
                        try:
                            os.system(f"sudo kill -9 {info['pid']}")
                            killed += 1
                        except Exception:
                            pass
        
        self.active_attacks.clear()
        print(f"[STOP] {killed} attack process(es) terminated")
        print("[STOP] ESP32 STOP_ATTACK command sent")
    
    def show_status(self):
        """Show status of all attacks."""
        print("\n╔══════════════════════════════════════════╗")
        print("║          ATTACK STATUS                   ║")
        print("╠══════════════════════════════════════════╣")
        
        if not self.active_attacks:
            print("║  No active attacks                       ║")
        else:
            for name, info in self.active_attacks.items():
                elapsed = time.time() - info['started']
                remaining = max(0, info['duration'] - elapsed)
                
                if info['type'] == 'subprocess':
                    proc = info.get('process')
                    alive = proc and proc.poll() is None
                    status = "RUNNING" if alive else "FINISHED"
                    pid_str = f"PID:{info['pid']}"
                else:
                    alive = remaining > 0
                    status = "ACTIVE" if alive else "EXPIRED"
                    pid_str = "MQTT"
                
                status_icon = "🔴" if alive else "⚫"
                print(f"║  {status_icon} {name:<15} | {status:<8} | "
                      f"{pid_str:<10} | {remaining:.0f}s left ║")
                
                # Clean up finished attacks
                if not alive:
                    del self.active_attacks[name]
        
        print("╚══════════════════════════════════════════╝")
    
    def cleanup(self):
        """Clean up resources on exit."""
        self.stop_all_attacks()
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()


# ═══════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════

def print_menu():
    """Print the main menu."""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║            SmartGrid Attack Controller                      ║
║            Target: {BROKER_IP}:{BROKER_PORT} (MQTT Broker)          ║
║            RESEARCH USE ONLY — Lab Network                  ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  1. FDI via MQTT Command (ESP32 falsifies own readings)     ║
║  2. IP Spoofing Attack (forged source IP packets)           ║
║  3. Replay Attack (capture + replay)                        ║
║  4. Stop All Attacks                                        ║
║  5. Status (show running attacks)                           ║
║  6. Exit                                                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def main():
    """Main entry point."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║       SmartGrid Attack Simulation Control Center            ║
║       Academic Research — Controlled Lab Environment        ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    manager = AttackManager()
    
    try:
        while True:
            print_menu()
            try:
                choice = input("  Select option [1-6]: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            
            if choice == '1':
                manager.launch_fdi_attack()
            elif choice == '2':
                manager.launch_ip_spoof()
            elif choice == '3':
                manager.launch_replay()
            elif choice == '4':
                manager.stop_all_attacks()
            elif choice == '5':
                manager.show_status()
            elif choice == '6':
                print("\n[EXIT] Shutting down attack controller...")
                break
            else:
                print("[ERROR] Invalid option. Please select 1-6.")
            
            # Small pause for output to flush
            time.sleep(0.5)
    
    except KeyboardInterrupt:
        print("\n[EXIT] Interrupted by user")
    finally:
        manager.cleanup()
        print("[EXIT] Attack controller shutdown complete.")


if __name__ == "__main__":
    main()
