"""
MODULE BRIEFING
---------------
Module: twin_simulator
Purpose: Main entry point for the Digital Twin simulator.
Runs standalone or MQTT mode, generating telemetry via scenario engine.
"""

import argparse
import time
import json
import hmac
import hashlib
from power_grid_model import PowerGridModel
from scenario_engine import ScenarioEngine
try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

SECRET_KEY = 'smartgrid_secret_key_2025'.encode('utf-8')

BANNER = r'''
  ____                      _    ____      _     _   
 / ___| _ __ ___   __ _ _ __| |_ / ___| ___(_) __| |  
 \___ \| '_ ` _ \ / _` | '__| __| |  _ / _ \ |/ _` |  
  ___) | | | | | | (_| | |  | |_| |_| |  __/ | (_| |  
 |____/|_| |_| |_|\__,_|_|   \__|\____|\___|_|\__,_|  
                                                      
   Digital Twin Simulator - FDIA Shield
'''

def calculate_hmac(payload_dict):
    payload_str = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True)
    return hmac.new(SECRET_KEY, payload_str.encode('utf-8'), hashlib.sha256).hexdigest()

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[+] Connected to MQTT Broker successfully")
    else:
        print(f"[-] Failed to connect, return code {rc}")

def run_simulator(args):
    print(BANNER)
    
    if args.list_scenarios:
        print("Available Scenarios:")
        for s in ScenarioEngine.list_scenarios():
            print(f"  - {s}")
        return

    interval = 0.1 if args.pmu_mode else args.interval
    topic = args.topic or f"smartgrid/{args.node_id}/telemetry"

    print(f"[*] Starting simulator in {args.mode.upper()} mode.")
    print(f"[*] Node ID: {args.node_id} | Topic: {topic}")
    print(f"[*] Scenario: {args.scenario}")
    print(f"[*] Interval: {interval}s ({'Virtual PMU 10Hz Synchrophasor Stream' if args.pmu_mode else 'Standard Mode'})")

    grid = PowerGridModel()
    engine = ScenarioEngine(grid)
    
    client = None
    
    if args.mode == 'mqtt':
        if mqtt is None:
            print("[-] paho-mqtt not installed. Please pip install paho-mqtt")
            return
            
        print(f"[*] Connecting to broker {args.broker}:{args.port}")
        client = mqtt.Client(client_id=f"twin_{args.node_id}_{int(time.time())}")
        client.on_connect = on_connect
        try:
            client.connect(args.broker, args.port, 60)
            client.loop_start()
        except Exception as e:
            print(f"[-] MQTT Connection failed: {e}")
            return

    seq_counter = 0
    try:
        scenario_gen = engine.run_scenario(args.scenario, interval)
        for timestamp, readings, is_attack, attack_type in scenario_gen:
            seq_counter += 1
            payload = {
                'node_id': args.node_id,
                'timestamp': int(time.time()),
                'seq': seq_counter,
                'voltage_V': readings['voltage_V'],
                'current_A': readings['current_A'],
                'power_W': readings['power_W'],
                'energy_Wh': readings['energy_Wh'],
                'frequency_Hz': readings['frequency_Hz'],
                'power_factor': readings['power_factor'],
                'phase_angle_deg': readings.get('phase_angle_deg', 0.0),
                'rocof_Hz_s': readings.get('rocof_Hz_s', 0.0),
            }
            
            # Generate valid HMAC matching ArduinoJson / Python HMAC verifier
            signature = calculate_hmac(payload)
            payload['hmac'] = signature
            
            # Color-coded output
            status_color = '\033[91m' if is_attack else '\033[92m'
            end_color = '\033[0m'
            
            pmu_str = f"δ:{readings.get('phase_angle_deg', 0.0):+.2f}° df/dt:{readings.get('rocof_Hz_s', 0.0):+.3f}"
            print(f"[{timestamp}][Seq:{seq_counter}] {status_color}{'ATTACK' if is_attack else 'CLEAN'} ({attack_type}){end_color} | "
                  f"V:{readings['voltage_V']:.1f}V I:{readings['current_A']:.3f}A P:{readings['power_W']:.1f}W | {pmu_str}")
            
            if args.mode == 'mqtt' and client:
                client.publish(topic, json.dumps(payload))
                
            time.sleep(interval if args.scenario != 'dos_flood' else 0.05)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping simulator...")
    finally:
        if client:
            client.loop_stop()
            client.disconnect()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SmartGrid Digital Twin Simulator")
    parser.add_argument('--mode', choices=['mqtt', 'standalone'], default='standalone', help="Run mode")
    parser.add_argument('--broker', default='10.59.53.30', help="MQTT broker IP")
    parser.add_argument('--port', type=int, default=1883, help="MQTT broker port")
    parser.add_argument('--topic', default=None, help="Target MQTT topic (e.g. smartgrid/node01/telemetry)")
    parser.add_argument('--scenario', default='normal', help="Simulation scenario to run")
    parser.add_argument('--interval', type=float, default=5.0, help="Publish interval in seconds")
    parser.add_argument('--node-id', default='twin_01', help="Node ID to simulate")
    parser.add_argument('--pmu-mode', action='store_true', help="High-frequency Synchrophasor PMU mode (100ms / 10 Hz)")
    parser.add_argument('--list-scenarios', action='store_true', help="List available scenarios")
    
    args = parser.parse_args()
    run_simulator(args)
