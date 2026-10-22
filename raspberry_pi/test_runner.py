"""
MODULE BRIEFING:
Purpose: Orchestrates all 6 test scenarios sequentially, logs results, and produces a test report.
Inputs: Configuration files, DB access, SSH to attacker laptop, MQTT commands.
Outputs: Console output, JSON test report, database records.
Dependencies: paho-mqtt, config, db_manager (local project modules), standard library modules.

Research Disclaimer: This code is designed for a controlled academic testbed environment.
"""

import json
import time
import subprocess
import sys
import os
import logging
from pathlib import Path
from datetime import datetime

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

logger = logging.getLogger(__name__)

# Import project modules
from config import *
from db_manager import DatabaseManager


class TestRunner:
    def __init__(self, db_path=None, attacker_scripts_dir=None):
        """Initialize the TestRunner with database and configurations."""
        self.db = DatabaseManager(db_path)
        
        # Auto-detect local attacker scripts directory on Pi or fallback
        candidates = [
            attacker_scripts_dir,
            Path(__file__).resolve().parent.parent / "attacker",
            Path(__file__).resolve().parent / "attacker",
            Path("/home/smartgrid/Desktop/Project/Smartgrid-FDIA-Shield/attacker"),
            Path("/home/smartgrid/smartgrid/attacker"),
            Path("/home/attacker")
        ]
        self.attacker_dir = None
        for cand in candidates:
            if cand and Path(cand).exists() and (Path(cand) / "attack_ip_spoof.py").exists():
                self.attacker_dir = Path(cand)
                break
        if not self.attacker_dir:
            self.attacker_dir = Path('/home/attacker')
            
        print(f"[*] Attacker scripts directory: {self.attacker_dir}")
        self.mqtt_client = None
        self.results = {}
        self._setup_mqtt()

    def _run_attacker_script(self, script_name: str, args: list, attacker_host: str, duration: int, label: str):
        """Execute attacker script locally on Pi if available, else fallback to SSH."""
        local_script = self.attacker_dir / script_name if self.attacker_dir else None
        if local_script and local_script.exists():
            print(f'  [LOCAL ATTACK] Running {script_name} locally: {" ".join(args)}')
            cmd = ["sudo", sys.executable, str(local_script)] + args
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._wait_with_countdown(duration, label)
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                return
            except Exception as e:
                print(f'  [-] Local execution failed: {e}')

        # SSH fallback
        ssh_cmd = f'ssh attacker@{attacker_host} "sudo python3 /home/attacker/{script_name} {" ".join(args)}"'
        print(f'  [SSH] {ssh_cmd}')
        try:
            proc = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._wait_with_countdown(duration + 5, label)
            proc.terminate()
        except Exception as e:
            print(f'  [WARNING] SSH launch failed: {e}')
            self._wait_with_countdown(duration, label)
    
    def _setup_mqtt(self):
        """Set up MQTT connection for sending attack commands to ESP32."""
        if mqtt:
            try:
                self.mqtt_client = mqtt.Client('test_runner')
                self.mqtt_client.connect(MQTT_BROKER_IP, MQTT_PORT)
                self.mqtt_client.loop_start()
            except Exception as e:
                logger.error(f'MQTT setup failed: {e}')
    
    def _send_cmd(self, cmd_dict):
        """Publish a command to the MQTT command topic."""
        if self.mqtt_client:
            self.mqtt_client.publish(MQTT_TOPIC_CMD, json.dumps(cmd_dict), qos=1)
    
    def _wait_with_countdown(self, seconds, label=''):
        """Wait for a specific duration with a visible countdown."""
        for remaining in range(seconds, 0, -1):
            print(f'\r  [{label}] {remaining}s remaining...', end='', flush=True)
            time.sleep(1)
        print(f'\r  [{label}] Complete!{" " * 30}')
    
    def _get_scenario_results(self, start_time, end_time) -> dict:
        """Query DB for detection results in a time window."""
        results = self.db.get_all_detection_results(since_timestamp=start_time)
        # Filter to our window
        window_results = [r for r in results if r.get('timestamp', 0) <= end_time]
        
        total = len(window_results)
        normal = sum(1 for r in window_results if r.get('status') == 'NORMAL')
        suspicious = sum(1 for r in window_results if r.get('status') == 'SUSPICIOUS')
        attack = sum(1 for r in window_results if r.get('status') == 'ATTACK_DETECTED')
        
        # Detection latency: time from first attack packet to first ATTACK_DETECTED
        attack_results = [r for r in window_results if r.get('status') == 'ATTACK_DETECTED']
        first_attack_time = attack_results[0]['timestamp'] if attack_results else None
        
        # Attack type breakdown
        attack_types = {}
        for r in window_results:
            at = r.get('attack_type')
            if at:
                attack_types[at] = attack_types.get(at, 0) + 1
        
        # Dominant detector
        max_scores = {'physics': 0, 'zscore': 0, 'ml': 0, 'hmac': 0, 'fingerprint': 0}
        for r in attack_results:
            max_scores['physics'] = max(max_scores['physics'], r.get('physics_score', 0))
            max_scores['zscore'] = max(max_scores['zscore'], r.get('z_score_normalized', 0))
            max_scores['ml'] = max(max_scores['ml'], r.get('ml_score', 0))
            max_scores['hmac'] = max(max_scores['hmac'], r.get('hmac_score', 0))
            max_scores['fingerprint'] = max(max_scores['fingerprint'], r.get('fingerprint_score', 0))
        dominant = max(max_scores, key=max_scores.get) if attack_results else 'N/A'
        
        return {
            'total_packets': total,
            'normal': normal,
            'suspicious': suspicious,
            'attack_detected': attack,
            'true_positives': attack,  # In attack scenarios
            'false_positives': attack if total == normal + attack else 0,  # In baseline
            'detection_latency_s': None,  # Filled by caller
            'attack_types': attack_types,
            'dominant_detector': dominant,
            'max_scores': max_scores,
        }
    
    # ═══════════════════════════════════════════════
    # SCENARIOS
    # ═══════════════════════════════════════════════
    
    def scenario_1_baseline(self, duration=300):
        """Scenario 1: Baseline (no attack) — collect clean data."""
        print('\n' + '='*60)
        print('SCENARIO 1 — BASELINE (No Attack)')
        print(f'Duration: {duration}s')
        print('Expected: All NORMAL, confidence < 0.3')
        print('='*60)
        
        start = int(time.time())
        self._wait_with_countdown(duration, 'BASELINE')
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        results['false_positives'] = results['attack_detected']  # Any attack in baseline is FP
        self.results['scenario_1'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["normal"]} normal, {results["false_positives"]} false positives')
        return results
    
    def scenario_2_fdi_voltage_spike(self, duration=60):
        """Scenario 2: FDI firmware voltage spike (1.5x)."""
        print('\n' + '='*60)
        print('SCENARIO 2 — FDI FIRMWARE VOLTAGE SPIKE (1.5x)')
        print(f'Duration: {duration}s')
        print('Expected: Physics check fires, ATTACK_DETECTED, type=FDI_FIRMWARE')
        print('='*60)
        
        start = int(time.time())
        self._send_cmd({'cmd': 'INJECT_FDI', 'voltage': 1.5, 'duration_s': duration})
        print('  [CMD] Sent INJECT_FDI voltage=1.5x')
        self._wait_with_countdown(duration, 'FDI_SPIKE')
        self._send_cmd({'cmd': 'STOP_ATTACK'})
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        self.results['scenario_2'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results
    
    def scenario_3_fdi_subtle(self, duration=60):
        """Scenario 3: Subtle FDI (5% scale on all params)."""
        print('\n' + '='*60)
        print('SCENARIO 3 — FDI FIRMWARE SUBTLE (5% scale)')
        print(f'Duration: {duration}s')
        print('Expected: Physics may pass, ML + Z-score catch it')
        print('='*60)
        
        start = int(time.time())
        self._send_cmd({'cmd': 'INJECT_FDI', 'voltage': 1.05, 'current': 1.05,
                       'power': 1.05, 'duration_s': duration})
        print('  [CMD] Sent INJECT_FDI voltage=1.05x current=1.05x power=1.05x')
        self._wait_with_countdown(duration, 'FDI_SUBTLE')
        self._send_cmd({'cmd': 'STOP_ATTACK'})
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        self.results['scenario_3'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results
    
    def scenario_4_ip_spoof(self, duration=60, attacker_host='10.59.53.200'):
        """Scenario 4: IP Spoofing attack."""
        print('\n' + '='*60)
        print('SCENARIO 4 — IP SPOOFING ATTACK')
        print(f'Duration: {duration}s')
        print('Expected: HMAC fails, ATTACK_DETECTED, type=TAMPERED_OR_SPOOFED')
        print('='*60)
        
        start = int(time.time())
        args = ["--duration", str(duration), "--target-ip", MQTT_BROKER_IP, "--spoof-ip", EXPECTED_NODE_IP]
        self._run_attacker_script("attack_ip_spoof.py", args, attacker_host, duration, "IP_SPOOF")
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        self.results['scenario_4'] = results
        
        spoof_summary = self.db.get_spoof_summary(since_timestamp=start)
        results['spoof_summary'] = spoof_summary
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected')
        if spoof_summary:
            print(f'  Spoof episodes: {spoof_summary.get("total_spoof_episodes", 0)}')
        return results
    
    def scenario_5_ip_spoof_advanced(self, duration=60, attacker_host='10.59.53.200'):
        """Scenario 5: IP Spoofing with valid HMAC (insider threat)."""
        print('\n' + '='*60)
        print('SCENARIO 5 — IP SPOOFING + VALID HMAC (Insider Threat)')
        print(f'Duration: {duration}s')
        print('Expected: HMAC passes, detection relies on fingerprint + physics')
        print('='*60)
        
        start = int(time.time())
        args = ["--duration", str(duration), "--target-ip", MQTT_BROKER_IP, "--spoof-ip", EXPECTED_NODE_IP, "--advanced-mode"]
        self._run_attacker_script("attack_ip_spoof.py", args, attacker_host, duration, "SPOOF_ADV")
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        self.results['scenario_5'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results
    
    def scenario_6_replay(self, duration=60, attacker_host='10.59.53.200'):
        """Scenario 6: Replay attack."""
        print('\n' + '='*60)
        print('SCENARIO 6 — REPLAY ATTACK')
        print(f'Duration: {duration}s')
        print('Expected: Stale seq/timestamp detected, type=REPLAY')
        print('='*60)
        
        start = int(time.time())
        args = ["--duration", str(duration), "--target-ip", MQTT_BROKER_IP, "--esp32-ip", EXPECTED_NODE_IP]
        self._run_attacker_script("attack_replay.py", args, attacker_host, duration, "REPLAY")
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        self.results['scenario_6'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results

    def scenario_7_modbus(self, duration=30, attacker_host='10.59.53.200'):
        """Scenario 7: Industrial Modbus TCP SCADA injection & breaker trip."""
        print('\n' + '='*60)
        print('SCENARIO 7 — INDUSTRIAL MODBUS TCP TAMPERING & BREAKER TRIP')
        print(f'Duration: {duration}s')
        print('Expected: Coil 00001 tripped, Reg 40001 tampered, SCADA Alert fired')
        print('='*60)
        
        start = int(time.time())
        local_script = (self.attacker_dir / "attack_modbus.py") if self.attacker_dir else None
        if local_script and local_script.exists():
            subprocess.run([sys.executable, str(local_script), "--target", MQTT_BROKER_IP, "--port", "5020", "--action", "trip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([sys.executable, str(local_script), "--target", MQTT_BROKER_IP, "--port", "5020", "--action", "inject", "--reg", "40001", "--val", "285.0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._wait_with_countdown(duration, "MODBUS_ATTACK")
            subprocess.run([sys.executable, str(local_script), "--target", MQTT_BROKER_IP, "--port", "5020", "--action", "close"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            self._wait_with_countdown(duration, "MODBUS_ATTACK")
            
        end = int(time.time())
        results = self._get_scenario_results(start, end)
        self.results['scenario_7'] = results
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected')
        return results

    def scenario_8_ramp(self, duration=40, attacker_host='10.59.53.200'):
        """Scenario 8: Stealth Monotonic Voltage Drift (Ramp Attack)."""
        print('\n' + '='*60)
        print('SCENARIO 8 — STEALTH FDI RAMP (Monotonic Voltage Drift)')
        print(f'Duration: {duration}s')
        print('Expected: Monotonic slope tracking / CUSUM catches gradual drift')
        print('='*60)
        
        start = int(time.time())
        args = ["--target-ip", MQTT_BROKER_IP, "--duration", str(duration), "--interval", "2.0", "--step", "0.8", "--advanced-mode"]
        self._run_attacker_script("attack_ramp.py", args, attacker_host, duration, "FDI_RAMP")
        end = int(time.time())
        
        results = self._get_scenario_results(start, end)
        self.results['scenario_8'] = results
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results
    
    # ═══════════════════════════════════════════════
    # ORCHESTRATION
    # ═══════════════════════════════════════════════
    
    def run_all(self, baseline_duration=120, attack_duration=30,
                gap_between_scenarios=20, attacker_host='10.59.53.200', auto_plot=True):
        """Run all 8 scenarios sequentially with gaps between them."""
        print('╔══════════════════════════════════════════════════╗')
        print('║  SmartGrid Test Runner — Full 8-Scenario Suite   ║')
        print('╚══════════════════════════════════════════════════╝')
        print(f'  Baseline: {baseline_duration}s')
        print(f'  Attack scenarios: {attack_duration}s each')
        print(f'  Gap between scenarios: {gap_between_scenarios}s')
        print(f'  Attacker host: {attacker_host}')
        total_time = baseline_duration + 7 * attack_duration + 8 * gap_between_scenarios
        print(f'  Estimated total time: {total_time // 60}m {total_time % 60}s')
        print()
        
        overall_start = time.time()
        
        # Phase 1: Baseline
        self.scenario_1_baseline(baseline_duration)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        # Phase 2: FDI Voltage Spike
        self.scenario_2_fdi_voltage_spike(attack_duration)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        # Phase 3: FDI Subtle
        self.scenario_3_fdi_subtle(attack_duration)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        # Phase 4: IP Spoof (Invalid HMAC)
        self.scenario_4_ip_spoof(attack_duration, attacker_host)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        # Phase 5: IP Spoof (Valid HMAC)
        self.scenario_5_ip_spoof_advanced(attack_duration, attacker_host)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        # Phase 6: Replay
        self.scenario_6_replay(attack_duration, attacker_host)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')

        # Phase 7: Industrial Modbus TCP
        self.scenario_7_modbus(attack_duration, attacker_host)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')

        # Phase 8: Stealth FDI Ramp
        self.scenario_8_ramp(attack_duration, attacker_host)
        
        overall_elapsed = time.time() - overall_start
        
        # Generate report
        self._print_summary_table()
        self._save_report(overall_elapsed)

        # Auto-generate all 11 IEEE scientific plots
        if auto_plot:
            try:
                from analysis import SmartGridAnalyzer
                print("\n[ANALYZER] Automatically generating all 11 scientific plots from test run...")
                analyzer = SmartGridAnalyzer()
                analyzer.generate_all_plots(since_timestamp=overall_start)
                analyzer.close()
            except Exception as e:
                logger.error(f"Plot generation failed: {e}")
                print(f"[!] Plot generation error: {e}")
    
    def _print_summary_table(self):
        """Print formatted results table."""
        print('\n' + '='*88)
        print('COMPLETE TEST RESULTS')
        print('='*88)
        
        header = f'{"Metric":<24} {"Sc1":>6} {"Sc2":>6} {"Sc3":>6} {"Sc4":>6} {"Sc5":>6} {"Sc6":>6} {"Sc7":>6} {"Sc8":>6}'
        print(header)
        print('-' * 88)
        
        for metric in ['total_packets', 'attack_detected', 'dominant_detector']:
            row = f'{metric:<24}'
            for i in range(1, 9):
                key = f'scenario_{i}'
                val = self.results.get(key, {}).get(metric, '-')
                row += f' {str(val):>6}'
            print(row)
        
        print('='*88)
    
    def _save_report(self, elapsed):
        """Save full test report to JSON."""
        report = {
            'test_run_timestamp': datetime.now().isoformat(),
            'total_elapsed_s': round(elapsed, 1),
            'scenarios': self.results,
        }
        
        report_path = Path('results') / 'test_report.json'
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f'\nReport saved to: {report_path}')
    
    def cleanup(self):
        """Clean up MQTT and Database connections."""
        if self.mqtt_client:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        self.db.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description='SmartGrid Test Runner & Auto-Plotter')
    parser.add_argument('--baseline', type=int, default=120, help='Baseline duration (s)')
    parser.add_argument('--attack', type=int, default=30, help='Attack scenario duration (s)')
    parser.add_argument('--gap', type=int, default=20, help='Gap between scenarios (s)')
    parser.add_argument('--attacker', type=str, default='127.0.0.1', help='Attacker host IP')
    parser.add_argument('--scenario', type=int, default=0, help='Run single scenario (1-8), 0=all')
    parser.add_argument('--clean-db', action='store_true', help='Clean SQLite database before starting test run')
    parser.add_argument('--no-plot', action='store_true', help='Disable automatic plot generation')
    args = parser.parse_args()

    if args.clean_db:
        from config import DB_PATH
        p = Path(DB_PATH)
        print(f"[*] Cleaning database files at: {p.parent}")
        for ext in ('', '-wal', '-shm'):
            f = Path(str(p) + ext)
            if f.exists():
                try:
                    f.unlink()
                    print(f"  Deleted: {f.name}")
                except Exception as e:
                    print(f"  Could not delete {f.name}: {e}")
    
    runner = TestRunner()
    
    try:
        if args.scenario == 0:
            runner.run_all(args.baseline, args.attack, args.gap, args.attacker, auto_plot=not args.no_plot)
        else:
            scenarios = {
                1: lambda: runner.scenario_1_baseline(args.baseline),
                2: lambda: runner.scenario_2_fdi_voltage_spike(args.attack),
                3: lambda: runner.scenario_3_fdi_subtle(args.attack),
                4: lambda: runner.scenario_4_ip_spoof(args.attack, args.attacker),
                5: lambda: runner.scenario_5_ip_spoof_advanced(args.attack, args.attacker),
                6: lambda: runner.scenario_6_replay(args.attack, args.attacker),
                7: lambda: runner.scenario_7_modbus(args.attack, args.attacker),
                8: lambda: runner.scenario_8_ramp(args.attack, args.attacker),
            }
            if args.scenario in scenarios:
                t_start = time.time()
                scenarios[args.scenario]()
                if not args.no_plot:
                    from analysis import SmartGridAnalyzer
                    print("\n[ANALYZER] Generating scientific plots for scenario...")
                    analyzer = SmartGridAnalyzer()
                    analyzer.generate_all_plots(since_timestamp=t_start)
                    analyzer.close()
            else:
                print(f'Invalid scenario: {args.scenario} (Options: 1-8)')
    except KeyboardInterrupt:
        print('\nTest run interrupted')
    finally:
        runner.cleanup()

if __name__ == '__main__':
    main()
