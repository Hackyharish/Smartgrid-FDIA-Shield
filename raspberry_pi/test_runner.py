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
        self.attacker_dir = attacker_scripts_dir or Path('/home/attacker')
        self.mqtt_client = None
        self.results = {}
        self._setup_mqtt()
    
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
    
    def scenario_4_ip_spoof(self, duration=60, attacker_host='192.168.1.200'):
        """Scenario 4: IP Spoofing attack."""
        print('\n' + '='*60)
        print('SCENARIO 4 — IP SPOOFING ATTACK')
        print(f'Duration: {duration}s')
        print(f'Attacker: {attacker_host}')
        print('Expected: HMAC fails, ATTACK_DETECTED, type=TAMPERED_OR_SPOOFED')
        print('='*60)
        
        start = int(time.time())
        # Try to launch attack remotely via SSH
        ssh_cmd = (f'ssh attacker@{attacker_host} '
                   f'"sudo python3 /home/attacker/attack_ip_spoof.py --duration {duration}"')
        print(f'  [SSH] {ssh_cmd}')
        try:
            proc = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._wait_with_countdown(duration + 5, 'IP_SPOOF')
            proc.terminate()
        except Exception as e:
            print(f'  [WARNING] SSH launch failed: {e}')
            print('  [WARNING] Please run attack_ip_spoof.py manually on the attacker machine')
            self._wait_with_countdown(duration, 'IP_SPOOF')
        
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
    
    def scenario_5_ip_spoof_advanced(self, duration=60, attacker_host='192.168.1.200'):
        """Scenario 5: IP Spoofing with valid HMAC (insider threat)."""
        print('\n' + '='*60)
        print('SCENARIO 5 — IP SPOOFING + VALID HMAC (Insider Threat)')
        print(f'Duration: {duration}s')
        print('Expected: HMAC passes, detection relies on fingerprint + physics')
        print('='*60)
        
        start = int(time.time())
        ssh_cmd = (f'ssh attacker@{attacker_host} '
                   f'"sudo python3 /home/attacker/attack_ip_spoof.py '
                   f'--duration {duration} --advanced-mode"')
        print(f'  [SSH] {ssh_cmd}')
        try:
            proc = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._wait_with_countdown(duration + 5, 'SPOOF_ADV')
            proc.terminate()
        except Exception as e:
            print(f'  [WARNING] SSH launch failed: {e}')
            self._wait_with_countdown(duration, 'SPOOF_ADV')
        
        end = int(time.time())
        results = self._get_scenario_results(start, end)
        self.results['scenario_5'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results
    
    def scenario_6_replay(self, duration=60, attacker_host='192.168.1.200'):
        """Scenario 6: Replay attack."""
        print('\n' + '='*60)
        print('SCENARIO 6 — REPLAY ATTACK')
        print(f'Duration: {duration}s')
        print('Expected: Stale seq/timestamp detected, type=REPLAY')
        print('='*60)
        
        start = int(time.time())
        ssh_cmd = (f'ssh attacker@{attacker_host} '
                   f'"sudo python3 /home/attacker/attack_replay.py --duration {duration}"')
        print(f'  [SSH] {ssh_cmd}')
        try:
            proc = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._wait_with_countdown(duration + 10, 'REPLAY')
            proc.terminate()
        except Exception as e:
            print(f'  [WARNING] SSH launch failed: {e}')
            self._wait_with_countdown(duration, 'REPLAY')
        
        end = int(time.time())
        results = self._get_scenario_results(start, end)
        self.results['scenario_6'] = results
        
        print(f'  Results: {results["total_packets"]} packets, '
              f'{results["attack_detected"]} attacks detected, '
              f'dominant={results["dominant_detector"]}')
        return results
    
    # ═══════════════════════════════════════════════
    # ORCHESTRATION
    # ═══════════════════════════════════════════════
    
    def run_all(self, baseline_duration=300, attack_duration=60,
                gap_between_scenarios=30, attacker_host='192.168.1.200'):
        """Run all 6 scenarios sequentially with gaps between them."""
        print('╔══════════════════════════════════════════════════╗')
        print('║  SmartGrid Test Runner — Full 6-Scenario Suite   ║')
        print('╚══════════════════════════════════════════════════╝')
        print(f'  Baseline: {baseline_duration}s')
        print(f'  Attack scenarios: {attack_duration}s each')
        print(f'  Gap between scenarios: {gap_between_scenarios}s')
        print(f'  Attacker host: {attacker_host}')
        total_time = baseline_duration + 5 * attack_duration + 6 * gap_between_scenarios
        print(f'  Estimated total time: {total_time // 60}m {total_time % 60}s')
        print()
        
        overall_start = time.time()
        
        self.scenario_1_baseline(baseline_duration)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        self.scenario_2_fdi_voltage_spike(attack_duration)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        self.scenario_3_fdi_subtle(attack_duration)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        self.scenario_4_ip_spoof(attack_duration, attacker_host)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        self.scenario_5_ip_spoof_advanced(attack_duration, attacker_host)
        self._wait_with_countdown(gap_between_scenarios, 'COOLDOWN')
        
        self.scenario_6_replay(attack_duration, attacker_host)
        
        overall_elapsed = time.time() - overall_start
        
        # Generate report
        self._print_summary_table()
        self._save_report(overall_elapsed)
    
    def _print_summary_table(self):
        """Print formatted results table."""
        print('\n' + '='*80)
        print('COMPLETE TEST RESULTS')
        print('='*80)
        
        header = f'{"Metric":<30} {"Sc1":>6} {"Sc2":>6} {"Sc3":>6} {"Sc4":>6} {"Sc5":>6} {"Sc6":>6}'
        print(header)
        print('-' * 80)
        
        for metric in ['total_packets', 'attack_detected', 'dominant_detector']:
            row = f'{metric:<30}'
            for i in range(1, 7):
                key = f'scenario_{i}'
                val = self.results.get(key, {}).get(metric, '-')
                row += f' {str(val):>6}'
            print(row)
        
        print('='*80)
    
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
    parser = argparse.ArgumentParser(description='SmartGrid Test Runner')
    parser.add_argument('--baseline', type=int, default=300, help='Baseline duration (s)')
    parser.add_argument('--attack', type=int, default=60, help='Attack scenario duration (s)')
    parser.add_argument('--gap', type=int, default=30, help='Gap between scenarios (s)')
    parser.add_argument('--attacker', type=str, default='192.168.1.200', help='Attacker host IP')
    parser.add_argument('--scenario', type=int, default=0, help='Run single scenario (1-6), 0=all')
    args = parser.parse_args()
    
    runner = TestRunner()
    
    try:
        if args.scenario == 0:
            runner.run_all(args.baseline, args.attack, args.gap, args.attacker)
        else:
            scenarios = {
                1: lambda: runner.scenario_1_baseline(args.baseline),
                2: lambda: runner.scenario_2_fdi_voltage_spike(args.attack),
                3: lambda: runner.scenario_3_fdi_subtle(args.attack),
                4: lambda: runner.scenario_4_ip_spoof(args.attack, args.attacker),
                5: lambda: runner.scenario_5_ip_spoof_advanced(args.attack, args.attacker),
                6: lambda: runner.scenario_6_replay(args.attack, args.attacker),
            }
            if args.scenario in scenarios:
                scenarios[args.scenario]()
            else:
                print(f'Invalid scenario: {args.scenario}')
    except KeyboardInterrupt:
        print('\nTest run interrupted')
    finally:
        runner.cleanup()

if __name__ == '__main__':
    main()
