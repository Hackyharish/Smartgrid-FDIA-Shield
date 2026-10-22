"""
MODULE BRIEFING:
Purpose: Core detection engine for False Data Injection (FDI) attacks in the SmartGrid project.
It utilizes a FIVE-SIGNAL FUSION system:
1. Physics consistency check (Voltage/Frequency bounds, Power equation)
2. Statistical Z-score + EWMA (Exponentially Weighted Moving Average)
3. Isolation Forest ML model for anomaly detection
4. HMAC verification score (external input)
5. Network Fingerprinting score (external input)

Inputs: Enriched telemetry payload dict, external HMAC and fingerprint scores.
Outputs: Detection result dictionary containing fused scores, attack status, and compromised parameters.
Dependencies: numpy, scikit-learn (optional but recommended for ML), logging.

RESEARCH DISCLAIMER:
This code is part of a controlled lab testbed for a university final-year project.
It is intended for educational and research purposes in IoT cybersecurity.
"""

import numpy as np
import logging
import time
import json
import pickle
from pathlib import Path
from collections import deque
from typing import Dict, List, Optional, Tuple

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from state_estimator import StateEstimator
from virtual_pmu import VirtualPMUProcessor

logger = logging.getLogger(__name__)

class FDIDetector:
    def __init__(self, node_id='node_01', rolling_window_size=20, model_path=None):
        # Initialize all state
        self.node_id = node_id
        self.rolling_window_size = rolling_window_size
        self.model_path = model_path or Path('models/isolation_forest.pkl')
        
        # Rolling window history (deques)
        self.voltage_history = deque(maxlen=rolling_window_size)
        self.current_history = deque(maxlen=rolling_window_size)
        self.power_history = deque(maxlen=rolling_window_size)
        self.frequency_history = deque(maxlen=rolling_window_size)
        self.pf_history = deque(maxlen=rolling_window_size)
        self.energy_history = deque(maxlen=rolling_window_size)
        self.timestamp_history = deque(maxlen=rolling_window_size)
        
        # EWMA state
        self.ewma_alpha = 0.3
        self.ewma_voltage = None
        self.ewma_current = None
        self.ewma_power = None
        
        # Sequence tracking for replay detection
        self.last_seq = {}
        self._jump_streak = {}
        self.seq_reboot_grace = 3  # Allow seq reset after reboot
        
        # Suspicious streak tracking
        self.suspicious_streak = 0
        self.suspicious_escalation_count = 3
        
        # Stealth Ramp & CUSUM drift detection
        self.cusum_pos = 0.0
        self.cusum_neg = 0.0
        self.cusum_k = 0.35  # Drift sensitivity threshold (Volts)
        self.cusum_h = 3.5   # Decision threshold (Cumulative Volts)
        self.ramp_consecutive_inc = 0
        self.ramp_consecutive_dec = 0
        self.last_voltage = None
        
        # ML model
        self.iso_forest = None
        self._load_model()
        
        # Detection weights
        self.weights = {
            'physics': 0.25,
            'zscore': 0.20,
            'ml': 0.20,
            'hmac': 0.25,
            'fingerprint': 0.10,
        }
        
        # Thresholds
        self.attack_threshold = 0.6
        self.suspicious_threshold = 0.35
        self.z_score_threshold = 3.0
        
        # Physics bounds
        self.voltage_bounds = (200.0, 260.0)
        self.frequency_bounds = (49.0, 51.0)
        self.pf_bounds = (0.0, 1.0)
        self.power_tolerance_pct = 10.0
        
        # Industrial State Estimator & Synchrophasor PMU
        self.state_estimator = StateEstimator()
        self.virtual_pmu = VirtualPMUProcessor()

    def detect(self, payload: dict, hmac_score: float = 0.0, 
               fingerprint_score: float = 0.0, fingerprint_verdict: str = 'UNKNOWN') -> dict:
        """Run all 5 detection signals and fuse results.
        
        Args:
            payload: Enriched telemetry dict from MQTT subscriber
            hmac_score: 0.0 (valid) or 1.0 (invalid/missing) from hmac_verifier
            fingerprint_score: 0.0-1.0 from network_fingerprint module
            fingerprint_verdict: LEGITIMATE, SUSPECTED_SPOOF, CONFIRMED_SPOOF
        
        Returns:
            Detection result dict with all scores, status, and attack_type
        """
        # 1. Physics consistency & WLS / PMU check
        physics_score, physics_violations, state_est, pmu = self._physics_check(payload)
        
        # 2. Statistical Z-score + EWMA
        z_score_norm = self._statistical_check(payload)
        
        # 3. Isolation Forest ML
        ml_score = self._ml_check(payload)
        
        # 4. Replay detection
        replay_detected = self._replay_check(payload, hmac_valid=(hmac_score == 0.0))
        
        # 5. Weighted fusion
        confidence = (
            self.weights['physics'] * physics_score +
            self.weights['zscore'] * z_score_norm +
            self.weights['ml'] * ml_score +
            self.weights['hmac'] * hmac_score +
            self.weights['fingerprint'] * fingerprint_score
        )
        
        # Determine status and attack type
        status = 'NORMAL'
        attack_type = None
        
        # OVERRIDE RULES (checked AFTER fusion)
        if physics_violations.get('voltage_oob'):
            status = 'ATTACK_DETECTED'
            attack_type = 'FDI_VOLTAGE_OOB'
            confidence = max(confidence, 0.95)
        elif physics_violations.get('frequency_oob'):
            status = 'ATTACK_DETECTED'
            attack_type = 'FDI_FREQUENCY_OOB'
            confidence = max(confidence, 0.95)
        elif physics_violations.get('ramp_detected'):
            status = 'ATTACK_DETECTED'
            attack_type = 'FDI_RAMP_STEALTH'
            confidence = max(confidence, 0.88)
        elif replay_detected:
            status = 'ATTACK_DETECTED'
            attack_type = 'REPLAY'
        elif hmac_score == 1.0 and fingerprint_verdict == 'CONFIRMED_SPOOF':
            status = 'ATTACK_DETECTED'
            attack_type = 'IP_SPOOF_CONFIRMED'
        elif hmac_score == 1.0:
            status = 'ATTACK_DETECTED'
            attack_type = 'TAMPERED_OR_SPOOFED'
        elif confidence >= self.attack_threshold:
            status = 'ATTACK_DETECTED'
            attack_type = 'FDI_FIRMWARE'
        elif confidence >= self.suspicious_threshold:
            status = 'SUSPICIOUS'
            self.suspicious_streak += 1
            if self.suspicious_streak >= self.suspicious_escalation_count:
                status = 'ATTACK_DETECTED'
                attack_type = 'FDI_FIRMWARE'
        
        if status == 'NORMAL':
            self.suspicious_streak = 0
            # Update rolling window with verified data
            self._update_history(payload)
        
        # Determine compromised parameters
        compromised = []
        if physics_violations.get('voltage_oob'): compromised.append('voltage_V')
        if physics_violations.get('ramp_detected') and 'voltage_V' not in compromised: compromised.append('voltage_V')
        if physics_violations.get('power_mismatch'): compromised.append('power_W')
        if physics_violations.get('frequency_oob'): compromised.append('frequency_Hz')
        if physics_violations.get('pf_oob'): compromised.append('power_factor')
        if physics_violations.get('energy_decrease'): compromised.append('energy_kWh')
        if state_est.get('compromised_measurement') and state_est['compromised_measurement'] not in compromised:
            compromised.append(state_est['compromised_measurement'])
        
        return {
            'node_id': payload.get('node_id', self.node_id),
            'timestamp': payload.get('timestamp', int(time.time())),
            'status': status,
            'attack_type': attack_type,
            'attack_confidence': round(float(confidence), 4),
            'physics_score': round(float(physics_score), 4),
            'z_score_normalized': round(float(z_score_norm), 4),
            'ml_score': round(float(ml_score), 4),
            'hmac_score': round(float(hmac_score), 4),
            'fingerprint_score': round(float(fingerprint_score), 4),
            'physics_violations': physics_violations,
            'compromised_parameters': compromised,
            'replay_detected': replay_detected,
            'state_estimation': state_est,
            'synchrophasor_pmu': pmu,
        }

    def _physics_check(self, payload) -> Tuple[float, dict, dict, dict]:
        """Physics-based consistency validation & WLS / Synchrophasor PMU check.
        
        Checks:
        1. Voltage within bounds [200V, 260V]
        2. Frequency within bounds [49Hz, 51Hz]
        3. Power factor within [0, 1]
        4. P ≈ V × I × PF (within tolerance)
        5. Energy monotonically increasing (can't decrease)
        6. AC WLS State Estimation residual & Chi-square Bad Data Detection
        7. Virtual PMU Synchrophasor angle, TVE, and ROCOF consistency
        
        Returns: (score 0.0-1.0, violations_dict, state_est_dict, pmu_dict)
        """
        score = 0.0
        violations = {}
        
        v = payload.get('voltage_V', payload.get('voltage_v', 230.0))
        i = payload.get('current_A', payload.get('current_a', 0.0))
        p = payload.get('power_W', payload.get('power_w', 0.0))
        f = payload.get('frequency_Hz', payload.get('frequency_hz', 50.0))
        pf = payload.get('power_factor', 1.0)
        e = payload.get('energy_kWh', payload.get('energy_kwh', 0.0))
        
        # 1. Voltage bounds (IEEE 1547 / EN 50160 grid standard: 200V-260V)
        if v < self.voltage_bounds[0] or v > self.voltage_bounds[1]:
            violations['voltage_oob'] = True
            v_dev = abs(v - 230.0) / 230.0
            score += min(1.0, 0.6 + v_dev * 2.0)
            
        # 2. Frequency bounds (49.0 - 51.0 Hz)
        if f < self.frequency_bounds[0] or f > self.frequency_bounds[1]:
            violations['frequency_oob'] = True
            f_dev = abs(f - 50.0) / 50.0
            score += min(1.0, 0.6 + f_dev * 10.0)
            
        # 3. Power factor bounds
        if pf < self.pf_bounds[0] or pf > self.pf_bounds[1]:
            violations['pf_oob'] = True
            score += 0.2
            
        # 4. Power consistency
        expected_p = v * i * pf
        pwr_diff_pct = abs(p - expected_p) / max(p, 0.001) * 100
        if pwr_diff_pct > self.power_tolerance_pct:
            violations['power_mismatch'] = True
            score += 0.2
            
        # 5. Energy monotonicity
        if len(self.energy_history) > 0:
            last_e = self.energy_history[-1]
            if e < last_e:
                violations['energy_decrease'] = True
                score += 0.2

        # 6. Industrial AC WLS State Estimation
        state_est = self.state_estimator.estimate_state(payload)
        if state_est.get('bad_data_detected'):
            violations['wls_bad_data'] = True
            violations['wls_chi2'] = state_est.get('chi_square_stat')
            violations['wls_compromised'] = state_est.get('compromised_measurement')
            score += state_est.get('residual_score', 0.5) * 0.4

        # 7. Virtual PMU Synchrophasor & ROCOF
        pmu = self.virtual_pmu.process_measurement(payload)
        if pmu.get('phase_jump_detected') or pmu.get('rocof_violation') or not pmu.get('ieee_c37_118_compliant'):
            violations['pmu_anomaly'] = True
            violations['pmu_rocof'] = pmu.get('rocof_Hz_s')
            violations['pmu_tve'] = pmu.get('total_vector_error_pct')
            score += pmu.get('pmu_anomaly_score', 0.3) * 0.3

        # 8. Stealth Monotonic Voltage Ramp & CUSUM Drift Detection
        if self.last_voltage is not None:
            dv = v - self.last_voltage

            # Transient step jump (e.g. attack started, stopped, or load stepped):
            # Reset CUSUM so large single-packet jumps do not latch drift detectors
            if abs(dv) > 3.0:
                self.cusum_pos = 0.0
                self.cusum_neg = 0.0
                self.ramp_consecutive_inc = 0
                self.ramp_consecutive_dec = 0
            else:
                if dv > 0.35:
                    self.ramp_consecutive_inc += 1
                    self.ramp_consecutive_dec = 0
                    self.cusum_pos = max(0.0, self.cusum_pos + (dv - self.cusum_k))
                elif dv < -0.35:
                    self.ramp_consecutive_dec += 1
                    self.ramp_consecutive_inc = 0
                    self.cusum_neg = max(0.0, self.cusum_neg + (-dv - self.cusum_k))
                else:
                    # Steady-state (|dv| <= 0.35V): active drift has halted
                    self.ramp_consecutive_inc = 0
                    self.ramp_consecutive_dec = 0
                    self.cusum_pos = 0.0
                    self.cusum_neg = 0.0

            # Voltage drift relative to nominal 230.0V
            v_dev = abs(v - 230.0)

            # Active ramp detection requires:
            # (1) Active monotonic drift (streak >= 4 or CUSUM >= h)
            # AND (2) Significant absolute drift from nominal (>= 4.0V)
            if ((self.ramp_consecutive_inc >= 4 or self.cusum_pos >= self.cusum_h) and (v - 230.0 >= 4.0)) or \
               ((self.ramp_consecutive_dec >= 4 or self.cusum_neg >= self.cusum_h) and (230.0 - v >= 4.0)):
                violations['ramp_detected'] = True
                score += 0.5
        self.last_voltage = v
                
        return min(score, 1.0), violations, state_est, pmu

    def _extract_ml_features(self, payload: dict) -> list:
        """Extracts load-invariant cyber-physical feature vector for Isolation Forest."""
        v = float(payload.get('voltage_V', payload.get('voltage_v', 230.0)))
        i = float(payload.get('current_A', payload.get('current_a', 0.0)))
        p = float(payload.get('power_W', payload.get('power_w', 0.0)))
        f = float(payload.get('frequency_Hz', payload.get('frequency_hz', 50.0)))
        pf = float(payload.get('power_factor', 1.0))
        rssi = float(payload.get('rssi_dBm', payload.get('rssi_dbm', -50.0)))
        
        expected_p = v * i * max(0.01, pf)
        pwr_diff = abs(p - expected_p)
        pwr_err_pct = pwr_diff / max(p, 1.0) * 100.0
        pwr_ratio = p / max(expected_p, 0.01)
        
        return [v, i, p, f, pf, rssi, pwr_diff, pwr_err_pct, pwr_ratio]

    def _statistical_check(self, payload) -> float:
        """Z-score + EWMA anomaly detection with physical load invariance."""
        if len(self.voltage_history) < 5:
            return 0.0
            
        v = float(payload.get('voltage_V', payload.get('voltage_v', 230.0)))
        i = float(payload.get('current_A', payload.get('current_a', 0.0)))
        p = float(payload.get('power_W', payload.get('power_w', 0.0)))
        pf = float(payload.get('power_factor', 1.0))
        
        expected_p = v * i * max(0.01, pf)
        pwr_diff_pct = abs(p - expected_p) / max(p, 1.0) * 100.0
        
        # Grid voltage stability check (voltage is regulated by utility regardless of load)
        v_mean = np.mean(self.voltage_history)
        v_std = max(np.std(self.voltage_history), 1.0)
        z_v = abs(v - v_mean) / v_std
        
        # Physical consistency check: Does the power math add up?
        # Legitimate load variation: P = V * I * PF math holds AND voltage is within regulated grid bounds
        math_adds_up = (pwr_diff_pct <= self.power_tolerance_pct) and (self.voltage_bounds[0] <= v <= self.voltage_bounds[1])
        
        if math_adds_up:
            # Physically valid load variation: evaluate voltage stability only
            z_score_norm = min(z_v / self.z_score_threshold, 1.0) * 0.3
            ewma_score = 0.0
            if self.ewma_voltage is not None:
                res_v = abs(v - self.ewma_voltage) / max(self.ewma_voltage, 1.0)
                ewma_score = min(res_v * 5.0, 1.0) * 0.3
        else:
            # Math does NOT add up: sensor values physically conflict
            z_i = abs(i - np.mean(self.current_history)) / (np.std(self.current_history) + 1e-6)
            z_p = abs(p - np.mean(self.power_history)) / (np.std(self.power_history) + 1e-6)
            max_z = max(z_v, z_i, z_p, pwr_diff_pct / 5.0)
            z_score_norm = min(max_z / self.z_score_threshold, 1.0)
            ewma_score = min(pwr_diff_pct / 20.0, 1.0)
            
        # Combine Z-score and EWMA
        combined = (z_score_norm + ewma_score) / 2.0
        return float(np.clip(combined, 0.0, 1.0))

    def _ml_check(self, payload) -> float:
        """
        Cyber-Physical Machine Learning Anomaly Score.
        Combines Isolation Forest tree density score with feature boundary deviations.
        """
        v = float(payload.get('voltage_V', payload.get('voltage_v', 230.0)))
        f = float(payload.get('frequency_Hz', payload.get('frequency_hz', 50.0)))
        p = float(payload.get('power_W', payload.get('power_w', 0.0)))
        i = float(payload.get('current_A', payload.get('current_a', 0.0)))
        pf = float(payload.get('power_factor', 1.0))
        
        # 1. Feature boundary deviation score
        v_dev = 0.0
        if v < 200.0 or v > 260.0:
            v_dev = min(1.0, abs(v - 230.0) / 40.0)
        elif v < 225.0 or v > 235.0:
            v_dev = min(0.3, abs(v - 230.0) / 30.0)

        f_dev = min(1.0, abs(f - 50.0) / 1.0) if (f < 49.5 or f > 50.5) else 0.0
        
        exp_p = v * i * max(0.01, pf)
        pwr_err = abs(p - exp_p) / max(p, 1.0)
        p_dev = min(1.0, pwr_err / 0.25) if pwr_err > 0.10 else 0.0

        phys_ml_score = max(v_dev, f_dev, p_dev)

        if self.iso_forest is None or not SKLEARN_AVAILABLE:
            return float(np.clip(phys_ml_score, 0.0, 1.0))

        try:
            X = np.array([self._extract_ml_features(payload)])
            decision = self.iso_forest.decision_function(X)[0]
            
            # Baseline clean training data produces decision ~0.207.
            # Decision drops as features deviate:
            if decision >= 0.195:
                if_score = 0.0
            elif decision >= 0.0:
                if_score = float(np.clip((0.195 - decision) / 0.195 * 0.5, 0.0, 0.5))
            else:
                if_score = float(np.clip(0.5 + (-decision / 0.10) * 0.5, 0.5, 1.0))

            combined_score = max(if_score, phys_ml_score)
            return float(np.clip(combined_score, 0.0, 1.0))
        except Exception as e:
            logger.error(f"ML check failed: {e}")
            return float(np.clip(phys_ml_score, 0.0, 1.0))

    def _replay_check(self, payload, hmac_valid: bool = True) -> bool:
        """Detect replay attacks via sequence number analysis."""
        node = payload.get('node_id', self.node_id)
        seq = payload.get('seq', payload.get('sequence', None))
        
        if seq is None:
            return False
            
        if node not in self.last_seq:
            self.last_seq[node] = seq
            return False
            
        last_seq = self.last_seq[node]
        
        # 1. ESP32 reboot / counter rollover detection:
        if seq < 10 and last_seq > 50:
            logger.info(f"ESP32 reboot / sequence reset detected for {node}: {last_seq} -> {seq}")
            self.last_seq[node] = seq
            self._jump_streak.pop(node, None)
            return False
            
        # 2. Sequence progression (seq > last_seq):
        if seq > last_seq:
            jump = seq - last_seq
            if jump > 30:
                # If HMAC is valid, the node simply continued incrementing during cooldown/silence
                if hmac_valid:
                    logger.info(f"Telemetry stream synchronized for {node} after cooldown ({last_seq} -> {seq}).")
                    self.last_seq[node] = seq
                    self._jump_streak.pop(node, None)
                    return False
                
                # If packet has invalid HMAC, verify consecutive progression before accepting
                streak = self._jump_streak.get(node, (0, 0))
                if streak[0] + 1 == seq and streak[1] >= 2:
                    logger.info(f"Consecutive stream confirmed for {node}: advancing tracker to {seq}.")
                    self.last_seq[node] = seq
                    self._jump_streak.pop(node, None)
                    return False
                else:
                    self._jump_streak[node] = (seq, streak[1] + 1 if streak[0] + 1 == seq else 1)
                    logger.warning(f"Abnormal sequence jump detected for {node}: {last_seq} -> {seq}. Injected packet.")
                    return False
            
            # Normal sequential progression
            self.last_seq[node] = seq
            self._jump_streak.pop(node, None)
            return False
            
        # 3. True replay: identical sequence number or replayed recent packet (within 30 packets)
        if 0 <= (last_seq - seq) <= 30:
            return True
            
        # 4. If seq is much smaller than last_seq (last_seq was poisoned by injection jump), reset to genuine seq
        if (last_seq - seq) > 30:
            logger.info(f"Resetting poisoned sequence tracker for {node}: {last_seq} -> {seq}")
            self.last_seq[node] = seq
            self._jump_streak.pop(node, None)
            return False
            
        return False

    def _update_history(self, payload):
        """Add verified reading to rolling window history and update EWMA."""
        v = payload.get('voltage_V', payload.get('voltage_v', 230.0))
        i = payload.get('current_A', payload.get('current_a', 0.0))
        p = payload.get('power_W', payload.get('power_w', 0.0))
        f = payload.get('frequency_Hz', payload.get('frequency_hz', 50.0))
        pf = payload.get('power_factor', 1.0)
        e = payload.get('energy_kWh', payload.get('energy_kwh', 0.0))
        ts = payload.get('timestamp', int(time.time()))
        
        self.voltage_history.append(v)
        self.current_history.append(i)
        self.power_history.append(p)
        self.frequency_history.append(f)
        self.pf_history.append(pf)
        self.energy_history.append(e)
        self.timestamp_history.append(ts)
        
        # Update EWMA
        if self.ewma_voltage is None:
            self.ewma_voltage = v
            self.ewma_current = i
            self.ewma_power = p
        else:
            self.ewma_voltage = self.ewma_alpha * v + (1 - self.ewma_alpha) * self.ewma_voltage
            self.ewma_current = self.ewma_alpha * i + (1 - self.ewma_alpha) * self.ewma_current
            self.ewma_power = self.ewma_alpha * p + (1 - self.ewma_alpha) * self.ewma_power

    def _load_model(self):
        """Load trained Isolation Forest model from disk with path search and auto-training fallback."""
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not available. ML checking will use statistical distance fallback.")
            return
            
        candidate_paths = [
            Path(self.model_path) if self.model_path else None,
            Path(__file__).parent / 'models' / 'isolation_forest.pkl',
            Path('models/isolation_forest.pkl'),
            Path('/home/smartgrid/smartgrid/models/isolation_forest.pkl'),
            Path('/home/smartgrid/Desktop/Project/Smartgrid-FDIA-Shield/raspberry_pi/models/isolation_forest.pkl')
        ]
        
        loaded = False
        for p in candidate_paths:
            if p and p.exists():
                try:
                    with open(p, 'rb') as f:
                        self.iso_forest = pickle.load(f)
                    self.model_path = p
                    logger.info(f"Loaded Isolation Forest model from {p}")
                    loaded = True
                    break
                except Exception as e:
                    logger.error(f"Failed to load ML model from {p}: {e}")
                    
        if not loaded:
            logger.warning(f"ML model not found in candidates. Auto-training baseline Isolation Forest model now...")
            try:
                baseline_samples = []
                for v_offset in [-2.0, -1.0, -0.5, 0.0, 0.5, 1.0, 2.0]:
                    for f_offset in [-0.05, 0.0, 0.05]:
                        baseline_samples.append({
                            'voltage_V': 230.0 + v_offset,
                            'current_A': 0.44,
                            'power_W': 100.0,
                            'frequency_Hz': 50.0 + f_offset,
                            'power_factor': 0.99,
                            'rssi_dBm': -55.0
                        })
                self.train_model(baseline_samples, save=True)
                logger.info("Auto-trained and initialized fresh Isolation Forest model.")
            except Exception as e:
                logger.error(f"Auto-training baseline ML model failed: {e}")

    def train_model(self, baseline_data: list, save=True):
        """
        Train Isolation Forest on baseline clean data with Physics-Constrained Load Augmentation.
        Learns from real lab ambient voltage/frequency/RSSI while generalising across varying loads (10W-3000W).
        """
        if not SKLEARN_AVAILABLE:
            logger.error('scikit-learn not available, cannot train model')
            return False
        
        # Load power steps spanning wide real-world loads (5W to 3000W)
        power_steps = [5.0, 15.0, 30.0, 50.0, 75.0, 100.0, 150.0, 200.0, 250.0, 300.0, 400.0, 500.0, 750.0, 1000.0, 1500.0, 2000.0, 3000.0]
        
        features = []
        for d in baseline_data:
            # Real lab operating conditions from user testbed
            v = float(d.get('voltage_V', d.get('voltage_v', 228.0)))
            f = float(d.get('frequency_Hz', d.get('frequency_hz', 50.0)))
            pf = float(d.get('power_factor', 0.99))
            rssi = float(d.get('rssi_dBm', d.get('rssi_dbm', -55.0)))
            
            # 1. Add the original measured sample
            orig_i = float(d.get('current_A', d.get('current_a', 0.44)))
            orig_p = float(d.get('power_W', d.get('power_w', 100.0)))
            features.append(self._extract_ml_features({
                'voltage_V': v, 'current_A': orig_i, 'power_W': orig_p,
                'frequency_Hz': f, 'power_factor': pf, 'rssi_dBm': rssi
            }))
            
            # 2. Physics-constrained load augmentation:
            # Augment across varying power levels where the math adds up (P = V * I * PF)
            for p_step in power_steps:
                i_step = p_step / max(v * pf, 1.0) * float(np.random.normal(1.0, 0.003))
                p_meas = v * i_step * pf * float(np.random.normal(1.0, 0.003))
                features.append(self._extract_ml_features({
                    'voltage_V': v, 'current_A': i_step, 'power_W': p_meas,
                    'frequency_Hz': f, 'power_factor': pf, 'rssi_dBm': rssi
                }))
        
        X = np.array(features)
        self.iso_forest = IsolationForest(
            n_estimators=150,
            contamination=0.01,
            random_state=42,
            n_jobs=-1
        )
        self.iso_forest.fit(X)
        
        if save:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.iso_forest, f)
            logger.info(f'Load-invariant Isolation Forest model saved to {self.model_path} ({len(X)} samples)')
        
        return True

    def get_state_summary(self) -> dict:
        """Return current detector state for logging/debugging."""
        return {
            'node_id': self.node_id,
            'history_size': len(self.voltage_history),
            'ewma_voltage': round(self.ewma_voltage, 2) if self.ewma_voltage is not None else None,
            'suspicious_streak': self.suspicious_streak,
            'ml_model_loaded': self.iso_forest is not None,
            'last_sequence': self.last_seq.get(self.node_id, None)
        }
