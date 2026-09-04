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
        self.seq_reboot_grace = 3  # Allow seq reset after reboot
        
        # Suspicious streak tracking
        self.suspicious_streak = 0
        self.suspicious_escalation_count = 3
        
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
        # 1. Physics consistency check
        physics_score, physics_violations = self._physics_check(payload)
        
        # 2. Statistical Z-score + EWMA
        z_score_norm = self._statistical_check(payload)
        
        # 3. Isolation Forest ML
        ml_score = self._ml_check(payload)
        
        # 4. Replay detection
        replay_detected = self._replay_check(payload)
        
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
        if replay_detected:
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
        if physics_violations.get('power_mismatch'): compromised.append('power_W')
        if physics_violations.get('frequency_oob'): compromised.append('frequency_Hz')
        if physics_violations.get('pf_oob'): compromised.append('power_factor')
        if physics_violations.get('energy_decrease'): compromised.append('energy_kWh')
        
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
        }

    def _physics_check(self, payload) -> Tuple[float, dict]:
        """Physics-based consistency validation.
        
        Checks:
        1. Voltage within bounds [200V, 260V]
        2. Frequency within bounds [49Hz, 51Hz]
        3. Power factor within [0, 1]
        4. P ≈ V × I × PF (within tolerance)
        5. Energy monotonically increasing (can't decrease)
        
        Returns: (score 0.0-1.0, violations_dict)
        """
        score = 0.0
        violations = {}
        
        v = payload.get('voltage_V', payload.get('voltage_v', 230.0))
        i = payload.get('current_A', payload.get('current_a', 0.0))
        p = payload.get('power_W', payload.get('power_w', 0.0))
        f = payload.get('frequency_Hz', payload.get('frequency_hz', 50.0))
        pf = payload.get('power_factor', 1.0)
        e = payload.get('energy_kWh', payload.get('energy_kwh', 0.0))
        
        # 1. Voltage bounds
        if v < self.voltage_bounds[0] or v > self.voltage_bounds[1]:
            violations['voltage_oob'] = True
            score += 0.2
            
        # 2. Frequency bounds
        if f < self.frequency_bounds[0] or f > self.frequency_bounds[1]:
            violations['frequency_oob'] = True
            score += 0.2
            
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
                
        return min(score, 1.0), violations

    def _statistical_check(self, payload) -> float:
        """Z-score + EWMA anomaly detection."""
        if len(self.voltage_history) < 5:
            return 0.0
            
        v = payload.get('voltage_V', payload.get('voltage_v', 230.0))
        i = payload.get('current_A', payload.get('current_a', 0.0))
        p = payload.get('power_W', payload.get('power_w', 0.0))
        
        v_mean = np.mean(self.voltage_history)
        v_std = np.std(self.voltage_history) + 1e-6
        i_mean = np.mean(self.current_history)
        i_std = np.std(self.current_history) + 1e-6
        p_mean = np.mean(self.power_history)
        p_std = np.std(self.power_history) + 1e-6
        
        z_v = abs(v - v_mean) / v_std
        z_i = abs(i - i_mean) / i_std
        z_p = abs(p - p_mean) / p_std
        
        max_z = max(z_v, z_i, z_p)
        
        # Normalize z-score to 0-1
        # if max_z is 0 -> 0.0, if max_z >= threshold -> 1.0
        z_score_norm = min(max_z / self.z_score_threshold, 1.0)
        
        # EWMA Residual check
        ewma_score = 0.0
        if self.ewma_voltage is not None:
            res_v = abs(v - self.ewma_voltage) / (self.ewma_voltage + 1e-6)
            res_p = abs(p - self.ewma_power) / (self.ewma_power + 1e-6)
            ewma_score = min((res_v + res_p) * 2, 1.0)
            
        # Combine Z-score and EWMA
        combined = (z_score_norm + ewma_score) / 2.0
        return combined

    def _ml_check(self, payload) -> float:
        """Isolation Forest anomaly score."""
        if self.iso_forest is None or not SKLEARN_AVAILABLE:
            return 0.0
            
        v = payload.get('voltage_V', payload.get('voltage_v', 230.0))
        i = payload.get('current_A', payload.get('current_a', 0.0))
        p = payload.get('power_W', payload.get('power_w', 0.0))
        f = payload.get('frequency_Hz', payload.get('frequency_hz', 50.0))
        pf = payload.get('power_factor', 1.0)
        rssi = payload.get('rssi_dBm', payload.get('rssi_dbm', -50))
        
        expected_p = v * i * pf
        pwr_err = abs(p - expected_p) / max(p, 0.001) * 100
        
        try:
            X = np.array([[v, i, p, f, pf, rssi, pwr_err]])
            # decision_function returns negative for anomaly, positive for normal
            decision = self.iso_forest.decision_function(X)[0]
            
            # Map decision to 0.0 - 1.0 (higher = more anomalous)
            # Typically decision is between -0.5 and 0.5
            norm_score = 0.5 - decision
            return float(np.clip(norm_score, 0.0, 1.0))
        except Exception as e:
            logger.error(f"ML check failed: {e}")
            return 0.0

    def _replay_check(self, payload) -> bool:
        """Detect replay attacks via sequence number analysis."""
        node = payload.get('node_id', self.node_id)
        seq = payload.get('sequence', None)
        
        if seq is None:
            return False
            
        if node not in self.last_seq:
            self.last_seq[node] = seq
            return False
            
        last_seq = self.last_seq[node]
        
        # Reboot grace period check
        if seq < self.seq_reboot_grace and (last_seq > 1000):
            # Probably a reboot, accept it
            self.last_seq[node] = seq
            return False
            
        if seq <= last_seq:
            return True
            
        if seq > last_seq + 5:
            logger.warning(f"Sequence jump detected for {node}: {last_seq} -> {seq}. Possible injection gap.")
            
        self.last_seq[node] = seq
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
        """Load trained Isolation Forest model from disk."""
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn not available. ML checking disabled.")
            return
            
        if self.model_path.exists():
            try:
                with open(self.model_path, 'rb') as f:
                    self.iso_forest = pickle.load(f)
                logger.info(f"Loaded Isolation Forest model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
        else:
            logger.warning(f"ML model not found at {self.model_path}. ML checking will return 0.0.")

    def train_model(self, baseline_data: list, save=True):
        """Train Isolation Forest on baseline (clean) data."""
        if not SKLEARN_AVAILABLE:
            logger.error('scikit-learn not available, cannot train model')
            return False
        
        features = []
        for d in baseline_data:
            v = d.get('voltage_V', d.get('voltage_v', 230.0))
            i = d.get('current_A', d.get('current_a', 0.0))
            p = d.get('power_W', d.get('power_w', 0.0))
            f = d.get('frequency_Hz', d.get('frequency_hz', 50.0))
            pf = d.get('power_factor', 1.0)
            rssi = d.get('rssi_dBm', d.get('rssi_dbm', -50))
            
            # Compute power error
            expected_p = v * i * pf
            pwr_err = abs(p - expected_p) / max(p, 0.001) * 100
            features.append([v, i, p, f, pf, rssi, pwr_err])
        
        X = np.array(features)
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )
        self.iso_forest.fit(X)
        
        if save:
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.iso_forest, f)
            logger.info(f'Isolation Forest model saved to {self.model_path}')
        
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
