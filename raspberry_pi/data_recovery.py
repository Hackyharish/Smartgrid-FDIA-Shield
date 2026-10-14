"""
MODULE BRIEFING:
Purpose: Data Recovery Module for Smart Grid Project.
Provides a three-strategy data recovery mechanism with attack-type awareness:
1. Interpolation (Temporal polynomial fit)
2. Physics Reconstruction (Using physical formulas like Ohm's law and power equation)
3. Kalman Filter (Prediction-only mode for spoofed packets)

Inputs: Attack payload, detection results (from FDIDetector), verified historical data.
Outputs: Recovered data payload with confidence scores and strategy metadata.
Dependencies: numpy, logging, time, collections.

Disclaimer: Part of a controlled university lab testbed for IoT-based FDI attack detection.
"""

import numpy as np
import logging
import time
from typing import Dict, List, Optional, Tuple
from collections import deque

logger = logging.getLogger(__name__)

class DataRecovery:
    def __init__(self, interpolation_window: int = 5,
                 kalman_process_noise: float = 0.01,
                 kalman_measurement_noise: float = 0.1):
        self.interpolation_window = interpolation_window
        
        # Kalman filter state (per parameter)
        self.kalman_states = {}
        self.kalman_process_noise = kalman_process_noise
        self.kalman_measurement_noise = kalman_measurement_noise
        
        # History of verified readings
        self.verified_history = deque(maxlen=50)

    def recover(self, attack_payload: dict, detection_result: dict,
                verified_history: list = None) -> dict:
        """Recover correct data values based on attack type.
        
        Attack-type aware strategy selection:
        - IP_SPOOF_CONFIRMED / TAMPERED_OR_SPOOFED:
            Skip interpolation (entire packet is fabricated, no real sensor data).
            Use Kalman prediction-only (Strategy 3).
            Note: 'Packet rejected at network layer.'
        
        - FDI_FIRMWARE:
            Physical sensor still attached. Some params may be partially reliable.
            Use physics reconstruction first (Strategy 2).
            If physics can't recover, fall back to interpolation (Strategy 1).
        
        - REPLAY:
            Values are real but stale. Use interpolation (Strategy 1)
            with corrected timestamp.
            Note: 'Replayed packet timestamp corrected.'
        
        Args:
            attack_payload: The suspicious/attack telemetry payload
            detection_result: Output from FDIDetector.detect()
            verified_history: Recent verified readings (optional, uses internal if None)
        
        Returns:
            Recovery result dict
        """
        history = verified_history or list(self.verified_history)
        attack_type = detection_result.get('attack_type')
        compromised = detection_result.get('compromised_parameters', [])
        
        # Strategy selection based on attack type
        if attack_type in ('IP_SPOOF_CONFIRMED', 'TAMPERED_OR_SPOOFED'):
            result = self._strategy_kalman_prediction(attack_payload, history)
            result['strategy_used'] = 'KALMAN_PREDICTION_ONLY'
            result['recovery_note'] = ('Packet rejected at network layer. '
                                       'Value estimated from Kalman filter state only. '
                                       'No sensor data available.')
        elif attack_type == 'REPLAY':
            result = self._strategy_interpolation(attack_payload, history)
            result['strategy_used'] = 'INTERPOLATION_TIMESTAMP_CORRECTED'
            result['timestamp'] = int(time.time())  # Correct stale timestamp
            result['recovery_note'] = 'Replayed packet timestamp corrected.'
        elif attack_type == 'FDI_FIRMWARE':
            # Try physics reconstruction first
            result = self._strategy_physics_reconstruction(attack_payload, history, compromised)
            if result['recovery_confidence'] < 0.5:
                # Physics couldn't recover well, try interpolation
                interp_result = self._strategy_interpolation(attack_payload, history)
                if interp_result['recovery_confidence'] > result['recovery_confidence']:
                    result = interp_result
                    result['strategy_used'] = 'INTERPOLATION_FALLBACK'
            else:
                result['strategy_used'] = 'PHYSICS_RECONSTRUCTION'
            result['recovery_note'] = 'FDI attack on firmware. Physics/interpolation recovery applied.'
        else:
            # Unknown attack type — use Kalman as safest default
            result = self._strategy_kalman_prediction(attack_payload, history)
            result['strategy_used'] = 'KALMAN_DEFAULT'
            result['recovery_note'] = 'Unknown attack type. Kalman prediction used.'
        
        result['attack_type_context'] = attack_type
        result['original_voltage'] = attack_payload.get('voltage_V', attack_payload.get('voltage_v', 230.0))
        result['original_current'] = attack_payload.get('current_A', attack_payload.get('current_a', 0.0))
        result['original_power'] = attack_payload.get('power_W', attack_payload.get('power_w', 0.0))
        result['node_id'] = attack_payload.get('node_id', 'node_01')
        result['timestamp'] = result.get('timestamp', attack_payload.get('timestamp', int(time.time())))

        # Standardize keys across strategies so both with and without _V/_A/_W exist
        rv = result.get('recovered_voltage_V', result.get('recovered_voltage', 230.0))
        ri = result.get('recovered_current_A', result.get('recovered_current', 0.0))
        rp = result.get('recovered_power_W', result.get('recovered_power', 0.0))

        # Absolute physical grid guardrails (prevent mathematical explosion or zero collapse)
        rv = float(np.clip(rv, 215.0, 245.0))
        rp = float(max(0.0, rp))
        ri = float(max(0.0, ri))

        result['recovered_voltage'] = round(float(rv), 2)
        result['recovered_voltage_V'] = round(float(rv), 2)
        result['recovered_current'] = round(float(ri), 4)
        result['recovered_current_A'] = round(float(ri), 4)
        result['recovered_power'] = round(float(rp), 2)
        result['recovered_power_W'] = round(float(rp), 2)
        
        return result

    def _strategy_interpolation(self, payload: dict, history: list) -> dict:
        """Strategy 1: Physics-constrained time series forecasting on verified history.
        
        Uses Exponentially Weighted Moving Average (EWMA) with trend damping
        and physical electrical bounds (Ohm's Law / power triangle).
        Guarantees voltage, current, and power remain strictly within real physical bounds.
        """
        result = {}
        if not history:
            return self._fallback_to_defaults()
            
        recent = history[-min(len(history), self.interpolation_window):]
        
        # 1. Recover Voltage (Time-Series EWMA with mean-reverting grid regulation)
        # Power grid utility maintains voltage tightly regulated around ~230V.
        v_vals = [float(h.get('voltage_V', h.get('voltage', 230.0))) for h in recent]
        v_mean = float(np.mean(v_vals))
        v_last = v_vals[-1]
        v_pred = 0.7 * v_last + 0.3 * v_mean
        v_rec = float(np.clip(v_pred, 215.0, 245.0))
        
        # 2. Recover Power (Time-Series EWMA of valid active power)
        p_vals = [float(h.get('power_W', h.get('power', 0.0))) for h in recent]
        p_mean = float(np.mean(p_vals))
        p_last = p_vals[-1]
        p_rec = float(max(0.0, 0.7 * p_last + 0.3 * p_mean))
        
        # 3. Recover Power Factor & Frequency
        pf_vals = [float(h.get('power_factor', h.get('pf', 0.99))) for h in recent]
        pf_rec = float(np.clip(np.mean(pf_vals), 0.85, 1.0))
        
        f_vals = [float(h.get('frequency_Hz', h.get('frequency', 50.0))) for h in recent]
        f_rec = float(np.clip(np.mean(f_vals), 49.8, 50.2))
        
        # 4. Recover Current via AC Power Physics: I = P / (V * PF)
        if v_rec > 1.0 and pf_rec > 0.01:
            i_rec = float(p_rec / (v_rec * pf_rec))
        else:
            i_vals = [float(h.get('current_A', h.get('current', 0.0))) for h in recent]
            i_rec = float(np.mean(i_vals))
            
        result['recovered_voltage_V'] = round(v_rec, 2)
        result['recovered_current_A'] = round(i_rec, 4)
        result['recovered_power_W'] = round(p_rec, 2)
        result['recovered_frequency_Hz'] = round(f_rec, 2)
        result['recovered_power_factor'] = round(pf_rec, 3)
        result['recovery_confidence'] = 0.90
        return result

    def _strategy_physics_reconstruction(self, payload: dict, history: list,
                                          compromised: list) -> dict:
        """Strategy 2: Physics-constrained back-calculation.
        
        Use Ohm's Law / power equation relationships:
        - If voltage is compromised but current and PF are OK:
            V_recovered = P / (I × PF)
        - If current is compromised but voltage and PF are OK:
            I_recovered = P / (V × PF)
        - If power is compromised but voltage, current, and PF are OK:
            P_recovered = V × I × PF
        - If multiple params compromised, use last known good values from history
        
        Confidence based on which params were used for reconstruction.
        """
        result = {}
        
        # Original values from payload
        v = payload.get('voltage_V', 230.0)
        i = payload.get('current_A', 0.0)
        p = payload.get('power_W', 0.0)
        pf = payload.get('power_factor', 0.95)
        
        last_good = history[-1] if history else {}
        
        v_comp = 'voltage' in compromised or 'voltage_V' in compromised
        i_comp = 'current' in compromised or 'current_A' in compromised
        p_comp = 'power' in compromised or 'power_W' in compromised
        
        num_compromised = sum([v_comp, i_comp, p_comp])
        confidence = 0.0
        
        try:
            if num_compromised == 1:
                if v_comp:
                    if i > 0.01 and pf > 0.01:
                        result['recovered_voltage_V'] = p / (i * pf)
                        confidence = 0.85
                    else:
                        result['recovered_voltage_V'] = last_good.get('voltage_V', 230.0)
                        confidence = 0.4
                    result['recovered_current_A'] = i
                    result['recovered_power_W'] = p
                
                elif i_comp:
                    if v > 0.01 and pf > 0.01:
                        result['recovered_current_A'] = p / (v * pf)
                        confidence = 0.85
                    else:
                        result['recovered_current_A'] = last_good.get('current_A', 0.0)
                        confidence = 0.4
                    result['recovered_voltage_V'] = v
                    result['recovered_power_W'] = p
                    
                elif p_comp:
                    result['recovered_power_W'] = v * i * pf
                    confidence = 0.9
                    result['recovered_voltage_V'] = v
                    result['recovered_current_A'] = i
            else:
                # Multiple parameters compromised, fallback to history or kalman (will have low confidence)
                result['recovered_voltage_V'] = last_good.get('voltage_V', 230.0)
                result['recovered_current_A'] = last_good.get('current_A', 0.0)
                result['recovered_power_W'] = last_good.get('power_W', 0.0)
                confidence = 0.3
                
        except ZeroDivisionError:
            logger.error("ZeroDivisionError in physics reconstruction. Falling back.")
            result['recovered_voltage_V'] = last_good.get('voltage_V', 230.0)
            result['recovered_current_A'] = last_good.get('current_A', 0.0)
            result['recovered_power_W'] = last_good.get('power_W', 0.0)
            confidence = 0.2
            
        result['recovery_confidence'] = confidence
        return result

    def _strategy_kalman_prediction(self, payload: dict, history: list) -> dict:
        """Strategy 3: Kalman Filter prediction-only mode.
        
        Maintains a simple scalar Kalman filter for each parameter (V, I, P).
        In attack mode: skip measurement update, use prediction only.
        This gives a smooth estimate based on the last known dynamics.
        
        State: [value]
        Process model: value_{k+1} = value_k (constant model)
        When legitimate data: full predict + update cycle
        When attack: predict only (no measurement update)
        """
        result = {}
        confidences = []
        
        # If kalman state is empty, try to initialize it from history
        if not self.kalman_states and history:
            last_reading = history[-1]
            self._kalman_update('voltage_V', last_reading.get('voltage_V', 230.0))
            self._kalman_update('current_A', last_reading.get('current_A', 0.0))
            self._kalman_update('power_W', last_reading.get('power_W', 0.0))
            
        for param, default in [('voltage_V', 230.0), ('current_A', 0.0), ('power_W', 0.0)]:
            val, conf = self._kalman_predict(param)
            if val is None:
                val = default
                conf = 0.1
            result[f'recovered_{param}'] = val
            confidences.append(conf)
            
        result['recovery_confidence'] = min(confidences) if confidences else 0.1
        return result
        
    def _fallback_to_defaults(self) -> dict:
        """Returns safe default values with low confidence if no history is available."""
        return {
            'recovered_voltage_V': 230.0,
            'recovered_current_A': 0.0,
            'recovered_power_W': 0.0,
            'recovery_confidence': 0.1
        }

    def add_verified_reading(self, payload: dict):
        """Add a verified (NORMAL) reading to internal history and update Kalman states."""
        self.verified_history.append(payload)
        # Full Kalman predict + update cycle for each parameter
        self._kalman_update('voltage_V', payload.get('voltage_V', 230.0))
        self._kalman_update('current_A', payload.get('current_A', 0.0))
        self._kalman_update('power_W', payload.get('power_W', 0.0))

    def _kalman_update(self, param: str, measurement: float):
        """Full Kalman filter predict + update cycle."""
        if param not in self.kalman_states:
            self.kalman_states[param] = {
                'x': measurement,  # state estimate
                'P': 1.0,  # error covariance
                'Q': self.kalman_process_noise,
                'R': self.kalman_measurement_noise,
                'last_update': time.time(),
            }
            return
        
        state = self.kalman_states[param]
        # Predict
        x_pred = state['x']  # constant model
        P_pred = state['P'] + state['Q']
        # Update
        K = P_pred / (P_pred + state['R'])  # Kalman gain
        state['x'] = x_pred + K * (measurement - x_pred)
        state['P'] = (1 - K) * P_pred
        state['last_update'] = time.time()

    def _kalman_predict(self, param: str) -> tuple:
        """Kalman predict-only step (no measurement update). Returns (predicted_value, confidence)."""
        if param not in self.kalman_states:
            return None, 0.0
        
        state = self.kalman_states[param]
        x_pred = state['x']
        P_pred = state['P'] + state['Q']
        
        # Confidence decreases with time since last real measurement
        time_since = time.time() - state['last_update']
        confidence = max(0.3, 1.0 - (time_since / 300.0))  # Decay over 5 minutes
        
        # Update covariance (grows without measurement)
        state['P'] = P_pred
        
        return x_pred, confidence
