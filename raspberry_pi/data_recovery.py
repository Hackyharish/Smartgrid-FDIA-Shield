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
        result['original_voltage'] = attack_payload.get('voltage_V')
        result['original_current'] = attack_payload.get('current_A')
        result['original_power'] = attack_payload.get('power_W')
        result['node_id'] = attack_payload.get('node_id', 'node_01')
        result['timestamp'] = result.get('timestamp', attack_payload.get('timestamp', int(time.time())))
        
        return result

    def _strategy_interpolation(self, payload: dict, history: list) -> dict:
        """Strategy 1: Temporal interpolation using polynomial fit on last N verified readings.
        
        Uses numpy polyfit (degree 2) on the last `interpolation_window` verified readings
        for each parameter (V, I, P). Extrapolates to current timestamp.
        
        Confidence based on R² of the polynomial fit or fallback logic.
        """
        result = {}
        confidence = 0.0
        
        if not history:
            return self._fallback_to_defaults()
            
        recent_history = history[-self.interpolation_window:]
        timestamps = [h.get('timestamp', time.time()) for h in recent_history]
        
        # If we don't have enough points for degree 2, drop to degree 1 or just take last known
        degree = 2 if len(recent_history) >= 3 else (1 if len(recent_history) == 2 else 0)
        
        target_timestamp = payload.get('timestamp', time.time())
        if payload.get('attack_type') == 'REPLAY':
             target_timestamp = time.time()
             
        try:
            if degree > 0:
                t_arr = np.array(timestamps)
                # Normalize time to prevent numerical instability
                t_norm = t_arr - t_arr[0]
                target_t_norm = target_timestamp - t_arr[0]
                
                for param in ['voltage_V', 'current_A', 'power_W']:
                    values = np.array([h.get(param, 0.0) for h in recent_history])
                    coeffs = np.polyfit(t_norm, values, degree)
                    poly = np.poly1d(coeffs)
                    predicted_val = poly(target_t_norm)
                    
                    # Compute R^2 proxy for confidence
                    residuals = values - poly(t_norm)
                    ss_res = np.sum(residuals**2)
                    ss_tot = np.sum((values - np.mean(values))**2)
                    r2 = 1 - (ss_res / ss_tot) if ss_tot > 1e-6 else 1.0
                    
                    result[f'recovered_{param}'] = max(0.0, float(predicted_val))
                
                confidence = max(0.4, min(0.95, r2))
            else:
                # Degree 0: just use the last known good reading
                last_reading = recent_history[-1]
                result['recovered_voltage_V'] = last_reading.get('voltage_V', 230.0)
                result['recovered_current_A'] = last_reading.get('current_A', 0.0)
                result['recovered_power_W'] = last_reading.get('power_W', 0.0)
                confidence = 0.6
                
        except Exception as e:
            logger.error(f"Interpolation error: {e}. Falling back to last known reading.")
            last_reading = recent_history[-1]
            result['recovered_voltage_V'] = last_reading.get('voltage_V', 230.0)
            result['recovered_current_A'] = last_reading.get('current_A', 0.0)
            result['recovered_power_W'] = last_reading.get('power_W', 0.0)
            confidence = 0.3
            
        result['recovery_confidence'] = confidence
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
