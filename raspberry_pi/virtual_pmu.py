"""
MODULE BRIEFING:
Purpose: Virtual Phasor Measurement Unit (PMU) & Synchrophasor Processor.
Implements IEEE C37.118 standard synchrophasor mathematical concepts:
1. Voltage and Current Synchrophasors: V * exp(j * delta_V), I * exp(j * delta_I)
2. Phase Angle tracking relative to nominal 50.00 Hz reference oscillator
3. Rate of Change of Frequency (ROCOF = df/dt) computation
4. Total Vector Error (TVE) estimation against physical power factor reference
5. High-speed phase angle jump / angular instability detection

Dependencies: numpy, time
Research Disclaimer: Academic research and educational testbed for SmartGrid FDIA Shield.
"""

import numpy as np
import time
import logging
from collections import deque
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class VirtualPMUProcessor:
    """
    Virtual PMU processor tracking synchrophasors, phase angles, ROCOF, and TVE.
    """

    def __init__(self, nominal_freq: float = 50.0, max_history: int = 50):
        self.nominal_freq = nominal_freq
        self.max_history = max_history

        # Time-series history for derivative estimation (ROCOF and d_delta/dt)
        self.timestamp_history = deque(maxlen=max_history)
        self.freq_history = deque(maxlen=max_history)
        self.voltage_angle_history = deque(maxlen=max_history)

        # Baseline reference oscillator state
        self.start_epoch = time.time()
        self.last_phase_angle = 0.0

    def process_measurement(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a telemetry sample and produces IEEE C37.118 synchrophasor metrics.

        Args:
            telemetry: Dict containing voltage_V, current_A, frequency_Hz, power_factor,
                       and optional timestamp.
        Returns:
            Dict containing synchrophasor magnitude, phase angle (deg), ROCOF (Hz/s),
            TVE (%), and phase anomaly flags.
        """
        now = float(telemetry.get('timestamp', time.time()))
        v_mag = float(telemetry.get('voltage_V', telemetry.get('voltage_v', 230.0)))
        i_mag = float(telemetry.get('current_A', telemetry.get('current_a', 0.26)))
        freq = float(telemetry.get('frequency_Hz', telemetry.get('frequency_hz', 50.0)))
        pf = float(telemetry.get('power_factor', 0.99))

        # 1. Compute Synchrophasor Phase Angle delta_V
        # If the sender provided explicit phase angle (from digital twin or PMU firmware), use it.
        # Otherwise, calculate continuous phase deviation relative to nominal 50 Hz reference:
        # delta_V(t) = 360 * integral(f(t) - f0) dt (modulo [-180, +180])
        explicit_angle = telemetry.get('phase_angle_deg', None)
        if explicit_angle is not None:
            v_angle_deg = float(explicit_angle)
        else:
            elapsed = now - self.start_epoch
            freq_dev = freq - self.nominal_freq
            # Integrate deviation
            if len(self.timestamp_history) > 0 and len(self.freq_history) > 0:
                dt = max(0.001, now - self.timestamp_history[-1])
                angle_increment = (freq_dev * 360.0 * dt)
                v_angle_deg = (self.last_phase_angle + angle_increment)
            else:
                v_angle_deg = (freq_dev * 360.0 * (elapsed % 1.0))

            # Wrap to [-180, 180]
            v_angle_deg = ((v_angle_deg + 180.0) % 360.0) - 180.0

        self.last_phase_angle = v_angle_deg

        # 2. Compute Current Phase Angle delta_I:
        # PF = cos(delta_V - delta_I)  =>  delta_I = delta_V - arccos(PF)
        pf_clamped = max(-1.0, min(1.0, pf))
        phi_rad = np.arccos(pf_clamped)
        phi_deg = float(np.degrees(phi_rad))
        i_angle_deg = v_angle_deg - phi_deg
        i_angle_deg = ((i_angle_deg + 180.0) % 360.0) - 180.0

        # 3. Calculate Rate of Change of Frequency (ROCOF = df/dt in Hz/s)
        rocof = 0.0
        if len(self.timestamp_history) > 0:
            dt = now - self.timestamp_history[-1]
            if 0.01 <= dt <= 10.0:
                df = freq - self.freq_history[-1]
                rocof = df / dt

        # 4. Total Vector Error (TVE) estimation
        # Compares measured phasor with nominal expected phasor V_nom * exp(j * 0)
        # TVE = |V_meas - V_nom| / |V_nom| * 100%
        v_nom = 230.0
        v_meas_complex = v_mag * np.exp(1j * np.radians(v_angle_deg))
        tve = float(np.abs(v_meas_complex - v_nom) / v_nom * 100.0)

        # 5. Anomaly detection on PMU parameters
        # Grid codes require ROCOF < 1.0 Hz/s under normal operation
        # IEEE C37.118 specifies TVE < 1.0% under normal steady state
        phase_jump_detected = False
        if len(self.voltage_angle_history) > 0:
            angle_diff = abs(v_angle_deg - self.voltage_angle_history[-1])
            if angle_diff > 180.0:
                angle_diff = 360.0 - angle_diff
            if angle_diff > 25.0:  # Sudden 25 degree unphysical phase jump
                phase_jump_detected = True

        rocof_violation = bool(abs(rocof) > 1.5)  # > 1.5 Hz/s is severe disturbance
        tve_violation = bool(tve > 5.0)

        # Update rolling history
        self.timestamp_history.append(now)
        self.freq_history.append(freq)
        self.voltage_angle_history.append(v_angle_deg)

        # PMU Anomaly Score (0.0 to 1.0)
        pmu_anomaly_score = 0.0
        if phase_jump_detected:
            pmu_anomaly_score += 0.5
        if rocof_violation:
            pmu_anomaly_score += 0.3
        if tve_violation:
            pmu_anomaly_score += 0.2
        pmu_anomaly_score = min(1.0, pmu_anomaly_score)

        return {
            'voltage_mag_V': round(v_mag, 2),
            'voltage_angle_deg': round(v_angle_deg, 3),
            'current_mag_A': round(i_mag, 4),
            'current_angle_deg': round(i_angle_deg, 3),
            'power_angle_phi_deg': round(phi_deg, 3),
            'frequency_Hz': round(freq, 4),
            'rocof_Hz_s': round(rocof, 4),
            'total_vector_error_pct': round(tve, 3),
            'phase_jump_detected': phase_jump_detected,
            'rocof_violation': rocof_violation,
            'pmu_anomaly_score': round(pmu_anomaly_score, 4),
            'ieee_c37_118_compliant': bool(tve <= 1.0 and abs(rocof) <= 0.5 and not phase_jump_detected)
        }
