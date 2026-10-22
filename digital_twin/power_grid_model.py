"""
MODULE BRIEFING
---------------
Module: power_grid_model
Purpose: Simulates a simple 3-bus radial distribution network.
Provides telemetry readings for a digital twin ESP32 node.
Includes power flow simplified logic, fault injection, noise, and time-varying load.
"""

import math
import random
import time
from datetime import datetime

class PowerGridModel:
    def __init__(self, nominal_voltage=230.0, nominal_frequency=50.0):
        self.nominal_voltage = nominal_voltage
        self.nominal_frequency = nominal_frequency
        
        # Grid state
        self.time_seconds = 0.0
        
        # Line parameters
        self.z_line = 0.1 # ohms
        
        # Physical Testbed Bulb Configuration:
        # 1x 50W bulb + 3x 100W bulbs (Total possible: 50W, 100W, 150W, 200W, 250W, 300W, 350W)
        self.bulbs_nominal = [50.0, 100.0, 100.0, 100.0]
        self.active_bulbs = [True, False, False, False]  # Default: 50W bulb on
        self.auto_cycle_bulbs = True
        
        # Base load
        self.base_power = 50.0  # W
        self.current_load = self.base_power
        
        # Current state
        self.voltage_v = nominal_voltage
        self.current_a = 0.22
        self.power_w = 50.0
        self.energy_wh = 0.0
        self.frequency_hz = nominal_frequency
        self.power_factor = 0.99
        self.phase_angle_deg = 0.0
        self.rocof_hz_s = 0.0
        self.last_freq = nominal_frequency
        
        # Faults
        self.faults = {
            'line_fault': False,
            'overload': False,
            'frequency_deviation': False
        }
        
    def set_fault(self, fault_type, state=True):
        if fault_type in self.faults:
            self.faults[fault_type] = state

    def set_bulbs(self, b50=False, b100_1=False, b100_2=False, b100_3=False):
        """Manually control the 4 physical bulbs."""
        self.auto_cycle_bulbs = False
        self.active_bulbs = [b50, b100_1, b100_2, b100_3]
            
    def _apply_noise(self, value, percentage=0.005):
        noise = value * percentage * random.uniform(-1, 1)
        return value + noise
        
    def _calculate_time_varying_load(self):
        """Simulates turning the 1x50W and 3x100W bulbs on and off across combinations."""
        if self.auto_cycle_bulbs:
            # 8 discrete bulb combinations: 0W, 50W, 100W, 150W, 200W, 250W, 300W, 350W
            cycle_idx = int((self.time_seconds // 20) % 8)
            combos = [
                [False, False, False, False],  # Idle / Standby (~5W)
                [True,  False, False, False],  # 50W
                [False, True,  False, False],  # 100W
                [True,  True,  False, False],  # 150W
                [False, True,  True,  False],  # 200W
                [True,  True,  True,  False],  # 250W
                [False, True,  True,  True ],  # 300W
                [True,  True,  True,  True ],  # 350W (Full load)
            ]
            self.active_bulbs = combos[cycle_idx]

        active_power = sum(b_nom for b_nom, active in zip(self.bulbs_nominal, self.active_bulbs) if active)
        if active_power == 0:
            active_power = 5.0  # minimal idle standby consumption

        # Incandescent bulb voltage dependency: P = P_nom * (V / V_nom)^1.6
        v_ratio = max(0.5, self.voltage_v / self.nominal_voltage)
        actual_power = active_power * (v_ratio ** 1.6)
        return actual_power

    def step(self, dt):
        self.time_seconds += dt
        
        # Base load variation
        load_w = self._calculate_time_varying_load()
        
        # Apply faults
        if self.faults['overload']:
            load_w *= 2.5
            
        freq = self.nominal_frequency
        if self.faults['frequency_deviation']:
            freq -= 2.0
            
        v_source = self.nominal_voltage
        if self.faults['line_fault']:
            v_source *= 0.6 # Sag
            
        # Power flow calculation:
        # V_drop = I * Z_line, Power angle delta ≈ (P * X) / (V1 * V2)
        approx_i = load_w / (v_source * self.power_factor)
        v_drop = approx_i * self.z_line
        
        self.voltage_v = v_source - v_drop
        self.current_a = load_w / (self.voltage_v * self.power_factor)
        self.power_w = self.voltage_v * self.current_a * self.power_factor
        
        # Rate of Change of Frequency (ROCOF)
        self.rocof_hz_s = (freq - self.last_freq) / max(0.001, dt)
        self.last_freq = freq
        self.frequency_hz = freq

        # Synchrophasor phase angle (load power angle delta in degrees)
        # delta ≈ - (P * X_line) / (V_nom^2) * (180 / pi)
        x_line = 0.08  # inductive line reactance
        angle_rad = - (self.power_w * x_line) / (self.nominal_voltage ** 2)
        self.phase_angle_deg = math.degrees(angle_rad)
        
        # Apply noise
        self.voltage_v = self._apply_noise(self.voltage_v)
        self.current_a = self._apply_noise(self.current_a)
        self.power_w = self._apply_noise(self.power_w)
        self.frequency_hz = self._apply_noise(self.frequency_hz, 0.001)
        self.power_factor = self._apply_noise(self.power_factor, 0.001)
        self.phase_angle_deg = self._apply_noise(self.phase_angle_deg, 0.01)
        
        # Update energy
        self.energy_wh += (self.power_w * (dt / 3600.0))
        
        return self.get_readings()

    def get_readings(self):
        return {
            'voltage_V': round(self.voltage_v, 2),
            'current_A': round(self.current_a, 4),
            'power_W': round(self.power_w, 2),
            'energy_Wh': round(self.energy_wh, 2),
            'frequency_Hz': round(self.frequency_hz, 4),
            'power_factor': round(self.power_factor, 3),
            'phase_angle_deg': round(self.phase_angle_deg, 3),
            'rocof_Hz_s': round(self.rocof_hz_s, 4),
        }
