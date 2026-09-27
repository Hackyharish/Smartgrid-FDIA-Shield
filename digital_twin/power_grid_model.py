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
        
        # Base load
        self.base_power = 1000.0 # W
        self.current_load = self.base_power
        
        # Current state
        self.voltage_v = nominal_voltage
        self.current_a = 0.0
        self.power_w = 0.0
        self.energy_wh = 0.0
        self.frequency_hz = nominal_frequency
        self.power_factor = 0.95
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
            
    def _apply_noise(self, value, percentage=0.005):
        noise = value * percentage * random.uniform(-1, 1)
        return value + noise
        
    def _calculate_time_varying_load(self):
        # 24-hour cycle, peaking morning (8am) and evening (7pm)
        hour = (self.time_seconds / 3600.0) % 24
        
        # Morning peak around 8
        morning_peak = math.exp(-0.5 * ((hour - 8.0) / 2.0)**2)
        # Evening peak around 19
        evening_peak = math.exp(-0.5 * ((hour - 19.0) / 3.0)**2)
        
        load_multiplier = 0.8 + 0.6 * morning_peak + 0.8 * evening_peak
        return self.base_power * load_multiplier

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
