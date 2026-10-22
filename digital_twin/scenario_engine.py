"""
MODULE BRIEFING
---------------
Module: scenario_engine
Purpose: Defines attack and fault scenarios for the digital twin simulator.
Yields generated payloads with timestamps and flags indicating if it's an attack.
"""
import time
from datetime import datetime

class ScenarioEngine:
    def __init__(self, grid_model):
        self.grid = grid_model
        
    @staticmethod
    def list_scenarios():
        return [
            'normal',
            'fdi_voltage_ramp',
            'fdi_sudden_spike',
            'replay_attack',
            'dos_flood',
            'load_variation',
            'combined_stealth'
        ]
        
    def run_scenario(self, scenario_name, step_dt=5.0):
        if scenario_name == 'normal':
            return self._normal_scenario(step_dt)
        elif scenario_name == 'fdi_voltage_ramp':
            return self._fdi_voltage_ramp(step_dt)
        elif scenario_name == 'fdi_sudden_spike':
            return self._fdi_sudden_spike(step_dt)
        elif scenario_name == 'replay_attack':
            return self._replay_attack(step_dt)
        elif scenario_name == 'dos_flood':
            return self._dos_flood(step_dt)
        elif scenario_name == 'load_variation':
            return self._load_variation(step_dt)
        elif scenario_name == 'combined_stealth':
            return self._combined_stealth(step_dt)
        else:
            raise ValueError(f"Unknown scenario: {scenario_name}")

    def _generate_timestamp(self):
        return datetime.utcnow().isoformat() + "Z"

    def _normal_scenario(self, step_dt):
        # 10 minutes (600 seconds)
        duration = 600
        steps = int(duration / step_dt)
        for _ in range(steps):
            readings = self.grid.step(step_dt)
            yield self._generate_timestamp(), readings, False, 'none'

    def _fdi_voltage_ramp(self, step_dt):
        # 5 mins (300 seconds)
        duration = 300
        steps = int(duration / step_dt)
        ramp = 0.0
        for _ in range(steps):
            readings = self.grid.step(step_dt)
            readings['voltage_V'] += ramp
            ramp += 0.5
            yield self._generate_timestamp(), readings, True, 'fdi_voltage_ramp'

    def _fdi_sudden_spike(self, step_dt):
        # Spike at t=120s, returns normal at t=180s
        duration = 300
        steps = int(duration / step_dt)
        t = 0
        for _ in range(steps):
            readings = self.grid.step(step_dt)
            if 120 <= t <= 180:
                readings['voltage_V'] += 50.0
                is_attack = True
                atk_type = 'fdi_sudden_spike'
            else:
                is_attack = False
                atk_type = 'none'
            
            t += step_dt
            yield self._generate_timestamp(), readings, is_attack, atk_type

    def _replay_attack(self, step_dt):
        # 60s frozen values
        duration = 120
        steps = int(duration / step_dt)
        frozen_readings = None
        t = 0
        for _ in range(steps):
            readings = self.grid.step(step_dt)
            if 30 <= t <= 90:
                if frozen_readings is None:
                    frozen_readings = readings.copy()
                readings = frozen_readings.copy()
                is_attack = True
                atk_type = 'replay_attack'
            else:
                is_attack = False
                atk_type = 'none'
                frozen_readings = None
                
            t += step_dt
            yield self._generate_timestamp(), readings, is_attack, atk_type

    def _dos_flood(self, step_dt):
        # High rate garbage data
        for _ in range(100):
            readings = self.grid.step(0.1) # tiny step
            readings['voltage_V'] = -9999.9
            yield self._generate_timestamp(), readings, True, 'dos_flood'

    def _load_variation(self, step_dt):
        # 2 hour compressed to simulate daily load cycle
        duration = 120
        steps = int(duration / step_dt)
        for _ in range(steps):
            readings = self.grid.step(720) 
            yield self._generate_timestamp(), readings, False, 'none'

    def _combined_stealth(self, step_dt):
        # +2% voltage, -5% current sustained for 3 min
        duration = 300
        steps = int(duration / step_dt)
        t = 0
        for _ in range(steps):
            readings = self.grid.step(step_dt)
            if 60 <= t <= 240:
                readings['voltage_V'] = round(readings['voltage_V'] * 1.02, 2)
                readings['current_A'] = round(readings['current_A'] * 0.95, 2)
                is_attack = True
                atk_type = 'combined_stealth'
            else:
                is_attack = False
                atk_type = 'none'
            
            t += step_dt
            yield self._generate_timestamp(), readings, is_attack, atk_type
