# SmartGrid Digital Twin Simulator

The Digital Twin Simulator provides a virtual ESP32 sensor node backed by a physics-based 3-bus power system model. It is designed to evaluate the FDIA (False Data Injection Attack) Shield detection pipeline without requiring physical hardware.

## Architecture

```text
+-------------------+      +-------------------+      +-------------------+
|                   |      |                   |      |                   |
|  Power Grid Model +----->+  Scenario Engine  +----->+  Twin Simulator   |
|  (Physics logic)  |      |  (Attacks/Faults) |      |  (MQTT / Output)  |
|                   |      |                   |      |                   |
+-------------------+      +-------------------+      +-------------------+
                                                               |
                                                               v
                                                    +-------------------+
                                                    |                   |
                                                    |    MQTT Broker    |
                                                    |   (Mosquitto)     |
                                                    +-------------------+
```

## Installation

```bash
pip install -r requirements_twin.txt
```

## Usage Modes

The simulator operates in two modes:

1. **Standalone Mode** (Testing/Debugging locally):
   ```bash
   python twin_simulator.py --mode standalone --scenario fdi_sudden_spike
   ```

2. **MQTT Mode** (Integration with detection pipeline):
   ```bash
   python twin_simulator.py --mode mqtt --broker 10.59.53.30 --scenario combined_stealth
   ```

## Available Scenarios

- `normal`: 10 minutes of clean, expected operation with realistic daily variations.
- `fdi_voltage_ramp`: Gradually increases voltage readings by 0.5V per step over 5 minutes.
- `fdi_sudden_spike`: Sudden 50V jump at t=120s, returning to normal at t=180s.
- `replay_attack`: Freezes data values for 60s, simulating a replay attack.
- `dos_flood`: High-frequency garbage data flooding the topic.
- `load_variation`: Realistic daily load cycle compressed into 2 hours.
- `combined_stealth`: Subtle FDI (+2% voltage, -5% current) sustained for 3 minutes to evade simple threshold detection.

Use `--list-scenarios` to see available scenarios dynamically.

## Integration

The simulator automatically generates HMAC signatures using the shared project secret (`smartgrid_secret_key_2025`). This means its data is indistinguishable from genuine ESP32 node data on the network, making it perfect for end-to-end testing of the Python detection pipeline.
