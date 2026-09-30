"""
MODULE: train_model.py
PURPOSE: Standalone utility to train and save the Isolation Forest ML model for FDI detection.
USAGE:
    sudo ./venv/bin/python3 train_model.py
    sudo ./venv/bin/python3 train_model.py --bootstrap  # Generate clean synthetic baseline if DB is empty
"""

import sys
import argparse
import logging
from pathlib import Path
import numpy as np

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import DB_PATH, IF_MODEL_PATH, NODE_ID
from db_manager import DatabaseManager
from fdi_detector import FDIDetector

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')
logger = logging.getLogger('ModelTrainer')


def generate_synthetic_baseline(count: int = 1000, variable_load: bool = True, bulb_loads: bool = True, min_power: float = 20.0, max_power: float = 3000.0) -> list:
    """Generate realistic clean baseline electrical samples for bulb bank or wide variable load profiles."""
    if bulb_loads:
        logger.info(f"Generating {count} synthetic BULB BANK samples (1x 50W + 3x 100W = 50W..350W combinations, PF ~0.99)...")
    elif variable_load:
        logger.info(f"Generating {count} synthetic VARIABLE LOAD samples ({min_power}W to {max_power}W, PF 0.85-0.99)...")
    else:
        logger.info(f"Generating {count} synthetic steady baseline samples (230V, ~60W, PF 0.99)...")
        
    np.random.seed(42)
    samples = []
    
    # 8 physical discrete bulb bank combinations: 0W, 50W, 100W, 150W, 200W, 250W, 300W, 350W
    bulb_power_steps = [5.0, 50.0, 100.0, 150.0, 200.0, 250.0, 300.0, 350.0]
    
    for _ in range(count):
        if bulb_loads:
            # Pick one of the bulb combinations
            base_p = float(np.random.choice(bulb_power_steps))
            # Minor voltage sag with load
            v_drop = (base_p / 230.0) * 0.15
            v = float(np.random.normal(230.0 - v_drop, 1.2))
            # Incandescent bulb voltage exponent: P = P_nom * (V / 230)^1.6
            p_actual = base_p * ((v / 230.0) ** 1.6)
            pf = float(np.clip(np.random.normal(0.99, 0.005), 0.97, 1.0))
            i = float(p_actual / max(v * pf, 0.1))
            p = float(v * i * pf * (1.0 + np.random.normal(0, 0.004)))
        elif variable_load:
            # Multi-modal load distribution (light, medium, heavy household loads)
            mode = np.random.choice(['light', 'medium', 'heavy'], p=[0.4, 0.4, 0.2])
            if mode == 'light':
                p_target = float(np.random.uniform(min_power, 150.0))
            elif mode == 'medium':
                p_target = float(np.random.uniform(150.0, 1000.0))
            else:
                p_target = float(np.random.uniform(1000.0, max_power))
                
            pf = float(np.clip(np.random.normal(0.95, 0.03), 0.85, 0.999))
            v_drop = (p_target / 230.0) * 0.12
            v = float(np.random.normal(230.0 - v_drop, 1.2))
            i = float(p_target / max(v * pf, 0.1))
            p = float(v * i * pf * (1.0 + np.random.normal(0, 0.005)))
        else:
            v = float(np.random.normal(230.0, 1.5))
            i = float(np.random.normal(0.261, 0.008))
            pf = float(np.clip(np.random.normal(0.99, 0.005), 0.95, 1.0))
            p = float(v * i * pf)

        f = float(np.random.normal(50.0, 0.05))
        rssi = int(np.random.normal(-55, 3))
        
        samples.append({
            'voltage_v': v,
            'current_a': i,
            'power_w': p,
            'frequency_hz': f,
            'power_factor': pf,
            'rssi_dbm': rssi,
        })
    return samples


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest model for SmartGrid FDI Detection")
    parser.add_argument('--samples', type=int, default=1000, help="Number of baseline samples to use (default: 1000)")
    parser.add_argument('--bootstrap', action='store_true', help="Generate synthetic clean baseline if DB has few samples")
    parser.add_argument('--bulb-loads', action='store_true', default=True, help="Train specifically on 1x50W + 3x100W bulb bank combinations (default: True)")
    parser.add_argument('--wide-variable', action='store_true', help="Train on wide domestic loads (20W - 3000W)")
    parser.add_argument('--steady-load', action='store_true', help="Train on fixed steady 60W bench load only")
    parser.add_argument('--min-power', type=float, default=20.0, help="Minimum power in Watts for variable load (default: 20W)")
    parser.add_argument('--max-power', type=float, default=3000.0, help="Maximum power in Watts for variable load (default: 3000W)")
    args = parser.parse_args()

    use_bulbs = args.bulb_loads and not args.wide_variable and not args.steady_load
    use_wide = args.wide_variable

    mode_str = "BULB BANK (1x50W + 3x100W combos: 50W-350W)" if use_bulbs else ("WIDE VARIABLE (20W-3000W)" if use_wide else "STEADY 60W")

    print("=" * 60)
    print("      SmartGrid Machine Learning Model Trainer")
    print("=" * 60)
    print(f"Database: {DB_PATH}")
    print(f"Target Model: {IF_MODEL_PATH}")
    print(f"Training Profile: {mode_str}")
    print("-" * 60)

    db = DatabaseManager(DB_PATH)
    baseline_data = db.get_baseline_data(NODE_ID, count=args.samples)
    db.close()

    print(f"Found {len(baseline_data)} clean (NORMAL) readings in database.")

    if len(baseline_data) < 50:
        if args.bootstrap or len(baseline_data) == 0:
            print("[INFO] Generating synthetic baseline to bootstrap the model...")
            training_data = generate_synthetic_baseline(
                count=args.samples,
                variable_load=use_wide,
                bulb_loads=use_bulbs,
                min_power=args.min_power,
                max_power=args.max_power
            )
        else:
            print("[NOTICE] You have less than 50 packets in the database.")
            print("         You can let main.py run with normal bulb loads to collect real data, OR")
            print("         run with --bootstrap to train on bulb bank baseline immediately:")
            print("\n         sudo ./venv/bin/python3 train_model.py --bootstrap\n")
            sys.exit(0)
    else:
        print(f"[INFO] Using {len(baseline_data)} real sensor readings from database for training.")
        training_data = baseline_data

    # Train and save using FDIDetector
    detector = FDIDetector(node_id=NODE_ID, model_path=IF_MODEL_PATH)
    success = detector.train_model(training_data, save=True)

    if success:
        print("-" * 60)
        print("[SUCCESS] Isolation Forest model trained and saved successfully!")
        print(f"  Location: {IF_MODEL_PATH}")
        print("=" * 60)
        print("[INFO] Next time main.py starts, you will see:")
        print(f"       'Loaded Isolation Forest model from {IF_MODEL_PATH.name}'")
    else:
        print("[ERROR] Model training failed. Ensure scikit-learn is installed in your venv.")
        sys.exit(1)


if __name__ == '__main__':
    main()
