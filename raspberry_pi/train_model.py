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


def generate_synthetic_baseline(count: int = 1000, variable_load: bool = True, min_power: float = 20.0, max_power: float = 3000.0) -> list:
    """Generate realistic clean baseline electrical samples with variable load profiles."""
    if variable_load:
        logger.info(f"Generating {count} synthetic VARIABLE LOAD samples ({min_power}W to {max_power}W, PF 0.85-0.99)...")
    else:
        logger.info(f"Generating {count} synthetic steady baseline samples (230V, ~60W, PF 0.99)...")
        
    np.random.seed(42)
    samples = []
    
    for _ in range(count):
        if variable_load:
            # Multi-modal load distribution (light, medium, heavy household loads)
            mode = np.random.choice(['light', 'medium', 'heavy'], p=[0.4, 0.4, 0.2])
            if mode == 'light':
                p_target = float(np.random.uniform(min_power, 150.0))
            elif mode == 'medium':
                p_target = float(np.random.uniform(150.0, 1000.0))
            else:
                p_target = float(np.random.uniform(1000.0, max_power))
                
            pf = float(np.clip(np.random.normal(0.95, 0.03), 0.85, 0.999))
            # Minor line drop: V_drop = (P / 230) * 0.15 ohm
            v_drop = (p_target / 230.0) * 0.12
            v = float(np.random.normal(230.0 - v_drop, 1.2))
            i = float(p_target / max(v * pf, 0.1))
            # Measurement consistency: P ≈ V * I * PF with ±0.5% sensor noise
            p = float(v * i * pf * (1.0 + np.random.normal(0, 0.005)))
        else:
            v = float(np.random.normal(230.0, 1.5))
            i = float(np.random.normal(0.261, 0.008))
            pf = float(np.clip(np.random.normal(0.99, 0.005), 0.95, 1.0))
            p = float(v * i * pf)

        f = float(np.random.normal(50.0, 0.06))
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
    parser.add_argument('--variable-load', action='store_true', default=True, help="Train on variable load distribution (default: True)")
    parser.add_argument('--steady-load', action='store_true', help="Train on fixed steady 60W bench load only")
    parser.add_argument('--min-power', type=float, default=20.0, help="Minimum power in Watts for variable load (default: 20W)")
    parser.add_argument('--max-power', type=float, default=3000.0, help="Maximum power in Watts for variable load (default: 3000W)")
    args = parser.parse_args()

    use_variable = not args.steady_load

    print("=" * 60)
    print("      SmartGrid Machine Learning Model Trainer")
    print("=" * 60)
    print(f"Database: {DB_PATH}")
    print(f"Target Model: {IF_MODEL_PATH}")
    print(f"Mode: {'VARIABLE LOAD (' + str(args.min_power) + 'W - ' + str(args.max_power) + 'W)' if use_variable else 'STEADY 60W LOAD'}")
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
                variable_load=use_variable,
                min_power=args.min_power,
                max_power=args.max_power
            )
        else:
            print("[NOTICE] You have less than 50 packets in the database.")
            print("         You can let main.py run with normal variable load to collect real data, OR")
            print("         run with --bootstrap to train on variable load baseline immediately:")
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
