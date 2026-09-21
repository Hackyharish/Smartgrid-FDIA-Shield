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


def generate_synthetic_baseline(count: int = 500) -> list:
    """Generate realistic clean baseline electrical samples for bootstrapping."""
    logger.info(f"Generating {count} synthetic clean baseline samples (230V, ~60W, PF 0.99)...")
    np.random.seed(42)
    samples = []
    
    for _ in range(count):
        # Realistic grid fluctuations
        v = float(np.random.normal(230.0, 1.5))
        i = float(np.random.normal(0.261, 0.008))
        pf = float(np.clip(np.random.normal(0.99, 0.005), 0.95, 1.0))
        p = float(v * i * pf)
        f = float(np.random.normal(50.0, 0.08))
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
    parser.add_argument('--samples', type=int, default=500, help="Number of baseline samples to use (default: 500)")
    parser.add_argument('--bootstrap', action='store_true', help="Generate synthetic clean baseline if DB has few samples")
    args = parser.parse_args()

    print("=" * 60)
    print("      SmartGrid Machine Learning Model Trainer")
    print("=" * 60)
    print(f"Database: {DB_PATH}")
    print(f"Target Model: {IF_MODEL_PATH}")
    print("-" * 60)

    db = DatabaseManager(DB_PATH)
    baseline_data = db.get_baseline_data(NODE_ID, count=args.samples)
    db.close()

    print(f"Found {len(baseline_data)} clean (NORMAL) readings in database.")

    if len(baseline_data) < 20:
        if args.bootstrap or len(baseline_data) == 0:
            print("[INFO] Using synthetic clean baseline generation to bootstrap the model...")
            training_data = generate_synthetic_baseline(count=args.samples)
        else:
            print("[NOTICE] You have less than 20 packets in the database.")
            print("         You can let main.py run for 2-3 minutes to collect more, OR")
            print("         run with --bootstrap to train on realistic baseline data immediately:")
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
        print("✓ SUCCESS: Isolation Forest model trained and saved successfully!")
        print(f"  Location: {IF_MODEL_PATH}")
        print("=" * 60)
        print("[INFO] Next time main.py starts, you will see:")
        print(f"       'Loaded Isolation Forest model from {IF_MODEL_PATH.name}'")
    else:
        print("✗ ERROR: Model training failed. Ensure scikit-learn is installed in your venv.")
        sys.exit(1)


if __name__ == '__main__':
    main()
