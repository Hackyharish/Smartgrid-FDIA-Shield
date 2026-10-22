#!/usr/bin/env python3
"""
Standalone generator for Plot 12: Isolation Forest ML Training & Cyber-Physical Parameter Evaluation.
Complies with IEEE publication standards (100% pure white background #ffffff, high-contrast, 300 DPI).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from analysis import SmartGridAnalyzer

def main():
    print("=" * 64)
    print(" SmartGrid FDIA Shield — ML Training & Parameter Visualizer")
    print("=" * 64)
    analyzer = SmartGridAnalyzer()
    try:
        analyzer.plot_12_ml_training_evaluation()
    finally:
        analyzer.close()
    print("=" * 64)

if __name__ == '__main__':
    main()
