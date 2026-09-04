"""
MODULE BRIEFING:
Purpose: Generate visualization plots and metric tables for the SmartGrid project report.
Inputs: Telemetry data, detection logs, and recovery logs from the database.
Outputs: 10 PNG plots and a metrics summary text file saved to the results directory.
Dependencies: numpy, matplotlib, seaborn, db_manager, config.
"""

import json
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for headless Raspberry Pi
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import logging

from db_manager import DatabaseManager
from config import RESULTS_DIR

logger = logging.getLogger(__name__)

class SmartGridAnalyzer:
    def __init__(self, db_path=None, output_dir=None):
        self.db = DatabaseManager(db_path)
        self.output_dir = Path(output_dir) if output_dir else RESULTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        sns.set_theme(style='whitegrid', palette='deep')
        plt.rcParams['figure.figsize'] = (14, 6)
        plt.rcParams['figure.dpi'] = 150
    
    def generate_all_plots(self, since_timestamp=0):
        """Generate all 10 plots from stored data."""
        print('Generating all analysis plots...')
        
        # Load data
        detections = self.db.get_all_detection_results(since_timestamp)
        verified = self.db.get_all_verified_telemetry(since_timestamp)
        
        if not detections:
            print('No detection data found. Run tests first.')
            return
        
        # Generate each plot
        self.plot_1_voltage_current_power(verified)
        self.plot_2_attack_confidence_timeline(detections)
        self.plot_3_roc_curve(detections)
        self.plot_4_recovery_accuracy(since_timestamp)
        self.plot_5_detector_comparison(detections)
        self.plot_6_confusion_matrix(detections)
        self.plot_7_attack_type_pie(detections)
        self.plot_8_detector_heatmap(detections)
        self.plot_9_ip_spoof_detail(detections)
        self.plot_10_fingerprint_distribution(detections)
        
        # Generate metrics table
        self.generate_metrics_table(detections, since_timestamp)
        
        print(f'All plots saved to {self.output_dir}')
    
    def plot_1_voltage_current_power(self, verified):
        """Plot 1: V/I/P time-series from verified telemetry."""
        if not verified:
            return
        
        timestamps = [datetime.fromtimestamp(v['timestamp']) for v in verified]
        voltages = [v.get('voltage_v', 0) for v in verified]
        currents = [v.get('current_a', 0) for v in verified]
        powers = [v.get('power_w', 0) for v in verified]
        sources = [v.get('data_source', 'ORIGINAL') for v in verified]
        
        fig, axes = plt.subplots(3, 1, figsize=(16, 12), sharex=True)
        fig.suptitle('SmartGrid Telemetry — Voltage, Current, Power', fontsize=16, fontweight='bold')
        
        # Color by data source
        colors = ['#2ecc71' if s == 'ORIGINAL' else '#e74c3c' for s in sources]
        
        axes[0].scatter(timestamps, voltages, c=colors, s=5, alpha=0.7)
        axes[0].set_ylabel('Voltage (V)')
        axes[0].axhline(y=230, color='gray', linestyle='--', alpha=0.5, label='Nominal 230V')
        axes[0].legend()
        
        axes[1].scatter(timestamps, currents, c=colors, s=5, alpha=0.7)
        axes[1].set_ylabel('Current (A)')
        
        axes[2].scatter(timestamps, powers, c=colors, s=5, alpha=0.7)
        axes[2].set_ylabel('Power (W)')
        axes[2].set_xlabel('Time')
        
        for ax in axes:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
            ax.grid(True, alpha=0.3)
        
        # Legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor='#2ecc71', label='Original'),
                          Patch(facecolor='#e74c3c', label='Recovered')]
        fig.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_01_vip_timeseries.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 1: V/I/P time-series')
    
    def plot_2_attack_confidence_timeline(self, detections):
        """Plot 2: Attack confidence over time with threshold line."""
        if not detections:
            return
        
        timestamps = [datetime.fromtimestamp(d['timestamp']) for d in detections]
        confidences = [d.get('attack_confidence', 0) for d in detections]
        statuses = [d.get('status', 'NORMAL') for d in detections]
        
        colors = {'NORMAL': '#2ecc71', 'SUSPICIOUS': '#f39c12', 'ATTACK_DETECTED': '#e74c3c'}
        point_colors = [colors.get(s, '#95a5a6') for s in statuses]
        
        fig, ax = plt.subplots(figsize=(16, 6))
        ax.scatter(timestamps, confidences, c=point_colors, s=10, alpha=0.7)
        ax.axhline(y=0.6, color='red', linestyle='--', label='Attack Threshold (0.6)', alpha=0.8)
        ax.axhline(y=0.35, color='orange', linestyle='--', label='Suspicious Threshold (0.35)', alpha=0.6)
        ax.set_ylabel('Attack Confidence Score')
        ax.set_xlabel('Time')
        ax.set_title('Attack Confidence Timeline', fontsize=14, fontweight='bold')
        ax.set_ylim(-0.05, 1.05)
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_02_confidence_timeline.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 2: Confidence timeline')
    
    def plot_3_roc_curve(self, detections):
        """Plot 3: ROC-like curve showing detection performance."""
        # Simple threshold sweep to generate ROC-like curve
        # True label: any non-NORMAL in ground truth is positive
        confidences = np.array([d.get('attack_confidence', 0) for d in detections])
        labels = np.array([1 if d.get('status') != 'NORMAL' else 0 for d in detections])
        
        if len(np.unique(labels)) < 2:
            print('  ⚠ Plot 3: Skipped (need both normal and attack data for ROC)')
            return
        
        thresholds = np.linspace(0, 1, 100)
        tprs, fprs = [], []
        
        for t in thresholds:
            predicted = (confidences >= t).astype(int)
            tp = np.sum((predicted == 1) & (labels == 1))
            fp = np.sum((predicted == 1) & (labels == 0))
            fn = np.sum((predicted == 0) & (labels == 1))
            tn = np.sum((predicted == 0) & (labels == 0))
            
            tpr = tp / max(tp + fn, 1)
            fpr = fp / max(fp + tn, 1)
            tprs.append(tpr)
            fprs.append(fpr)
        
        fig, ax = plt.subplots(figsize=(8, 8))
        ax.plot(fprs, tprs, 'b-', linewidth=2, label='FDI Detector')
        ax.plot([0, 1], [0, 1], 'k--', alpha=0.3, label='Random')
        ax.fill_between(fprs, tprs, alpha=0.1)
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title('ROC Curve — FDI Detection Performance', fontsize=14, fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        # Compute AUC
        auc = np.trapz(tprs, fprs)
        ax.text(0.6, 0.2, f'AUC = {abs(auc):.3f}', fontsize=14,
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_03_roc_curve.png', bbox_inches='tight')
        plt.close()
        print(f'  ✓ Plot 3: ROC curve (AUC={abs(auc):.3f})')
    
    def plot_4_recovery_accuracy(self, since_timestamp=0):
        """Plot 4: Recovery accuracy — original vs recovered values."""
        # Query recovery logs from DB
        conn = self.db.conn
        cursor = conn.execute(
            'SELECT original_voltage, original_current, original_power, '
            'recovered_voltage, recovered_current, recovered_power, '
            'recovery_confidence, strategy_used '
            'FROM recovery_log WHERE timestamp >= ?', (since_timestamp,)
        )
        rows = cursor.fetchall()
        
        if not rows:
            print('  ⚠ Plot 4: No recovery data found')
            return
        
        orig_v = [r[0] or 0 for r in rows]
        orig_p = [r[2] or 0 for r in rows]
        rec_v = [r[3] or 0 for r in rows]
        rec_p = [r[5] or 0 for r in rows]
        confidences = [r[6] or 0 for r in rows]
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Data Recovery Accuracy', fontsize=14, fontweight='bold')
        
        axes[0].scatter(orig_v, rec_v, c=confidences, cmap='RdYlGn', alpha=0.6, s=20)
        axes[0].plot([min(orig_v+rec_v), max(orig_v+rec_v)],
                    [min(orig_v+rec_v), max(orig_v+rec_v)], 'k--', alpha=0.3)
        axes[0].set_xlabel('Reported Voltage (V)')
        axes[0].set_ylabel('Recovered Voltage (V)')
        axes[0].set_title('Voltage Recovery')
        
        axes[1].scatter(orig_p, rec_p, c=confidences, cmap='RdYlGn', alpha=0.6, s=20)
        axes[1].plot([min(orig_p+rec_p), max(orig_p+rec_p)],
                    [min(orig_p+rec_p), max(orig_p+rec_p)], 'k--', alpha=0.3)
        axes[1].set_xlabel('Reported Power (W)')
        axes[1].set_ylabel('Recovered Power (W)')
        axes[1].set_title('Power Recovery')
        
        for ax in axes:
            ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_04_recovery_accuracy.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 4: Recovery accuracy')
    
    def plot_5_detector_comparison(self, detections):
        """Plot 5: Box plot comparing individual detector scores."""
        scores = {
            'Physics': [d.get('physics_score', 0) for d in detections],
            'Z-Score': [d.get('z_score_normalized', 0) for d in detections],
            'ML (IF)': [d.get('ml_score', 0) for d in detections],
            'HMAC': [d.get('hmac_score', 0) for d in detections],
            'Fingerprint': [d.get('fingerprint_score', 0) for d in detections],
        }
        
        fig, ax = plt.subplots(figsize=(12, 6))
        positions = range(len(scores))
        bp = ax.boxplot(scores.values(), labels=scores.keys(), patch_artist=True)
        
        colors = ['#3498db', '#e67e22', '#2ecc71', '#e74c3c', '#9b59b6']
        for patch, color in zip(bp['boxes'], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        
        ax.set_ylabel('Score (0.0 — 1.0)')
        ax.set_title('Individual Detector Score Distribution', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_05_detector_comparison.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 5: Detector comparison')
    
    def plot_6_confusion_matrix(self, detections):
        """Plot 6: Confusion matrix for attack detection."""
        # Simplified: NORMAL vs ATTACK (merging SUSPICIOUS into threshold analysis)
        true_labels = []  # We'll use attack_type as ground truth indicator
        pred_labels = []
        
        for d in detections:
            has_attack = d.get('attack_type') is not None
            detected = d.get('status') == 'ATTACK_DETECTED'
            true_labels.append(1 if has_attack else 0)
            pred_labels.append(1 if detected else 0)
        
        # Build confusion matrix
        tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 1)
        fp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 1)
        fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 0)
        tn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 0)
        
        cm = np.array([[tn, fp], [fn, tp]])
        
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                   xticklabels=['Normal', 'Attack'],
                   yticklabels=['Normal', 'Attack'])
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')
        ax.set_title('Detection Confusion Matrix', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_06_confusion_matrix.png', bbox_inches='tight')
        plt.close()
        print(f'  ✓ Plot 6: Confusion matrix (TP={tp}, FP={fp}, FN={fn}, TN={tn})')
    
    def plot_7_attack_type_pie(self, detections):
        """Plot 7: Attack type breakdown pie chart."""
        type_counts = {'NORMAL': 0}
        for d in detections:
            at = d.get('attack_type') or 'NORMAL'
            type_counts[at] = type_counts.get(at, 0) + 1
        
        labels = list(type_counts.keys())
        sizes = list(type_counts.values())
        colors_map = {
            'NORMAL': '#2ecc71',
            'FDI_FIRMWARE': '#e74c3c',
            'IP_SPOOF_CONFIRMED': '#3498db',
            'TAMPERED_OR_SPOOFED': '#9b59b6',
            'REPLAY': '#f39c12',
        }
        colors = [colors_map.get(l, '#95a5a6') for l in labels]
        
        fig, ax = plt.subplots(figsize=(10, 8))
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=colors, autopct='%1.1f%%',
            startangle=90, pctdistance=0.85
        )
        for autotext in autotexts:
            autotext.set_fontsize(10)
        
        ax.set_title('Attack Type Distribution', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_07_attack_type_pie.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 7: Attack type pie chart')
    
    def plot_8_detector_heatmap(self, detections):
        """Plot 8: Detector signal heatmap over time."""
        if len(detections) < 2:
            print('  ⚠ Plot 8: Not enough data for heatmap')
            return
        
        # Build matrix: rows = detectors, cols = packets
        detector_names = ['Physics', 'Z-Score', 'ML (IF)', 'HMAC', 'Fingerprint']
        n_packets = len(detections)
        matrix = np.zeros((5, n_packets))
        
        for j, d in enumerate(detections):
            matrix[0, j] = d.get('physics_score', 0)
            matrix[1, j] = d.get('z_score_normalized', 0)
            matrix[2, j] = d.get('ml_score', 0)
            matrix[3, j] = d.get('hmac_score', 0)
            matrix[4, j] = d.get('fingerprint_score', 0)
        
        fig, ax = plt.subplots(figsize=(20, 5))
        im = ax.imshow(matrix, aspect='auto', cmap='RdYlBu_r', vmin=0, vmax=1,
                       interpolation='nearest')
        ax.set_yticks(range(5))
        ax.set_yticklabels(detector_names)
        ax.set_xlabel('Packet Number')
        ax.set_title('Detector Signal Heatmap — Which Detectors Fire During Attacks',
                     fontsize=14, fontweight='bold')
        plt.colorbar(im, ax=ax, label='Signal Strength (0=normal, 1=anomaly)')
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_08_detector_heatmap.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 8: Detector heatmap')
    
    def plot_9_ip_spoof_detail(self, detections):
        """Plot 9: IP Spoofing episode detail (TTL, HMAC, confidence)."""
        # Filter to spoof-related detections
        spoof_detections = [d for d in detections
                           if d.get('attack_type') in ('IP_SPOOF_CONFIRMED', 'TAMPERED_OR_SPOOFED')
                           or d.get('hmac_score', 0) > 0
                           or d.get('fingerprint_score', 0) > 0.3]
        
        if not spoof_detections:
            print('  ⚠ Plot 9: No IP spoofing data found')
            return
        
        timestamps = [datetime.fromtimestamp(d['timestamp']) for d in spoof_detections]
        hmac_scores = [d.get('hmac_score', 0) for d in spoof_detections]
        fp_scores = [d.get('fingerprint_score', 0) for d in spoof_detections]
        confidences = [d.get('attack_confidence', 0) for d in spoof_detections]
        
        fig, axes = plt.subplots(3, 1, figsize=(16, 10), sharex=True)
        fig.suptitle('IP Spoofing Attack Detection Timeline', fontsize=14, fontweight='bold')
        
        # HMAC validity
        hmac_colors = ['#e74c3c' if h > 0 else '#2ecc71' for h in hmac_scores]
        axes[0].bar(range(len(hmac_scores)), hmac_scores, color=hmac_colors, alpha=0.7)
        axes[0].set_ylabel('HMAC Score')
        axes[0].set_title('HMAC Validity (Red=Invalid, Green=Valid)')
        axes[0].set_ylim(-0.1, 1.1)
        
        # Fingerprint score
        axes[1].plot(range(len(fp_scores)), fp_scores, 'b-o', markersize=3, alpha=0.7)
        axes[1].axhline(y=0.5, color='red', linestyle='--', alpha=0.5, label='Spoof threshold')
        axes[1].set_ylabel('Fingerprint Score')
        axes[1].set_title('Network Fingerprint Score')
        axes[1].legend()
        
        # Confidence
        axes[2].plot(range(len(confidences)), confidences, 'r-o', markersize=3, alpha=0.7)
        axes[2].axhline(y=0.6, color='red', linestyle='--', alpha=0.5)
        axes[2].set_ylabel('Attack Confidence')
        axes[2].set_xlabel('Packet Number')
        axes[2].set_title('Overall Attack Confidence')
        
        for ax in axes:
            ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_09_ip_spoof_detail.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 9: IP spoof detail')
    
    def plot_10_fingerprint_distribution(self, detections):
        """Plot 10: Fingerprint score distribution — normal vs attack."""
        normal_fps = [d.get('fingerprint_score', 0) for d in detections if d.get('status') == 'NORMAL']
        attack_fps = [d.get('fingerprint_score', 0) for d in detections if d.get('status') == 'ATTACK_DETECTED']
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if normal_fps:
            ax.hist(normal_fps, bins=30, alpha=0.6, color='#2ecc71', label=f'Normal (n={len(normal_fps)})')
        if attack_fps:
            ax.hist(attack_fps, bins=30, alpha=0.6, color='#e74c3c', label=f'Attack (n={len(attack_fps)})')
        
        ax.set_xlabel('Network Fingerprint Score')
        ax.set_ylabel('Frequency')
        ax.set_title('Fingerprint Score Distribution — Normal vs Attack',
                     fontsize=14, fontweight='bold')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_10_fingerprint_distribution.png', bbox_inches='tight')
        plt.close()
        print('  ✓ Plot 10: Fingerprint distribution')
    
    def generate_metrics_table(self, detections, since_timestamp=0):
        """Generate and print the full metrics table."""
        stats = self.db.get_detection_stats(since_timestamp)
        spoof_stats = self.db.get_spoof_summary(since_timestamp)
        
        total = stats.get('total_packets', 0)
        normal = stats.get('normal_count', 0)
        attack = stats.get('attack_count', 0)
        suspicious = stats.get('suspicious_count', 0)
        
        # IP spoof metrics
        spoof_hmac = spoof_stats.get('detected_by_hmac', 0)
        spoof_fp = spoof_stats.get('detected_by_fingerprint', 0)
        spoof_both = spoof_stats.get('detected_by_both', 0)
        spoof_total = spoof_stats.get('total_spoof_episodes', 0)
        
        table = f"""
╔══════════════════════════════════════════════════════╗
║             SMARTGRID DETECTION METRICS               ║
╠══════════════════════════════════════════════╤═══════╣
║  Total Packets Processed                    │ {total:>5} ║
║  Normal                                     │ {normal:>5} ║
║  Suspicious                                 │ {suspicious:>5} ║
║  Attack Detected                            │ {attack:>5} ║
╠══════════════════════════════════════════════╧═══════╣
║  IP SPOOFING METRICS                                 ║
╠══════════════════════════════════════════════╤═══════╣
║  IP Spoof Episodes                          │ {spoof_total:>5} ║
║  Detected by HMAC                           │ {spoof_hmac:>5} ║
║  Detected by Fingerprint                    │ {spoof_fp:>5} ║
║  Detected by Both                           │ {spoof_both:>5} ║
╚══════════════════════════════════════════════╧═══════╝
"""
        print(table)
        
        # Save to file
        with open(self.output_dir / 'metrics_table.txt', 'w', encoding='utf-8') as f:
            f.write(table)
        print('  ✓ Metrics table saved')
    
    def close(self):
        self.db.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description='SmartGrid Analysis & Visualization')
    parser.add_argument('--since', type=int, default=0, help='Analyze data since this Unix timestamp')
    parser.add_argument('--output', type=str, default=None, help='Output directory for plots')
    args = parser.parse_args()
    
    analyzer = SmartGridAnalyzer(output_dir=args.output)
    try:
        analyzer.generate_all_plots(args.since)
    finally:
        analyzer.close()

if __name__ == '__main__':
    main()
