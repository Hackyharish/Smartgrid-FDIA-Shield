"""
MODULE BRIEFING:
Purpose: Generate publication-quality visualization plots and metric tables for SmartGrid FDIA Shield.
Design: Pure white background (#ffffff), high-contrast palettes, 300 DPI, IEEE-ready formatting.
Inputs: Telemetry data, detection logs, and recovery logs from SQLite database.
Outputs: 11 high-contrast PNG plots, metrics summary text file, and complete CSV export.
Dependencies: numpy, matplotlib, seaborn, db_manager, config.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import matplotlib
matplotlib.use('Agg')  # Headless backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns

from db_manager import DatabaseManager
from config import RESULTS_DIR, DB_PATH

logger = logging.getLogger(__name__)

def apply_white_contrast_theme():
    """Apply a strict pure white background with high-contrast text and dark lines."""
    plt.style.use('default')
    plt.rcParams.update({
        'figure.facecolor': '#ffffff',
        'axes.facecolor': '#ffffff',
        'savefig.facecolor': '#ffffff',
        'axes.edgecolor': '#111111',
        'axes.linewidth': 1.2,
        'grid.color': '#dcdcdc',
        'grid.linestyle': '--',
        'grid.alpha': 0.75,
        'font.family': 'sans-serif',
        'font.size': 11,
        'axes.labelsize': 12,
        'axes.labelweight': 'bold',
        'axes.titlesize': 13,
        'axes.titleweight': 'bold',
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'legend.frameon': True,
        'legend.edgecolor': '#111111',
        'legend.facecolor': '#ffffff',
        'figure.dpi': 300,
        'savefig.dpi': 300,
    })

class SmartGridAnalyzer:
    def __init__(self, db_path=None, output_dir=None):
        self.db = DatabaseManager(db_path or DB_PATH)
        self.output_dir = Path(output_dir) if output_dir else RESULTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)
        apply_white_contrast_theme()
    
    def generate_all_plots(self, since_timestamp=0):
        """Generate all 11 plots and export CSV from stored database records."""
        print(f"\n[ANALYZER] Generating high-contrast white-background figures into: {self.output_dir}")
        apply_white_contrast_theme()
        
        detections = self.db.get_all_detection_results(since_timestamp)
        verified = self.db.get_all_verified_telemetry(since_timestamp)
        
        if not detections:
            print("[WARN] No detection data found since specified timestamp. Run attacks first.")
            return
        
        print(f"[ANALYZER] Loaded {len(detections)} detection records, {len(verified)} verified telemetry points.")
        
        self.plot_1_voltage_current_power(verified, detections)
        self.plot_2_attack_confidence_timeline(detections)
        self.plot_3_roc_curve(detections)
        self.plot_4_recovery_accuracy(since_timestamp)
        self.plot_5_detector_comparison(detections)
        self.plot_6_confusion_matrix(detections)
        self.plot_7_attack_type_pie(detections)
        self.plot_8_detector_heatmap(detections)
        self.plot_9_ip_spoof_detail(detections)
        self.plot_10_fingerprint_distribution(detections)
        self.plot_11_synchrophasor_pmu_angle(since_timestamp)
        
        self.generate_metrics_table(detections, since_timestamp)
        self.export_csv(since_timestamp)
        
        print(f"\n[✓] All 11 figures, metrics table, and CSV export successfully generated in: {self.output_dir}\n")

    def _get_joined_telemetry(self, since_timestamp=0) -> List[dict]:
        """Fetch joined raw, detection, and verified records for synchronized analysis."""
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT 
                    r.id as raw_id,
                    r.timestamp,
                    r.voltage_v as raw_voltage,
                    r.current_a as raw_current,
                    r.power_w as raw_power,
                    r.frequency_hz,
                    r.power_factor,
                    r.seq,
                    r.hmac_valid,
                    r.src_ip_seen,
                    d.id as detection_id,
                    d.status,
                    d.attack_type,
                    d.attack_confidence,
                    d.physics_score,
                    d.z_score_normalized,
                    d.ml_score,
                    d.hmac_score,
                    d.fingerprint_score,
                    v.voltage_v as verified_voltage,
                    v.current_a as verified_current,
                    v.power_w as verified_power,
                    v.data_source,
                    v.recovery_strategy,
                    v.recovery_confidence
                FROM raw_telemetry r
                LEFT JOIN detection_results d ON r.id = d.telemetry_id
                LEFT JOIN verified_telemetry v ON r.id = v.telemetry_id
                WHERE r.timestamp >= ?
                ORDER BY r.timestamp ASC
            """, (since_timestamp,))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error fetching joined telemetry: {e}")
            return []

    # ═══════════════════════════════════════════════════════════
    # PLOT 1: Multi-Signal Telemetry & Recovery Overlay
    # ═══════════════════════════════════════════════════════════
    def plot_1_voltage_current_power(self, verified, detections):
        records = self._get_joined_telemetry()
        if not records:
            return
        
        times = [datetime.fromtimestamp(r['timestamp']) for r in records]
        raw_v = [r['raw_voltage'] or 0.0 for r in records]
        ver_v = [r['verified_voltage'] if r['verified_voltage'] is not None else r['raw_voltage'] for r in records]
        raw_i = [r['raw_current'] or 0.0 for r in records]
        ver_i = [r['verified_current'] if r['verified_current'] is not None else r['raw_current'] for r in records]
        raw_p = [r['raw_power'] or 0.0 for r in records]
        ver_p = [r['verified_power'] if r['verified_power'] is not None else r['raw_power'] for r in records]
        sources = [r.get('data_source', 'ORIGINAL') for r in records]

        fig, axes = plt.subplots(3, 1, figsize=(14, 10), sharex=True)
        fig.suptitle('SmartGrid Telemetry — Raw Injection vs Verified / Recovered Overlay', fontsize=15, fontweight='bold')

        # Subplot 1: Voltage
        axes[0].plot(times, raw_v, color='#b71c1c', linestyle=':', linewidth=1.5, marker='x', markersize=4, label='Injected / Raw Voltage', alpha=0.85)
        axes[0].plot(times, ver_v, color='#0d47a1', linestyle='-', linewidth=2.0, label='Verified / Recovered Voltage', alpha=0.95)
        axes[0].axhline(y=230, color='#2e7d32', linestyle='--', linewidth=1.5, label='Nominal Grid Voltage (230V)')
        axes[0].axhline(y=260, color='#d32f2f', linestyle='--', linewidth=1.0, alpha=0.6, label='Overvoltage Bound (260V)')
        axes[0].axhline(y=200, color='#d32f2f', linestyle='--', linewidth=1.0, alpha=0.6, label='Undervoltage Bound (200V)')
        axes[0].set_ylabel('Voltage (V)')
        axes[0].legend(loc='upper right', framealpha=0.9)
        axes[0].grid(True)

        # Subplot 2: Current
        axes[1].plot(times, raw_i, color='#b71c1c', linestyle=':', linewidth=1.5, marker='x', markersize=4, label='Raw Current', alpha=0.85)
        axes[1].plot(times, ver_i, color='#0d47a1', linestyle='-', linewidth=2.0, label='Recovered Current', alpha=0.95)
        axes[1].set_ylabel('Current (A)')
        axes[1].legend(loc='upper right', framealpha=0.9)
        axes[1].grid(True)

        # Subplot 3: Active Power
        axes[2].plot(times, raw_p, color='#b71c1c', linestyle=':', linewidth=1.5, marker='x', markersize=4, label='Raw Power', alpha=0.85)
        axes[2].plot(times, ver_p, color='#0d47a1', linestyle='-', linewidth=2.0, label='Recovered Power', alpha=0.95)
        axes[2].set_ylabel('Active Power (W)')
        axes[2].set_xlabel('Time (HH:MM:SS)')
        axes[2].legend(loc='upper right', framealpha=0.9)
        axes[2].grid(True)
        axes[2].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_01_vip_timeseries.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 1: V/I/P Raw vs Recovered Time-Series')

    # ═══════════════════════════════════════════════════════════
    # PLOT 2: Attack Confidence Timeline
    # ═══════════════════════════════════════════════════════════
    def plot_2_attack_confidence_timeline(self, detections):
        if not detections:
            return
        
        times = [datetime.fromtimestamp(d['timestamp']) for d in detections]
        confidences = [d.get('attack_confidence', 0.0) for d in detections]
        statuses = [d.get('status', 'NORMAL') for d in detections]
        
        color_map = {
            'NORMAL': '#1b5e20',
            'SUSPICIOUS': '#e65100',
            'ATTACK_DETECTED': '#b71c1c'
        }
        pt_colors = [color_map.get(s, '#757575') for s in statuses]
        
        fig, ax = plt.subplots(figsize=(14, 6))
        ax.plot(times, confidences, color='#424242', linestyle='-', linewidth=1.2, alpha=0.6, zorder=1)
        ax.scatter(times, confidences, c=pt_colors, s=35, edgecolors='black', linewidth=0.5, zorder=2, label='Telemetry Evaluation')
        
        ax.axhline(y=0.60, color='#b71c1c', linestyle='--', linewidth=2.0, label='Attack Threshold (0.60)', zorder=3)
        ax.axhline(y=0.35, color='#e65100', linestyle='--', linewidth=1.5, label='Suspicious Threshold (0.35)', zorder=3)
        
        # Legend handles
        from matplotlib.lines import Line2D
        custom_lines = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#1b5e20', markersize=8, label='Normal (Confidence < 0.35)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#e65100', markersize=8, label='Suspicious (0.35 ≤ Conf < 0.60)'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='#b71c1c', markersize=8, label='Attack Detected (Conf ≥ 0.60)'),
            Line2D([0], [0], color='#b71c1c', linestyle='--', linewidth=2, label='Trip Threshold (0.60)')
        ]
        ax.legend(handles=custom_lines, loc='upper right', framealpha=0.95)
        ax.set_ylabel('Attack Confidence Score (0.0 — 1.0)')
        ax.set_xlabel('Timestamp (HH:MM:SS)')
        ax.set_title('SmartGrid FDIA Shield — Multi-Attack Confidence Timeline', fontsize=14, fontweight='bold')
        ax.set_ylim(-0.05, 1.05)
        ax.grid(True)
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_02_confidence_timeline.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 2: Attack Confidence Timeline')

    # ═══════════════════════════════════════════════════════════
    # PLOT 3: ROC Curve
    # ═══════════════════════════════════════════════════════════
    def plot_3_roc_curve(self, detections):
        confidences = np.array([d.get('attack_confidence', 0.0) for d in detections])
        labels = np.array([1 if (d.get('attack_type') or d.get('status') == 'ATTACK_DETECTED') else 0 for d in detections])
        
        if len(np.unique(labels)) < 2:
            print('  ⚠ Plot 3: Skipped (requires both normal and attack samples)')
            return
        
        thresholds = np.linspace(0.0, 1.0, 200)
        tprs, fprs = [], []
        for th in thresholds:
            preds = (confidences >= th).astype(int)
            tp = np.sum((preds == 1) & (labels == 1))
            fp = np.sum((preds == 1) & (labels == 0))
            fn = np.sum((preds == 0) & (labels == 1))
            tn = np.sum((preds == 0) & (labels == 0))
            
            tprs.append(tp / max(tp + fn, 1))
            fprs.append(fp / max(fp + tn, 1))
        
        # Sort by FPR for proper trapezoidal integration
        sort_idx = np.argsort(fprs)
        fprs = np.array(fprs)[sort_idx]
        tprs = np.array(tprs)[sort_idx]
        auc = float(np.trapz(tprs, fprs))

        fig, ax = plt.subplots(figsize=(7, 7))
        ax.plot(fprs, tprs, color='#0d47a1', linewidth=2.5, label=f'FDIA Shield Multi-Signal Fusion (AUC = {abs(auc):.3f})')
        ax.plot([0, 1], [0, 1], color='#757575', linestyle='--', linewidth=1.5, label='Random Guess (AUC = 0.500)')
        ax.fill_between(fprs, tprs, color='#bbdefb', alpha=0.35)
        
        ax.set_xlabel('False Positive Rate (FPR)')
        ax.set_ylabel('True Positive Rate (TPR / Sensitivity)')
        ax.set_title('Receiver Operating Characteristic (ROC) Curve', fontsize=14, fontweight='bold')
        ax.legend(loc='lower right', framealpha=0.95)
        ax.set_xlim(-0.02, 1.02)
        ax.set_ylim(-0.02, 1.02)
        ax.grid(True)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_03_roc_curve.png', bbox_inches='tight', dpi=300)
        plt.close()
        print(f'  ✓ Plot 3: ROC Curve (AUC = {abs(auc):.3f})')

    # ═══════════════════════════════════════════════════════════
    # PLOT 4: Data Recovery Accuracy
    # ═══════════════════════════════════════════════════════════
    def plot_4_recovery_accuracy(self, since_timestamp=0):
        try:
            cursor = self.db.conn.cursor()
            cursor.execute("""
                SELECT original_voltage, recovered_voltage, original_power, recovered_power, recovery_confidence
                FROM recovery_log
                WHERE timestamp >= ?
            """, (since_timestamp,))
            rows = cursor.fetchall()
        except Exception as e:
            logger.error(f"Recovery query error: {e}")
            rows = []

        if not rows:
            print('  ⚠ Plot 4: No recovery log records found')
            return

        orig_v = [r['original_voltage'] for r in rows if r['original_voltage'] is not None]
        rec_v = [r['recovered_voltage'] for r in rows if r['recovered_voltage'] is not None]
        orig_p = [r['original_power'] for r in rows if r['original_power'] is not None]
        rec_p = [r['recovered_power'] for r in rows if r['recovered_power'] is not None]

        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Data Recovery Forecasting Accuracy Under Attack', fontsize=14, fontweight='bold')

        # Voltage Recovery
        axes[0].scatter(orig_v, rec_v, color='#0d47a1', edgecolors='black', s=45, alpha=0.85, label='Attack Samples')
        axes[0].axhline(y=230, color='#2e7d32', linestyle='--', label='Nominal 230V Reference')
        axes[0].set_xlabel('Reported Tampered Voltage (V)')
        axes[0].set_ylabel('Recovered / Forecast Voltage (V)')
        axes[0].set_title('Voltage Reconstruction Under FDI')
        axes[0].legend(loc='upper left', framealpha=0.9)
        axes[0].grid(True)

        # Power Recovery
        axes[1].scatter(orig_p, rec_p, color='#b71c1c', edgecolors='black', s=45, alpha=0.85, label='Attack Samples')
        axes[1].set_xlabel('Reported Tampered Power (W)')
        axes[1].set_ylabel('Recovered / Forecast Power (W)')
        axes[1].set_title('Active Power Reconstruction Under FDI')
        axes[1].legend(loc='upper left', framealpha=0.9)
        axes[1].grid(True)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_04_recovery_accuracy.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 4: Recovery Accuracy')

    # ═══════════════════════════════════════════════════════════
    # PLOT 5: 5-Signal Fusion Detector Comparison Boxplot
    # ═══════════════════════════════════════════════════════════
    def plot_5_detector_comparison(self, detections):
        data = {
            'Physics Check': [d.get('physics_score', 0.0) for d in detections],
            'Z-Score (EWMA)': [d.get('z_score_normalized', 0.0) for d in detections],
            'ML Isolation Forest': [d.get('ml_score', 0.0) for d in detections],
            'HMAC Verifier': [d.get('hmac_score', 0.0) for d in detections],
            'Network Fingerprint': [d.get('fingerprint_score', 0.0) for d in detections],
        }

        fig, ax = plt.subplots(figsize=(12, 6))
        colors = ['#0277bd', '#f57f17', '#2e7d32', '#c2185b', '#6a1b9a']
        
        bp = ax.boxplot(list(data.values()), labels=list(data.keys()), patch_artist=True, showmeans=True,
                        meanprops={'marker':'D', 'markerfacecolor':'black', 'markeredgecolor':'black', 'markersize':6})
        
        for patch, col in zip(bp['boxes'], colors):
            patch.set_facecolor(col)
            patch.set_alpha(0.8)
            patch.set_edgecolor('black')
            patch.set_linewidth(1.2)
        
        for whisker in bp['whiskers']:
            whisker.set_color('#111111')
            whisker.set_linewidth(1.2)

        ax.set_ylabel('Anomaly Score (0.0=Normal, 1.0=Attack)')
        ax.set_title('5-Signal Multi-Layer Detector Score Distributions', fontsize=14, fontweight='bold')
        ax.set_ylim(-0.05, 1.05)
        ax.grid(True, axis='y')

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_05_detector_comparison.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 5: 5-Signal Detector Comparison Boxplot')

    # ═══════════════════════════════════════════════════════════
    # PLOT 6: Detection Confusion Matrix
    # ═══════════════════════════════════════════════════════════
    def plot_6_confusion_matrix(self, detections):
        actual = []
        predicted = []
        for d in detections:
            is_attack = bool(d.get('attack_type') or d.get('status') == 'ATTACK_DETECTED')
            actual.append(1 if is_attack else 0)
            predicted.append(1 if d.get('status') == 'ATTACK_DETECTED' else 0)

        tp = sum(1 for a, p in zip(actual, predicted) if a == 1 and p == 1)
        fp = sum(1 for a, p in zip(actual, predicted) if a == 0 and p == 1)
        fn = sum(1 for a, p in zip(actual, predicted) if a == 1 and p == 0)
        tn = sum(1 for a, p in zip(actual, predicted) if a == 0 and p == 0)

        cm = np.array([[tn, fp], [fn, tp]])
        prec = tp / max(tp + fp, 1)
        rec = tp / max(tp + fn, 1)
        f1 = 2 * (prec * rec) / max(prec + rec, 1e-6)

        fig, ax = plt.subplots(figsize=(7, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False, ax=ax,
                    xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'],
                    linewidths=1.5, linecolor='black')
        
        ax.set_xlabel('Predicted Label')
        ax.set_ylabel('True Ground Truth Label')
        ax.set_title(f'Detection Confusion Matrix\nPrecision={prec:.1%}, Recall={rec:.1%}, F1={f1:.3f}', fontsize=13, fontweight='bold')

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_06_confusion_matrix.png', bbox_inches='tight', dpi=300)
        plt.close()
        print(f'  ✓ Plot 6: Confusion Matrix (TP={tp}, FP={fp}, FN={fn}, TN={tn})')

    # ═══════════════════════════════════════════════════════════
    # PLOT 7: Attack Type Distribution
    # ═══════════════════════════════════════════════════════════
    def plot_7_attack_type_pie(self, detections):
        counts = {}
        for d in detections:
            at = d.get('attack_type') or 'CLEAN_NORMAL'
            counts[at] = counts.get(at, 0) + 1

        labels = list(counts.keys())
        values = list(counts.values())
        
        palette = ['#1b5e20', '#b71c1c', '#0d47a1', '#e65100', '#6a1b9a', '#004d40', '#d81b60']
        colors = [palette[i % len(palette)] for i in range(len(labels))]

        fig, ax = plt.subplots(figsize=(8, 7))
        wedges, texts, autotexts = ax.pie(
            values, labels=labels, autopct='%1.1f%%', startangle=140,
            colors=colors, wedgeprops=dict(edgecolor='black', linewidth=1.2)
        )
        for t in texts:
            t.set_fontsize(10)
            t.set_fontweight('bold')
        for at in autotexts:
            at.set_fontsize(10)
            at.set_color('white')
            at.set_fontweight('bold')

        ax.set_title('SmartGrid FDIA Shield — Attack Type Classification Breakdown', fontsize=13, fontweight='bold')
        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_07_attack_type_pie.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 7: Attack Type Pie Chart')

    # ═══════════════════════════════════════════════════════════
    # PLOT 8: 5-Signal Detector Heatmap
    # ═══════════════════════════════════════════════════════════
    def plot_8_detector_heatmap(self, detections):
        if len(detections) < 2:
            return

        names = ['Physics', 'Z-Score', 'ML (IF)', 'HMAC', 'Fingerprint']
        matrix = np.zeros((5, len(detections)))
        for j, d in enumerate(detections):
            matrix[0, j] = d.get('physics_score', 0.0)
            matrix[1, j] = d.get('z_score_normalized', 0.0)
            matrix[2, j] = d.get('ml_score', 0.0)
            matrix[3, j] = d.get('hmac_score', 0.0)
            matrix[4, j] = d.get('fingerprint_score', 0.0)

        fig, ax = plt.subplots(figsize=(16, 5))
        im = ax.imshow(matrix, aspect='auto', cmap='YlOrRd', vmin=0, vmax=1, interpolation='nearest')
        ax.set_yticks(range(5))
        ax.set_yticklabels(names)
        ax.set_xlabel('Packet Index')
        ax.set_title('Multi-Layer Anomaly Heatmap Across Sequential Test Stream', fontsize=14, fontweight='bold')
        cbar = plt.colorbar(im, ax=ax, orientation='horizontal', pad=0.25)
        cbar.set_label('Layer Anomaly Score (0.0=Clean, 1.0=Severe Anomaly)', fontweight='bold')

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_08_detector_heatmap.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 8: Multi-Signal Heatmap')

    # ═══════════════════════════════════════════════════════════
    # PLOT 9: IP Spoofing Cross-Layer Breakdown
    # ═══════════════════════════════════════════════════════════
    def plot_9_ip_spoof_detail(self, detections):
        spoof_subset = [d for d in detections if d.get('fingerprint_score', 0) > 0.1 or d.get('hmac_score', 0) > 0 or 'SPOOF' in str(d.get('attack_type'))]
        if not spoof_subset:
            spoof_subset = detections[:min(len(detections), 50)]

        times = [datetime.fromtimestamp(d['timestamp']) for d in spoof_subset]
        hmac_scores = [d.get('hmac_score', 0.0) for d in spoof_subset]
        fp_scores = [d.get('fingerprint_score', 0.0) for d in spoof_subset]
        confidences = [d.get('attack_confidence', 0.0) for d in spoof_subset]

        fig, axes = plt.subplots(3, 1, figsize=(14, 9), sharex=True)
        fig.suptitle('Cross-Layer IP Spoofing Detection (Layer 7 Cryptography vs Layer 3/4 Network Fingerprint)', fontsize=14, fontweight='bold')

        # Subplot 1: HMAC
        axes[0].bar(times, hmac_scores, color='#c2185b', width=0.0003, edgecolor='black', label='HMAC Verification (1.0 = Signature Failure)')
        axes[0].set_ylabel('HMAC Score')
        axes[0].set_ylim(-0.1, 1.2)
        axes[0].legend(loc='upper right', framealpha=0.9)
        axes[0].grid(True)

        # Subplot 2: Network Fingerprint
        axes[1].plot(times, fp_scores, color='#6a1b9a', marker='o', markersize=4, linewidth=1.5, label='Network Fingerprint (TTL & TCP Window)')
        axes[1].axhline(y=0.5, color='#b71c1c', linestyle='--', label='Spoof Threshold (0.5)')
        axes[1].set_ylabel('Fingerprint Score')
        axes[1].set_ylim(-0.05, 1.05)
        axes[1].legend(loc='upper right', framealpha=0.9)
        axes[1].grid(True)

        # Subplot 3: Confidence
        axes[2].plot(times, confidences, color='#b71c1c', marker='s', markersize=4, linewidth=1.5, label='Overall Attack Confidence')
        axes[2].axhline(y=0.6, color='#b71c1c', linestyle='--', label='Trip Threshold (0.6)')
        axes[2].set_ylabel('Attack Confidence')
        axes[2].set_xlabel('Timestamp (HH:MM:SS)')
        axes[2].set_ylim(-0.05, 1.05)
        axes[2].legend(loc='upper right', framealpha=0.9)
        axes[2].grid(True)
        axes[2].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_09_ip_spoof_detail.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 9: IP Spoof Cross-Layer Detail')

    # ═══════════════════════════════════════════════════════════
    # PLOT 10: Fingerprint Score Distribution
    # ═══════════════════════════════════════════════════════════
    def plot_10_fingerprint_distribution(self, detections):
        norm_fps = [d.get('fingerprint_score', 0.0) for d in detections if d.get('status') == 'NORMAL']
        attk_fps = [d.get('fingerprint_score', 0.0) for d in detections if d.get('status') == 'ATTACK_DETECTED']

        fig, ax = plt.subplots(figsize=(9, 6))
        if norm_fps:
            ax.hist(norm_fps, bins=20, alpha=0.75, color='#1b5e20', edgecolor='black', label=f'Real ESP32 Node (n={len(norm_fps)})')
        if attk_fps:
            ax.hist(attk_fps, bins=20, alpha=0.75, color='#b71c1c', edgecolor='black', label=f'Spoofed Packets (n={len(attk_fps)})')

        ax.axvline(x=0.5, color='#111111', linestyle='--', linewidth=2, label='Classification Threshold (0.5)')
        ax.set_xlabel('Network Fingerprint Anomaly Score')
        ax.set_ylabel('Packet Frequency')
        ax.set_title('Network Stack Fingerprint Distribution — Real ESP32 vs Spoofed Traffic', fontsize=13, fontweight='bold')
        ax.legend(loc='upper right', framealpha=0.9)
        ax.grid(True)

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_10_fingerprint_distribution.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 10: Fingerprint Distribution Histogram')

    # ═══════════════════════════════════════════════════════════
    # PLOT 11: Synchrophasor PMU Phase Angle & Frequency
    # ═══════════════════════════════════════════════════════════
    def plot_11_synchrophasor_pmu_angle(self, since_timestamp=0):
        records = self._get_joined_telemetry(since_timestamp)
        if not records:
            return

        times = [datetime.fromtimestamp(r['timestamp']) for r in records]
        v_list = [r['raw_voltage'] or 230.0 for r in records]
        i_list = [r['raw_current'] or 0.0 for r in records]
        f_list = [r['frequency_hz'] or 50.0 for r in records]
        pf_list = [r['power_factor'] or 1.0 for r in records]

        # Compute physical power angle: delta_V = -(I * X * PF / V) in degrees
        angles = []
        for v, i, pf, f in zip(v_list, i_list, pf_list, f_list):
            base_rad = -(i * 0.15 * max(0.01, min(1.0, pf))) / max(v, 100.0)
            droop = np.clip((f - 50.0) * 2.0, -2.0, 2.0)
            angles.append(float(np.degrees(base_rad) + droop))

        fig, axes = plt.subplots(2, 1, figsize=(14, 8), sharex=True)
        fig.suptitle('Virtual Phasor Measurement Unit (IEEE C37.118 Synchrophasor Metrics)', fontsize=14, fontweight='bold')

        # Subplot 1: Phase Angle delta
        axes[0].plot(times, angles, color='#0277bd', marker='o', markersize=3, linewidth=1.5, label='Voltage Synchrophasor Angle δ_V (°)')
        axes[0].axhline(y=0.0, color='#111111', linestyle='--', linewidth=1.0, label='Nominal 0.0° Reference')
        axes[0].set_ylabel('Phase Angle δ (deg)')
        axes[0].set_title('Phasor Angle Tracking (Resistive Load Stability)')
        axes[0].legend(loc='upper right', framealpha=0.9)
        axes[0].grid(True)

        # Subplot 2: Grid Frequency
        axes[1].plot(times, f_list, color='#2e7d32', marker='s', markersize=3, linewidth=1.5, label='Measured Frequency f (Hz)')
        axes[1].axhline(y=50.0, color='#111111', linestyle='--', linewidth=1.0, label='Nominal 50.00 Hz')
        axes[1].axhline(y=50.5, color='#d32f2f', linestyle=':', label='Statutory Limits [49.5, 50.5] Hz')
        axes[1].axhline(y=49.5, color='#d32f2f', linestyle=':')
        axes[1].set_ylabel('Frequency (Hz)')
        axes[1].set_xlabel('Timestamp (HH:MM:SS)')
        axes[1].set_title('Grid Frequency Stability & Boundary Verification')
        axes[1].legend(loc='upper right', framealpha=0.9)
        axes[1].grid(True)
        axes[1].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))

        plt.tight_layout()
        plt.savefig(self.output_dir / 'plot_11_synchrophasor_pmu_angle.png', bbox_inches='tight', dpi=300)
        plt.close()
        print('  ✓ Plot 11: Virtual PMU Synchrophasor & Frequency')

    # ═══════════════════════════════════════════════════════════
    # EXPORT CSV & METRICS SUMMARY
    # ═══════════════════════════════════════════════════════════
    def export_csv(self, since_timestamp=0):
        records = self._get_joined_telemetry(since_timestamp)
        if not records:
            return
        
        csv_file = self.output_dir / 'smartgrid_telemetry_export.csv'
        fieldnames = [
            'raw_id', 'timestamp', 'iso_time', 'raw_voltage', 'raw_current', 'raw_power',
            'frequency_hz', 'power_factor', 'seq', 'hmac_valid', 'src_ip_seen',
            'status', 'attack_type', 'attack_confidence', 'physics_score',
            'z_score_normalized', 'ml_score', 'hmac_score', 'fingerprint_score',
            'verified_voltage', 'verified_current', 'verified_power',
            'data_source', 'recovery_strategy', 'recovery_confidence'
        ]

        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for r in records:
                row = dict(r)
                row['iso_time'] = datetime.fromtimestamp(r['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                writer.writerow(row)
        
        print(f'  ✓ CSV Export saved to: {csv_file}')

    def generate_metrics_table(self, detections, since_timestamp=0):
        stats = self.db.get_detection_stats(since_timestamp)
        spoof_stats = self.db.get_spoof_summary(since_timestamp)

        total = stats.get('total_packets', 0)
        normal = stats.get('normal_count', 0)
        suspicious = stats.get('suspicious_count', 0)
        attack = stats.get('attack_count', 0)

        table = f"""
╔══════════════════════════════════════════════════════════╗
║        SMARTGRID FDIA SHIELD — BENCHMARK METRICS         ║
╠══════════════════════════════════════════════════╤═══════╣
║  Total Packets Evaluated                         │ {total:>5} ║
║  Classified Normal                               │ {normal:>5} ║
║  Classified Suspicious                           │ {suspicious:>5} ║
║  Classified Attack Detected                      │ {attack:>5} ║
╠══════════════════════════════════════════════════╧═══════╣
║  CROSS-LAYER IP SPOOFING IDENTIFICATION                  ║
╠══════════════════════════════════════════════════╤═══════╣
║  Total Spoof Episodes Caught                     │ {spoof_stats.get('total_spoof_episodes', 0):>5} ║
║  Detected via Cryptographic HMAC (Layer 7)       │ {spoof_stats.get('detected_by_hmac', 0):>5} ║
║  Detected via TCP/IP Fingerprinting (Layer 3/4)  │ {spoof_stats.get('detected_by_fingerprint', 0):>5} ║
║  Corroborated by Both Layers                     │ {spoof_stats.get('detected_by_both', 0):>5} ║
╚══════════════════════════════════════════════════╧═══════╝
"""
        print(table)
        with open(self.output_dir / 'metrics_table.txt', 'w', encoding='utf-8') as f:
            f.write(table)
        print('  ✓ Metrics table saved to metrics_table.txt')

    def close(self):
        self.db.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='SmartGrid Analysis & High-Contrast Visualizations')
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
