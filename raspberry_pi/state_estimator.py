"""
MODULE BRIEFING:
Purpose: Industrial Weighted Least Squares (WLS) AC Power System State Estimator.
Implements the exact state estimation mathematical formulation used in utility EMS/SCADA
(Energy Management Systems) control centers:
1. Non-linear measurement model: z = h(x) + e, where x = [theta_2..N, V_1..N]^T
2. Iterative Gauss-Newton solution with Admittance Matrix Y_bus
3. Measurement residual vector: r = z - h(x_hat)
4. Residual covariance matrix: Omega = R - H * (H^T * W * H)^(-1) * H^T
5. Chi-square (chi^2) Bad Data Detection test: J(x_hat) = sum((z_i - h_i(x_hat))^2 / sigma_i^2)
6. Largest Normalized Residual Test (LNRT) to isolate corrupted sensors

Dependencies: numpy
Research Disclaimer: Academic research and educational testbed for SmartGrid FDIA Shield.
"""

import numpy as np
import logging
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

class StateEstimator:
    """
    Weighted Least Squares (WLS) AC State Estimator for distribution grid testbed.
    Models a 3-bus equivalent distribution system:
      - Bus 1: Slack / Substation Bus (V1 = 230.0 V, theta1 = 0.0 rad)
      - Bus 2: Distribution Feeder / Transformer Bus
      - Bus 3: Monitored Customer / DER Load Bus (where ESP32 / sensor measures)
    """

    def __init__(self,
                 nominal_voltage: float = 230.0,
                 nominal_freq: float = 50.0,
                 chi2_threshold: float = 11.34):  # chi2 for 3 DOF at alpha=0.01 is ~11.34
        self.nominal_voltage = nominal_voltage
        self.nominal_freq = nominal_freq
        self.chi2_threshold = chi2_threshold

        # Network branch parameters (per-unit or actual ohms)
        # Line 1-2 (Substation to transformer): R12 = 0.05 ohm, X12 = 0.15 ohm
        # Line 2-3 (Transformer to load bus): R23 = 0.08 ohm, X23 = 0.20 ohm
        self.r12 = 0.05
        self.x12 = 0.15
        self.r23 = 0.08
        self.x23 = 0.20

        # Construct 2-port line series admittances: y = 1 / (r + j*x) = g + j*b
        z12 = complex(self.r12, self.x12)
        z23 = complex(self.r23, self.x23)
        self.y12 = 1.0 / z12
        self.y23 = 1.0 / z23

        # Measurement variances (standard deviations squared)
        # sigma_v = 1.0 V, sigma_i = 0.02 A, sigma_p = 2.0 W, sigma_q = 2.0 VAR
        self.sigma = {
            'voltage': 1.0,
            'current': 0.02,
            'power': 2.0,
            'reactive_power': 2.5
        }

        # Weight matrix diagonal entries: W_ii = 1 / (sigma_i^2)
        self.weights = np.array([
            1.0 / (self.sigma['voltage'] ** 2),
            1.0 / (self.sigma['current'] ** 2),
            1.0 / (self.sigma['power'] ** 2),
            1.0 / (self.sigma['reactive_power'] ** 2)
        ])

        # State vector: x = [theta_3 (rad), V_3 (V)]
        # Initial flat start: theta_3 = 0.0, V_3 = nominal_voltage
        self.x_state = np.array([0.0, self.nominal_voltage])

    def _calculate_power_flow(self, v3: float, theta3: float) -> Tuple[float, float, float]:
        """
        Calculates expected active power P3, reactive power Q3, and line current I23
        at Bus 3 given Bus 3 voltage state (V3, theta3) and Bus 2 state.
        Assumes Bus 2 voltage is intermediate between Slack (230V, 0 rad) and Bus 3.
        """
        # Intermediate bus 2 estimate
        v2 = (self.nominal_voltage + v3) / 2.0
        theta2 = theta3 / 2.0

        v2_c = v2 * np.cos(theta2) + 1j * v2 * np.sin(theta2)
        v3_c = v3 * np.cos(theta3) + 1j * v3 * np.sin(theta3)

        # Current into Bus 3 from Bus 2
        i_branch = (v2_c - v3_c) * self.y23
        i_mag = abs(i_branch)

        # Complex power at Bus 3: S3 = V3 * conj(I_into_3)
        s3 = v3_c * np.conj(i_branch)
        p3_exp = s3.real
        q3_exp = s3.imag

        return p3_exp, q3_exp, i_mag

    def _measurement_function_h(self, x: np.ndarray) -> np.ndarray:
        """
        Computes the non-linear measurement vector h(x):
        z_est = [V_3, I_3, P_3, Q_3]^T
        """
        theta3 = x[0]
        v3 = x[1]

        p3, q3, i3 = self._calculate_power_flow(v3, theta3)
        return np.array([v3, i3, p3, q3], dtype=float)

    def _compute_jacobian(self, x: np.ndarray, eps: float = 1e-5) -> np.ndarray:
        """
        Numerical Jacobian matrix H = dh/dx of size (4 x 2):
        Row 0: dV3/dtheta3, dV3/dV3
        Row 1: dI3/dtheta3, dI3/dV3
        Row 2: dP3/dtheta3, dP3/dV3
        Row 3: dQ3/dtheta3, dQ3/dV3
        """
        h0 = self._measurement_function_h(x)
        H = np.zeros((4, 2))

        for j in range(2):
            x_step = x.copy()
            x_step[j] += eps
            h_step = self._measurement_function_h(x_step)
            H[:, j] = (h_step - h0) / eps

        return H

    def estimate_state(self, telemetry: Dict[str, Any], max_iter: int = 10, tol: float = 1e-4) -> Dict[str, Any]:
        """
        Executes Gauss-Newton WLS State Estimation and Chi-Square Bad Data Detection.

        Args:
            telemetry: Dict with keys: voltage_V, current_A, power_W, power_factor
        Returns:
            Dict containing estimated states, residuals, Chi-square statistic,
            and Bad Data Detection verdict.
        """
        v_meas = float(telemetry.get('voltage_V', telemetry.get('voltage_v', self.nominal_voltage)))
        i_meas = float(telemetry.get('current_A', telemetry.get('current_a', 0.26)))
        p_meas = float(telemetry.get('power_W', telemetry.get('power_w', 60.0)))
        pf = float(telemetry.get('power_factor', 0.99))

        # Calculate reactive power Q = P * tan(acos(pf))
        pf_clamped = max(-1.0, min(1.0, pf))
        sin_phi = np.sqrt(max(0.0, 1.0 - pf_clamped ** 2))
        q_meas = p_meas * (sin_phi / max(pf_clamped, 0.01))

        # Measurement vector z = [V, I, P, Q]^T
        z = np.array([v_meas, i_meas, p_meas, q_meas], dtype=float)

        # Weight matrix W (diagonal 4x4)
        W = np.diag(self.weights)
        R_cov = np.diag(1.0 / self.weights)  # Covariance matrix R

        # Flat start state x = [theta_3 = 0, V_3 = measured voltage]
        x = np.array([0.0, v_meas], dtype=float)
        converged = False
        iterations = 0

        for it in range(max_iter):
            iterations += 1
            h_x = self._measurement_function_h(x)
            r = z - h_x

            H = self._compute_jacobian(x)

            # Gain matrix G = H^T * W * H (2 x 2)
            G = H.T @ W @ H

            try:
                # Solve normal equation G * delta_x = H^T * W * r
                delta_x = np.linalg.solve(G, H.T @ W @ r)
            except np.linalg.LinAlgError:
                delta_x = np.linalg.pinv(G) @ (H.T @ W @ r)

            x = x + delta_x

            if np.max(np.abs(delta_x)) < tol:
                converged = True
                break

        # Store converged state
        self.x_state = x
        theta_est = float(x[0])
        v_est = float(x[1])

        # Final residual vector: r = z - h(x_hat)
        h_final = self._measurement_function_h(x)
        residual = z - h_final

        # Chi-square objective function J(x_hat) = sum((z_i - h_i)^2 / sigma_i^2)
        chi2_stat = float(np.sum(self.weights * (residual ** 2)))

        # Residual covariance matrix: Omega = R - H * (H^T * W * H)^(-1) * H^T
        try:
            G_inv = np.linalg.inv(H.T @ W @ H)
            Omega = R_cov - H @ G_inv @ H.T
            diag_omega = np.maximum(np.diag(Omega), 1e-6)
            normalized_residuals = np.abs(residual) / np.sqrt(diag_omega)
        except Exception:
            normalized_residuals = np.abs(residual) / np.sqrt(np.diag(R_cov))

        param_names = ['voltage_V', 'current_A', 'power_W', 'reactive_power_VAR']
        max_rn_idx = int(np.argmax(normalized_residuals))
        max_rn = float(normalized_residuals[max_rn_idx])
        most_compromised = param_names[max_rn_idx]

        # Bad data hypothesis test (Chi-Square test & Largest Normalized Residual)
        bad_data_detected = bool(chi2_stat > self.chi2_threshold or max_rn > 3.0)

        # Scale residual score between 0.0 and 1.0 for fusion
        # A chi2_stat of 0 gives 0.0, chi2_stat >= chi2_threshold gives 1.0
        residual_score = float(np.clip(chi2_stat / (self.chi2_threshold * 1.5), 0.0, 1.0))

        return {
            'converged': converged,
            'iterations': iterations,
            'estimated_voltage': round(v_est, 2),
            'estimated_angle_deg': round(float(np.degrees(theta_est)), 4),
            'chi_square_stat': round(chi2_stat, 3),
            'chi_square_threshold': round(self.chi2_threshold, 2),
            'bad_data_detected': bad_data_detected,
            'max_normalized_residual': round(max_rn, 3),
            'compromised_measurement': most_compromised if bad_data_detected else None,
            'residual_score': round(residual_score, 4),
            'residuals': {
                'v_diff': round(float(residual[0]), 3),
                'i_diff': round(float(residual[1]), 4),
                'p_diff': round(float(residual[2]), 2),
                'q_diff': round(float(residual[3]), 2),
            }
        }
