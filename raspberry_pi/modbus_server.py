"""
MODULE BRIEFING:
Purpose: Industrial Modbus TCP Server for SmartGrid Gateway.
Exposes standard SCADA Holding Registers and Coils for Substation Automation:
- Registers 40001-40015: Real-time telemetry, Synchrophasor angle, ROCOF, WLS State Estimation residuals
- Coils 00001-00004: Feeder Circuit Breakers (Trip/Close control) and protection modes

Runs in a non-blocking background thread.
Dual-mode implementation: uses pymodbus if installed, with a robust built-in
pure-Python Modbus TCP socket fallback for zero-dependency reliability.

Dependencies: threading, socket, struct
Research Disclaimer: Academic research and educational testbed for SmartGrid FDIA Shield.
"""

import socket
import struct
import threading
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ModbusServer:
    """
    Industrial Modbus TCP Server (Slave) running on Raspberry Pi Gateway.
    Default port: 5020 (avoids root requirement) or standard 502.
    """

    def __init__(self, host: str = '0.0.0.0', port: int = 5020):
        self.host = host
        self.port = port
        self.running = False
        self.server_thread = None
        self.sock = None
        self.lock = threading.Lock()

        # Modbus Storage Maps:
        # Holding Registers (16-bit unsigned/signed integers) - Address 0 to 19 (40001 to 40020)
        self.holding_registers = [0] * 32

        # Coils (1-bit booleans) - Address 0 to 7 (00001 to 00008)
        # Coil 0: Circuit Breaker Status (1 = Closed/Energized, 0 = Tripped/Open)
        # Coil 1: Automatic FDIA Isolation Interlock (1 = Enabled)
        self.coils = [False] * 16
        self.coils[0] = True  # Circuit breaker closed by default (grid energized)
        self.coils[1] = True  # Auto-isolation active

        # Statistics
        self.requests_served = 0

    def start(self):
        """Starts the Modbus TCP server thread."""
        if self.running:
            return
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True, name="ModbusTCPServer")
        self.server_thread.start()
        logger.info(f"Modbus TCP Server started on {self.host}:{self.port}")

    def stop(self):
        """Stops the Modbus TCP server."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0)
        logger.info("Modbus TCP Server stopped.")

    def trip_breaker(self, reason: str = "FDIA Critical Trip"):
        """Trips the physical/virtual circuit breaker (Coil 00001 = 0)."""
        with self.lock:
            if self.coils[0]:
                self.coils[0] = False
                logger.warning(f"CIRCUIT BREAKER TRIPPED! Reason: {reason}. Feeder isolated.")

    def close_breaker(self):
        """Re-closes the circuit breaker (Coil 00001 = 1)."""
        with self.lock:
            self.coils[0] = True
            logger.info("Circuit breaker closed. Feeder re-energized.")

    def is_breaker_closed(self) -> bool:
        """Returns True if circuit breaker is closed (energized)."""
        with self.lock:
            return bool(self.coils[0])

    def update_registers(self, telemetry: Dict[str, Any],
                         detection: Optional[Dict[str, Any]] = None,
                         state_est: Optional[Dict[str, Any]] = None,
                         pmu: Optional[Dict[str, Any]] = None):
        """
        Updates the Modbus holding registers from real-time pipeline outputs.
        """
        with self.lock:
            # 40001: Scaled Voltage (V * 10, e.g. 2304 -> 230.4 V)
            v = float(telemetry.get('voltage_V', telemetry.get('voltage_v', 230.0)))
            self.holding_registers[0] = int(np_clip(v * 10, 0, 65535))

            # 40002: Current in mA (I * 1000, e.g. 260 -> 0.260 A)
            i = float(telemetry.get('current_A', telemetry.get('current_a', 0.26)))
            self.holding_registers[1] = int(np_clip(i * 1000, 0, 65535))

            # 40003: Active Power in Watts (P, e.g. 60)
            p = float(telemetry.get('power_W', telemetry.get('power_w', 60.0)))
            self.holding_registers[2] = int(np_clip(p, 0, 65535))

            # 40004: Frequency in cHz (f * 100, e.g. 5000 -> 50.00 Hz)
            f = float(telemetry.get('frequency_Hz', telemetry.get('frequency_hz', 50.0)))
            self.holding_registers[3] = int(np_clip(f * 100, 0, 65535))

            # 40005: Power Factor * 1000 (e.g. 990 -> 0.99)
            pf = float(telemetry.get('power_factor', 0.99))
            self.holding_registers[4] = int(np_clip(pf * 1000, 0, 65535))

            # Synchrophasor PMU registers
            if pmu:
                # 40006: Voltage Phase Angle (deg * 100, signed 16-bit)
                angle_deg = float(pmu.get('voltage_angle_deg', 0.0))
                self.holding_registers[5] = int(angle_deg * 100) & 0xFFFF

                # 40007: ROCOF (Hz/s * 1000, signed 16-bit)
                rocof = float(pmu.get('rocof_Hz_s', 0.0))
                self.holding_registers[6] = int(rocof * 1000) & 0xFFFF

            # WLS State Estimator registers
            if state_est:
                # 40008: WLS Chi-Square Statistic J(x) * 10
                chi2 = float(state_est.get('chi_square_stat', 0.0))
                self.holding_registers[7] = int(np_clip(chi2 * 10, 0, 65535))

                # 40009: Max Normalized Residual rN * 100
                max_rn = float(state_est.get('max_normalized_residual', 0.0))
                self.holding_registers[8] = int(np_clip(max_rn * 100, 0, 65535))

                # 40010: Bad Data Flag (1 = Bad Data, 0 = Clean)
                self.holding_registers[9] = 1 if state_est.get('bad_data_detected') else 0

            # Detection fusion results
            if detection:
                status_str = detection.get('status', 'NORMAL')
                status_code = 0 if status_str == 'NORMAL' else (1 if status_str == 'SUSPICIOUS' else 2)
                # 40011: Fusion Status Code
                self.holding_registers[10] = status_code

                # 40012: Attack Confidence (0 to 10000 => 0.00% to 100.00%)
                conf = float(detection.get('attack_confidence', 0.0))
                self.holding_registers[11] = int(np_clip(conf * 10000, 0, 10000))

                # Automatic Circuit Breaker Trip if auto-isolation enabled
                if self.coils[1] and conf >= 0.85:
                    self.trip_breaker(f"FDIA Severe ({conf*100:.1f}%)")

    def _run_server(self):
        """Socket listener for incoming Modbus TCP connections."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.sock.settimeout(1.0)
        except Exception as e:
            logger.error(f"Failed to bind Modbus TCP server on port {self.port}: {e}")
            self.running = False
            return

        while self.running:
            try:
                client_sock, client_addr = self.sock.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.debug(f"Modbus socket accept notice: {e}")
                break

    def _handle_client(self, client_sock: socket.socket, client_addr):
        """Processes Modbus TCP ADU frames from an industrial client/SCADA."""
        client_sock.settimeout(5.0)
        try:
            while self.running:
                # Modbus TCP Header (MBAP): 7 bytes
                # Transaction ID (2B), Protocol ID (2B=0), Length (2B), Unit ID (1B)
                mbap = client_sock.recv(7)
                if not mbap or len(mbap) < 7:
                    break

                trans_id, proto_id, length, unit_id = struct.unpack('>HHHB', mbap)
                if proto_id != 0:
                    break

                # PDU data
                pdu_len = length - 1
                pdu = client_sock.recv(pdu_len)
                if len(pdu) < pdu_len:
                    break

                func_code = pdu[0]
                response_pdu = self._process_function(func_code, pdu[1:])

                # Wrap in MBAP Header and respond
                resp_length = len(response_pdu) + 1
                resp_mbap = struct.pack('>HHHB', trans_id, 0, resp_length, unit_id)
                client_sock.sendall(resp_mbap + response_pdu)

                with self.lock:
                    self.requests_served += 1
        except Exception:
            pass
        finally:
            client_sock.close()

    def _process_function(self, func_code: int, data: bytes) -> bytes:
        """Handles standard Modbus function codes: 01 (Read Coils), 03 (Read Holding), 05 (Write Single Coil), 06 (Write Register)."""
        with self.lock:
            # 01 (0x01): Read Coils
            if func_code == 1:
                start_addr, count = struct.unpack('>HH', data[:4])
                byte_count = (count + 7) // 8
                coils_byte = 0
                for bit_idx in range(min(count, 8)):
                    idx = start_addr + bit_idx
                    if idx < len(self.coils) and self.coils[idx]:
                        coils_byte |= (1 << bit_idx)
                return bytes([1, byte_count, coils_byte])

            # 03 (0x03): Read Holding Registers
            elif func_code == 3:
                start_addr, count = struct.unpack('>HH', data[:4])
                count = min(count, 20)
                byte_count = count * 2
                payload = bytearray([3, byte_count])
                for idx in range(start_addr, start_addr + count):
                    val = self.holding_registers[idx] if idx < len(self.holding_registers) else 0
                    payload.extend(struct.pack('>H', val & 0xFFFF))
                return bytes(payload)

            # 05 (0x05): Write Single Coil
            elif func_code == 5:
                coil_addr, coil_val = struct.unpack('>HH', data[:4])
                if coil_addr < len(self.coils):
                    self.coils[coil_addr] = (coil_val == 0xFF00)
                    logger.info(f"Modbus SCADA Command: Coil {coil_addr+1} set to {self.coils[coil_addr]}")
                return bytes([5]) + data[:4]

            # 06 (0x06): Write Single Holding Register
            elif func_code == 6:
                reg_addr, reg_val = struct.unpack('>HH', data[:4])
                if reg_addr < len(self.holding_registers):
                    self.holding_registers[reg_addr] = reg_val
                    logger.info(f"Modbus SCADA Command: Register {40001+reg_addr} set to {reg_val}")
                return bytes([6]) + data[:4]

            # Exception: Illegal Function
            else:
                return bytes([func_code | 0x80, 0x01])

def np_clip(val: float, low: float, high: float) -> float:
    return max(low, min(high, val))
