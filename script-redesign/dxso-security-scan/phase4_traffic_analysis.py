import os
import subprocess
import argparse
import time
from pathlib import Path

# Phase 4: Network Traffic & Bandwidth Analysis
# Dependencies: tshark, zeek

def run_traffic_analysis(interface, duration=300, output_dir="dxso_reports/4_Traffic_Analysis"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n=== PHASE 4: Traffic & Bandwidth Analysis ===")
    print(f"[*] Binding to interface {interface} for {duration} seconds...")

    # 1. Raw Packet Capture (Tshark)
    pcap_file = os.path.join(output_dir, "traffic_capture.pcap")
    print(f"    [!] 1/3 Capturing raw network packets to {pcap_file}...")
    try:
        # We use a strict timeout in tshark's own arguments
        cmd_tshark = f"tshark -i {interface} -a duration:{duration} -w {pcap_file} -q"
        subprocess.run(cmd_tshark, shell=True, check=True)
    except subprocess.CalledProcessError:
        print("    [!] Tshark capture failed. Do you have root privileges?")
        return

    # 2. Top Talker Extraction
    print("\n    [!] 2/3 Extracting Top Talkers (Bandwidth Hogs)...")
    top_talkers_file = os.path.join(output_dir, "top_talkers.txt")
    cmd_top = f"tshark -r {pcap_file} -q -z conv,ip > {top_talkers_file}"
    try:
        subprocess.run(cmd_top, shell=True, check=True)
        print(f"    [+] Saved Top Talkers to {top_talkers_file}")
    except Exception as e:
        print(f"    [!] Failed to extract top talkers: {e}")

    # 3. Dynamic Protocol & Anomaly Logging (Zeek)
    print("\n    [!] 3/3 Processing PCAP through Zeek for Protocol Forensics...")
    zeek_dir = os.path.join(output_dir, "zeek_logs")
    os.makedirs(zeek_dir, exist_ok=True)
    
    # We dump the PCAP into zeek which auto-generates readable logs (dns.log, http.log, ssl.log, weird.log)
    cmd_zeek = f"cd {zeek_dir} && zeek -C -r ../traffic_capture.pcap"
    try:
        subprocess.run(cmd_zeek, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"    [+] Zeek analysis complete. Logs saved in {zeek_dir}/")
        if os.path.exists(os.path.join(zeek_dir, "weird.log")):
            print("    [WARNING] Zeek 'weird.log' generated! Anomalous protocols detected.")
    except Exception:
        print("    [!] Zeek analysis failed or Zeek is not installed.")

    print("\n[+] Phase 4 Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 4: Traffic & Bandwidth Analysis")
    parser.add_argument("-i", "--interface", required=True, help="Network interface connected to SPAN port (e.g., eth0)")
    parser.add_argument("-d", "--duration", type=int, default=300, help="Capture duration in seconds (default: 300)")
    args = parser.parse_args()
    
    run_traffic_analysis(args.interface, args.duration)
