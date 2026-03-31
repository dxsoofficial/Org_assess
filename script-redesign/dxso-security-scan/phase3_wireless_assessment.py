import os
import subprocess
import argparse
import time
from pathlib import Path

# DXSO Phase 3: Comprehensive Wireless Security Assessment
# Covers: SSID Review, Mac Filtering, Encryption Assessment, Password Strength, Guest Networks
# Dependencies: aircrack-ng, nmap, tshark, john

def run_wireless_assessment(interface, gateway_ip, output_dir="dxso_reports/3_Wireless_Assessment"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n=== PHASE 3: Comprehensive Wireless Security Assessment ===")

    # 1. Enable Monitor Mode (Required for Over-The-Air listening)
    print(f"\n[*] 1/6 Entering Monitor Mode on {interface}...")
    try:
        subprocess.run(f"sudo airmon-ng start {interface}", shell=True, check=True, stdout=subprocess.DEVNULL)
        mon_iface = f"{interface}mon"
        print(f"    [+] Monitor Mode established on {mon_iface}")
    except subprocess.CalledProcessError:
        print(f"    [!] Failed to enter Monitor Mode. Ensure adapter supports it.")
        mon_iface = interface # Fallback to trying the original interface

    # 2. SSID Review, Encryption Assessment, Guest Networks & MAC Filtering
    print(f"\n[*] 2/6 Air-Sniffing (SSIDs, Encryption, MAC filtering, Handshakes)...")
    capture_prefix = os.path.join(output_dir, "ota_capture")
    print(f"    [!] Running Airodump-ng for 60 seconds. Collecting .CSV and .CAP files...")
    
    # We use a timeout to let airodump-ng scan the airspace and auto-kill it
    cmd_airodump = f"sudo airodump-ng {mon_iface} --write {capture_prefix} --output-format csv,cap"
    try:
        subprocess.run(cmd_airodump, shell=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print(f"    [+] Air-Sniffing completed.")

    # 3. WIDS/WIPS Detection & Anomalous Behavior
    print(f"\n[*] 3/6 WIDS/WIPS Detection (Analyzing Packet Flood/Deauths)...")
    wids_log = os.path.join(output_dir, "wids_deauth_log.txt")
    print(f"    [!] Checking captured PCAP for Deauth frames (indicating WIPS blocking)...")
    # Quick tshark parse over the newly generated airodump PCAP to check for management frames
    cmd_tshark_deauth = f"tshark -r {capture_prefix}-01.cap -Y 'wlan.fc.type_subtype == 0x000c' > {wids_log} 2>/dev/null"
    subprocess.run(cmd_tshark_deauth, shell=True)
    print(f"    [+] Saved anomalous Deauth packets to {wids_log}")

    # 4. Router Firmware Update & Firewall Integration (Network Layer)
    print(f"\n[*] 4/6 Router/Gateway Vulnerability & Firewall Scan ({gateway_ip})")
    gateway_log = os.path.join(output_dir, "gateway_firmware_firewall.txt")
    # Nmap scans the gateway intensively to find firmware versions, exposed ports, and firewall rules
    cmd_nmap_gw = f"nmap -sV -sC -O -p 1-1000,8080,8443 {gateway_ip} -oN {gateway_log}"
    try:
        subprocess.run(cmd_nmap_gw, shell=True, check=True)
        print(f"    [+] Router scan complete. Logs in {gateway_log}")
    except subprocess.CalledProcessError:
        print(f"    [!] Nmap failed on gateway. Are you connected to {gateway_ip}?")

    # 5. Network Segmentation & Access Logic
    print(f"\n[*] 5/6 Network Segmentation Testing...")
    segmentation_log = os.path.join(output_dir, "segmentation_isolation.txt")
    with open(segmentation_log, "w") as f:
        f.write("=== NETWORK SEGMENTATION TESTS ===\n")
        f.write("Check if guest network clients can ping the internal gateway:\n")
    # Quick ping test to standard internal subnets mimicking guest lateral movement
    subprocess.run(f"ping -c 2 10.0.0.1 >> {segmentation_log} 2>&1", shell=True)
    subprocess.run(f"ping -c 2 172.16.0.1 >> {segmentation_log} 2>&1", shell=True)
    print(f"    [+] Static isolation logic checked.")

    # 6. Password Strength Analysis & Authentication Mechanisms
    print(f"\n[*] 6/6 Password Strength Analysis Preparations (John the Ripper / wpapcap2john)")
    hash_file = os.path.join(output_dir, "cracked_hashes.txt")
    print(f"    [!] Generating WPA Hash format from {capture_prefix}-01.cap for John the Ripper (if handshakes caught)")
    
    # We attempt to convert the standard CAP file into a John The Ripper readable hash, and run it
    cmd_convert = f"wpapcap2john {capture_prefix}-01.cap > {output_dir}/wpahash.txt 2>/dev/null"
    subprocess.run(cmd_convert, shell=True)
    
    print(f"\n=== PHASE 3 SUMMARY ===")
    print(f"Data saved to directory: {output_dir}")
    print(f"  > SSID/Encryption Review: {capture_prefix}-01.csv")
    print(f"  > Firmware/Firewall: {gateway_log}")
    print(f"  > WIDS/WIPS Logs: {wids_log}")
    print(f"  > Raw PCAP for Wireshark: {capture_prefix}-01.cap")
    
    print("\n[!] TO INITIATE PASSWORD CRACKING RUN:")
    print(f"     aircrack-ng {capture_prefix}-01.cap -w /usr/share/wordlists/rockyou.txt")
    print(f"     OR")
    print(f"     john --wordlist=/usr/share/wordlists/rockyou.txt {output_dir}/wpahash.txt")

    # Cleanup AirMon
    print(f"\n[*] Reverting Monitor Mode: sudo airmon-ng stop {mon_iface}")
    subprocess.run(f"sudo airmon-ng stop {mon_iface}", shell=True, stderr=subprocess.DEVNULL)


def get_phase1_config():
    config_file = "dxso_reports/1_Network_Discovery/network_config.txt"
    config = {"INTERFACE": "wlan0", "GATEWAY": "192.168.1.1"}
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            for line in f:
                if "=" in line:
                    key, val = line.strip().split("=", 1)
                    if val != "unknown":
                        config[key] = val
    return config

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 3: Wireless Security Assessment")
    parser.add_argument("-i", "--interface", help="Wireless interface to set to Monitor Mode (e.g., wlan0)")
    parser.add_argument("-g", "--gateway", help="Router/Gateway IP for Firmware, Segmentation, and Firewall checks")
    args = parser.parse_args()
    
    config = get_phase1_config()
    interface = args.interface or config.get("INTERFACE", "wlan0")
    gateway = args.gateway or config.get("GATEWAY", "192.168.1.1")
    
    print(f"[*] Starting Phase 3 with Interface: {interface} | Gateway: {gateway}")
    run_wireless_assessment(interface, gateway)
