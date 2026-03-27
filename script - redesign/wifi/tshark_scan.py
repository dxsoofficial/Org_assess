import os
import sys
import subprocess
import argparse
from datetime import datetime

def setup_output_dir(scan_type="out_scan"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", "Individual_Scan", scan_type))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"results_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

ASSESSMENT_FOCUS = [
    "Encryption Protocol Assessment", 
    "Guest Network Configuration", 
    "Firewall Integration", 
    "Bandwidth and Traffic Monitoring", 
    "Authentication Mechanisms"
]

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

def run_tshark(out_dir, interface, duration_hours):
    duration_secs = int(duration_hours * 3600)
    log(f"Starting TShark capture on {interface} for {duration_hours} hour(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    pcap_out = os.path.join(out_dir, "capture.pcap")
    tshark_out = os.path.join(out_dir, "tshark_out.txt")
    
    try:
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration_secs}", "-w", pcap_out], 
                       capture_output=True, text=True)
        
        if os.path.exists(pcap_out):
            analysis = subprocess.run(["tshark", "-r", pcap_out, "-q", "-z", "io,phs"], 
                                      capture_output=True, text=True)
            with open(tshark_out, "w") as f:
                f.write("--- TSHARK PROTOCOL HIERARCHY ANALYSIS ---\n")
                f.write(analysis.stdout)
            log(f"TShark capture completed. Saved PCAP to: {pcap_out}", "SUCCESS")
            log(f"TShark protocol hierarchy analysis saved to: {tshark_out}", "SUCCESS")
        else:
            log("TShark did not successfully generate a PCAP file.", "WARN")
    except FileNotFoundError:
        log("TShark is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing TShark: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run TShark capture.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--interface", required=True, help="Monitor mode interface")
    parser.add_argument("--duration-hours", type=float, required=True, help="Duration in hours")
    
    args = parser.parse_args()
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_wifi_tshark")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_tshark(args.out_dir, args.interface, args.duration_hours)
