import os
import sys
import time
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
    "SSID Review", 
    "Guest Network Configuration", 
    "MAC Address Filtering", 
    "Access Point Placement", 
    "WIDS/WIPS Detection"
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

def run_kismet(out_dir, interface, duration_hours):
    duration_secs = int(duration_hours * 3600)
    log(f"Starting Kismet scan on {interface} for {duration_hours} hour(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    kismet_out = os.path.join(out_dir, "kismet_out.txt")
    try:
        with open(kismet_out, "w") as f:
            process = subprocess.Popen(["kismet", "-c", interface, "--no-ncurses"], stdout=f, stderr=subprocess.STDOUT)
            time.sleep(duration_secs)
            process.terminate()
            process.wait(timeout=10)
        log(f"Kismet scan completed. Text output saved to: {kismet_out}", "SUCCESS")
        log(f"Additional kismet-related db logs are generally saved in the cwd.", "INFO")
    except FileNotFoundError:
        log("Kismet is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing Kismet: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Kismet scan.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--interface", required=True, help="Monitor mode interface")
    parser.add_argument("--duration-hours", type=float, required=True, help="Duration in hours")
    
    args = parser.parse_args()
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_wifi_kismet")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_kismet(args.out_dir, args.interface, args.duration_hours)
