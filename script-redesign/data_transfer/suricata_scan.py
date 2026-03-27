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
    "File Transfer Monitoring",
    "Protocol Identification",
    "Encrypted vs UnEncrypted Data",
    "Unauthorized Transfers",
    "Real Time Alerts"
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

def compile_results(out_dir):
    log("Consolidating Suricata logs and applying Vulnerability Mapping Layer...", "INFO")
    
    fast_log_path = os.path.join(out_dir, "fast.log")
    suricata_console = os.path.join(out_dir, "suricata_console_out.txt")
    eve_json_path = os.path.join(out_dir, "eve.json")
    suricata_log_path = os.path.join(out_dir, "suricata.log")
    stats_log_path = os.path.join(out_dir, "stats.log")
    
    final_report_path = os.path.join(out_dir, "data_transfer_report.txt")
    
    try:
        # Run Vulnerability Mapping Layer
        import data_transfer_parser
        report_data = data_transfer_parser.parse_eve_json(eve_json_path)
        formatted_vuln_report = data_transfer_parser.generate_report_text(report_data)
        
        with open(final_report_path, "w") as report:
            report.write("==========================================================\n")
            report.write("   DATA TRANSFER & PROTOCOL MONITORING RISK REPORT        \n")
            report.write("==========================================================\n\n")
            
            report.write(formatted_vuln_report)
            report.write("\n----------------------------------------------------------\n")
            
            report.write("--- Suricata System Operations ---\n")
            if os.path.exists(suricata_console):
                with open(suricata_console, "r") as f:
                    report.write(f.read() + "\n")
            else:
                report.write("No system logs found.\n\n")
                
            report.write("--- Network Alerts (Protocol & Transfer Flags) ---\n")
            if os.path.exists(fast_log_path):
                with open(fast_log_path, "r") as f:
                    alerts = f.readlines()
                    if alerts:
                        report.writelines(alerts)
                    else:
                        report.write("No suspicious or flagged transfers detected.\n")
            else:
                report.write("No alerts file generated.\n")
            report.write("\n")
            
        for file in [fast_log_path, stats_log_path, eve_json_path, suricata_log_path, suricata_console]:
            if os.path.exists(file):
                os.remove(file)
                
        log("Cleaned up raw JSON and scattered log files.", "INFO")
        log(f"Risk Report successfully compiled into: {final_report_path}", "SUCCESS")
        
    except Exception as e:
        log(f"Error compiling final report: {e}", "ERROR")

def run_suricata(out_dir, interface, duration_mins):
    duration_secs = duration_mins * 60
    log(f"Starting Suricata monitoring on {interface} for {duration_mins} minute(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    suricata_console_log = os.path.join(out_dir, "suricata_console_out.txt")
    
    try:
        subprocess.run(["suricata", "-V"], capture_output=True, check=True)
        
        with open(suricata_console_log, "w") as f:
            process = subprocess.Popen(["suricata", "-i", interface, "-l", out_dir], stdout=f, stderr=subprocess.STDOUT)
            
            log(f"Suricata is now capturing and analyzing traffic on {interface}...", "SUCCESS")
            
            elapsed = 0
            while elapsed < duration_secs:
                time.sleep(5)
                elapsed += 5
                if process.poll() is not None:
                    log("Suricata process exited unexpectedly.", "ERROR")
                    break
                    
            if process.poll() is None:
                log("Completed run duration. Stopping Suricata safely...", "INFO")
                process.terminate()
                process.wait(timeout=10)
                log("Suricata monitoring completed.", "SUCCESS")
                compile_results(out_dir)
                
    except FileNotFoundError:
        log("Suricata is not found in PATH. Please install it (e.g., 'sudo apt install suricata').", "ERROR")
    except subprocess.CalledProcessError:
        log("Suricata seems to be improperly installed.", "ERROR")
    except Exception as e:
        log(f"Error executing Suricata: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Suricata scan.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--interface", required=False, help="Network interface")
    parser.add_argument("--duration-mins", type=int, required=False, help="Duration in minutes")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        print("\n--- Suricata Scan (Interactive Mode) ---")
        args.interface = input("Enter the network interface (e.g., eth0, wlan0): ").strip()
        if not args.interface:
            log("Interface is required.", "ERROR")
            sys.exit(1)
            
        try:
            val = input("Enter duration to monitor in minutes [default: 5]: ").strip()
            args.duration_mins = int(val) if val else 5
        except ValueError:
            args.duration_mins = 5
            log("Invalid input, defaulting to 5 minutes.", "WARN")
    else:
        if not args.interface or args.duration_mins is None:
            parser.error("--interface and --duration-mins are required when using command-line arguments.")
            
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_suricata")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_suricata(args.out_dir, args.interface, args.duration_mins)
