import os
import sys
import time
import subprocess
from datetime import datetime

# Tool Assessment Matrix defined by requirements
ASSESSMENT_FOCUS = {
    "Suricata": [
        "File Transfer Monitoring",
        "Protocol Identification",
        "Encrypted vs UnEncrypted Data",
        "Unauthorized Transfers",
        "Real Time Alerts"
    ]
}

def log(msg, level="INFO"):
    """Prints formatted color-coded log messages."""
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
    """Creates a timestamped output directory for the current monitoring session."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "..", "output", org_name, "out_data_transfer"))
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
    """Enables or disables IP forwarding to act as a router during ARP Spoofing."""
    val = "1" if enable else "0"
    state = "Enabling" if enable else "Disabling"
    log(f"{state} IP Forwarding...", "INFO")
    try:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True, check=True)
    except Exception as e:
        log(f"Failed to set IP forwarding. Interception might drop victim's internet: {e}", "WARN")

def start_arp_spoofing(interface, gateway_ip, target_ip=""):
    """Starts bidirectional ARP spoofing to capture whole network/target traffic."""
    procs = []
    try:
        # Verify arpspoof is installed (part of dsniff)
        subprocess.run(["arpspoof", "-h"], capture_output=True)
        
        log(f"Initiating ARP Spoofing on {interface} to intercept traffic...", "WARN")
        
        # We need the user to either spoof exactly one target or the entire subnet
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
    """Terminates ARP spoofing processes safely."""
    if procs:
        log("Stopping active interception (ARP Spoofing) and cleaning up...", "INFO")
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
        log("Target traffic routing restored to normal.", "SUCCESS")

def compile_results(out_dir):
    """Parses Suricata logs and consolidates them into a single file."""
    log("Consolidating Suricata logs into a single report...", "INFO")
    
    fast_log_path = os.path.join(out_dir, "fast.log")
    suricata_console = os.path.join(out_dir, "suricata_console_out.txt")
    eve_json_path = os.path.join(out_dir, "eve.json")
    suricata_log_path = os.path.join(out_dir, "suricata.log")
    stats_log_path = os.path.join(out_dir, "stats.log")
    
    final_report_path = os.path.join(out_dir, "data_transfer_report.txt")
    
    try:
        with open(final_report_path, "w") as report:
            report.write("==========================================================\n")
            report.write("          DATA TRANSFER & PROTOCOL MONITORING REPORT      \n")
            report.write("==========================================================\n\n")
            
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
        log(f"Report successfully compiled into: {final_report_path}", "SUCCESS")
        
    except Exception as e:
        log(f"Error compiling final report: {e}", "ERROR")

def run_suricata(out_dir, interface, duration_mins=5):
    """Runs Suricata for monitoring data transfers and protocol identification."""
    duration_secs = duration_mins * 60
    log(f"Starting Suricata monitoring on {interface} for {duration_mins} minute(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS['Suricata'])}", "INFO")
    
    suricata_console_log = os.path.join(out_dir, "suricata_console_out.txt")
    
    try:
        # Check if suricata is installed
        subprocess.run(["suricata", "-V"], capture_output=True, check=True)
        
        # Run Suricata: -i <interface>, -l <log_dir>
        with open(suricata_console_log, "w") as f:
            process = subprocess.Popen(["suricata", "-i", interface, "-l", out_dir], stdout=f, stderr=subprocess.STDOUT)
            
            log(f"Suricata is now capturing and analyzing traffic on {interface}...", "SUCCESS")
            
            # Simple progress monitor
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

def main():
    print("==========================================================")
    print("          Data Transfer Monitoring - Suricata             ")
    print("==========================================================")
    
    # Alert if not running as root
    if os.geteuid() != 0:
        log("WARNING: This script highly depends on raw access to interfaces. It should be run as root (sudo).", "WARN")
        time.sleep(2)
        
    arpspoof_procs = []
    is_spoofing = False
    
    try:
        org_name = input("\nEnter the organization name in which the assessment is performed: ").strip().replace(" ", "_")
        if not org_name:
            org_name = "Unknown_Org"
            
        # Request interface input
        interface = input("\nEnter network interface to monitor (e.g., eth0, wlan0) [default: eth0]: ").strip()
        if not interface:
            interface = "eth0"
            log(f"No interface provided, defaulting to {interface}", "INFO")
            
        duration_input = input("Enter duration to monitor in minutes [default: 5]: ").strip()
        duration_mins = int(duration_input) if duration_input.isdigit() else 5
        
        # Active Pen-Testing Setup
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
        
        print("\n--- Phase 2: Live Monitoring ---")
        run_suricata(out_dir, interface, duration_mins=duration_mins)
        
        print("\n==========================================================")
        log(f"Monitoring Phase complete!", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Monitoring forcefully interrupted by user.", "WARN")
    finally:
        # Ensure we always clean up the malicious routing rules if we crash or exit!
        if is_spoofing:
            print("\n--- Clean-up Phase ---")
            stop_arp_spoofing(arpspoof_procs)
            set_ip_forwarding(enable=False)
            
        sys.exit(0)

if __name__ == "__main__":
    main()
