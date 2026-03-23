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

def setup_output_dir():
    """Creates a timestamped output directory for the current monitoring session."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "..", "output", "out_data_transfer"))
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
        # We output standard terminal execution logs to a text file.
        # Suricata outputs its primary findings (alerts, network flows, file transfers) into the log dir (eve.json, fast.log, stats.log).
        with open(suricata_console_log, "w") as f:
            process = subprocess.Popen(["suricata", "-i", interface, "-l", out_dir], stdout=f, stderr=subprocess.STDOUT)
            
            log(f"Suricata is now capturing and analyzing traffic on {interface}...", "SUCCESS")
            log(f"While running, check '{os.path.join(out_dir, 'eve.json')}' to see real-time protocol identification and file transfer metadata.", "INFO")
            
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
        
    try:
        # Request interface input
        interface = input("\nEnter network interface to monitor (e.g., eth0, wlan0) [default: eth0]: ").strip()
        if not interface:
            interface = "eth0"
            log(f"No interface provided, defaulting to {interface}", "INFO")
            
        duration_input = input("Enter duration to monitor in minutes [default: 5]: ").strip()
        duration_mins = int(duration_input) if duration_input.isdigit() else 5
            
        out_dir = setup_output_dir()
        
        print("\n--- Phase 1: Live Monitoring ---")
        run_suricata(out_dir, interface, duration_mins=duration_mins)
        
        print("\n==========================================================")
        log(f"Monitoring complete! Important log files are located in: '{os.path.abspath(out_dir)}'", "SUCCESS")
        log(f" - eve.json: Contains highly structured JSON with protocol IDs, encrypted/unencrypted flows, and file transfers.", "INFO")
        log(f" - fast.log: Contains simple single-line alert messages for unauthorized/flagged transfers.", "INFO")
        log(f" - stats.log: Contains Suricata packet processing stats.", "INFO")
        
    except KeyboardInterrupt:
        print("\n")
        log("Monitoring forcefully interrupted by user. Exiting...", "WARN")
        sys.exit(0)

if __name__ == "__main__":
    main()
