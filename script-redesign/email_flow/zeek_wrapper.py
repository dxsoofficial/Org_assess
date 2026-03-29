import os
import sys
import argparse
import subprocess
import time
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
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name, "out_zeek_monitoring"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(base_out_dir, f"raw_logs_{timestamp}")
    report_dir = os.path.join(base_out_dir, f"report_{timestamp}")
    
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    
    log(f"Created log directory: {log_dir}", "SUCCESS")
    log(f"Created report directory: {report_dir}", "SUCCESS")
    
    return log_dir, report_dir

def run_zeek_capture(interface, duration_mins, log_dir):
    try:
        log("Testing Docker availability...", "INFO")
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        log("Docker is not installed! Cannot run Zeek container.", "ERROR")
        return False
    except subprocess.CalledProcessError:
        log("Docker daemon not running over current user. Use sudo?", "ERROR")
        return False

    log(f"Starting Zeek capture on interface '{interface}' for {duration_mins} minutes via Docker...", "WARN")
    
    docker_cmd = [
        "sudo", "docker", "run", "--rm",
        "--network", "host",
        "--cap-add=NET_ADMIN",
        "--cap-add=NET_RAW",
        "-v", f"{log_dir}:/logs",
        "zeek/zeek",
        "zeek", "-i", interface, "Log::default_logdir=/logs"
    ]
    
    try:
        process = subprocess.Popen(docker_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Determine wait duration
        wait_seconds = duration_mins * 60
        elapsed = 0
        
        while elapsed < wait_seconds:
            time.sleep(5)
            elapsed += 5
            if process.poll() is not None:
                log("Zeek container unexpectedly exited early.", "ERROR")
                break
                
        if process.poll() is None:
            log("Capture time completed. Stopping Zeek container...", "INFO")
            # We don't have the container ID easily, so we just terminate Popen
            # But wait, it's running via `sudo docker run --rm`
            # To stop it cleanly we should kill the process locally or send SIGINT
            process.send_signal(subprocess.signal.SIGINT if hasattr(subprocess.signal, 'SIGINT') else 2)
            process.wait(timeout=10)
            
        log(f"Zeek capture complete. Logs flushed to {log_dir}", "SUCCESS")
        return True
        
    except Exception as e:
        log(f"Error launching Zeek container: {e}", "ERROR")
        return False

def generate_reports(log_dir, report_dir):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    generator = os.path.join(script_dir, "zeek_report_gen.py")
    
    if not os.path.exists(generator):
        log("zeek_report_gen.py is missing!", "ERROR")
        return
        
    try:
        subprocess.run([sys.executable, generator, "--log-dir", log_dir, "--out-dir", report_dir], check=True)
        log("Analysis pipeline executed successfully.", "SUCCESS")
    except subprocess.CalledProcessError as e:
        log(f"Report generation script failed: {e}", "ERROR")

def main():
    print("==========================================================")
    print("      Zeek Network Usage Monitoring - Wrapper             ")
    print("==========================================================")
    
    org_name = input("\nEnter the organization name [default: Unknown_Org]: ").strip().replace(" ", "_")
    if not org_name:
        org_name = "Unknown_Org"
        
    try:
        choice = input("Do you already have existing Zeek logs to analyze? [y/N]: ").strip().lower()
        if choice == 'y':
            log_dir = input("Enter full absolute path to the directory containing conn.log, dns.log, etc: ").strip()
            if not os.path.isdir(log_dir):
                log("Invalid directory path.", "ERROR")
                sys.exit(1)
            
            _, report_dir = setup_output_dir(org_name)
            log("Bypassing live capture. Passing logs straight to analyzer.", "WARN")
            generate_reports(log_dir, report_dir)
            
        else:
            interface = input("Enter interface for Live Network Capture (e.g., eth0) [default: eth0]: ").strip()
            if not interface:
                interface = "eth0"
                
            duration_input = input("Enter Capture duration (minutes) [default: 5]: ").strip()
            duration_mins = int(duration_input) if duration_input.isdigit() else 5
            
            log_dir, report_dir = setup_output_dir(org_name)
            
            success = run_zeek_capture(interface, duration_mins, log_dir)
            if success:
                print("\n==========================================================")
                generate_reports(log_dir, report_dir)
            
    except KeyboardInterrupt:
        print("\n")
        log("Zeek monitoring interrupted by user.", "WARN")
        sys.exit(0)

if __name__ == "__main__":
    main()
