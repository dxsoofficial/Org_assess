import os
import sys
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
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name, "out_internet_usage"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(base_out_dir, f"logs_{timestamp}")
    report_dir = os.path.join(base_out_dir, f"report_{timestamp}")
    
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    
    log(f"Created log directory: {log_dir}", "SUCCESS")
    log(f"Created report directory: {report_dir}", "SUCCESS")
    
    return log_dir, report_dir

def check_tshark():
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False

def run_capture(interface, duration, log_dir):
    # TShark often drops privileges after starting. To avoid permission denied errors
    # when writing to root or home directories, we write to /tmp first.
    import shutil
    temp_pcap = f"/tmp/capture_temp_{int(time.time())}.pcap"
    pcap_file = os.path.join(log_dir, "capture.pcap")
    
    log(f"Starting TShark capture on interface '{interface}' for {duration} seconds...", "WARN")
    
    cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", temp_pcap, "-q"]
    try:
        start_time = time.time()
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        
        while process.poll() is None:
            elapsed = int(time.time() - start_time)
            # Ensure not to exceed visually the stated duration too cleanly on the final tick due to process loop timing
            display_elapsed = min(elapsed, duration) 
            sys.stdout.write(f"\rCapturing... {display_elapsed}/{duration} seconds elapsed")
            sys.stdout.flush()
            time.sleep(1)
            
        sys.stdout.write("\n")
        
        if process.returncode != 0:
            err_out = process.stderr.read().strip()
            log(f"TShark encountered an error: {err_out}", "ERROR")
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)
            return ""
            
        if os.path.exists(temp_pcap) and os.path.getsize(temp_pcap) > 0:
            shutil.move(temp_pcap, pcap_file)
            os.chmod(pcap_file, 0o666) # Ensure readable for parsing
            log(f"Capture complete. Saved to {pcap_file}", "SUCCESS")
            return pcap_file
        else:
            log("Capture completed but PCAP file is empty. There may have been no traffic on interface.", "ERROR")
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)
            return ""
            
    except Exception as e:
        log(f"Error launching TShark: {e}", "ERROR")
        return ""

def main():
    print("==========================================================")
    print("      Internet Usage Monitoring - Wrapper                 ")
    print("==========================================================")
    
    if not check_tshark():
        log("TShark is not installed. Please install it first ('sudo apt install tshark').", "ERROR")
        sys.exit(1)
        
    org_name = input("\nEnter the organization name [default: Unknown_Org]: ").strip().replace(" ", "_")
    if not org_name:
        org_name = "Unknown_Org"
        
    interface = input("Enter interface for Live Network Capture (e.g., eth0) [default: eth0]: ").strip()
    if not interface:
        interface = "eth0"
        
    duration_input = input("Enter Capture duration (seconds) [default: 60]: ").strip()
    duration = int(duration_input) if duration_input.isdigit() else 60
    
    log_dir, report_dir = setup_output_dir(org_name)
    
    pcap_file = run_capture(interface, duration, log_dir)
    
    if pcap_file and os.path.exists(pcap_file):
        print("\n==========================================================")
        log("Triggering parsing and analysis...", "INFO")
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parser_script = os.path.join(script_dir, "internet_usage_parser.py")
        
        if os.path.exists(parser_script):
            try:
                subprocess.run([sys.executable, parser_script, pcap_file, report_dir], check=True)
            except subprocess.CalledProcessError as e:
                log(f"Parsing script encountered an error: {e}", "ERROR")
        else:
            log(f"Parser script not found at {parser_script}", "ERROR")
            
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        log("Internet usage monitoring interrupted by user.", "WARN")
        sys.exit(0)
