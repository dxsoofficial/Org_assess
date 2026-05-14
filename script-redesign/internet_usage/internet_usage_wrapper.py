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
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name))
    os.makedirs(base_out_dir, exist_ok=True)
    
    log_dir = os.path.join(base_out_dir, "log")
    report_dir = os.path.join(base_out_dir, "report")
    
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
    # TShark often drops privileges after starting. 
    import shutil
    import tempfile
    temp_pcap = os.path.join(tempfile.gettempdir(), f"capture_temp_{int(time.time())}.pcap")
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
        log("TShark is not installed or not in PATH. Please install Wireshark/TShark first.", "ERROR")
        sys.exit(1)
        
    org_name = input("\nEnter the organization name [default: Unknown_Org]: ").strip().replace(" ", "_")
    if not org_name:
        org_name = "Unknown_Org"
        
    mode = input("Do you want to (1) Live Capture or (2) Analyze existing PCAP? [default: 2]: ").strip()
    if not mode:
        mode = "2"
        
    log_dir, report_dir = setup_output_dir(org_name)
    
    pcap_file = ""
    if mode == "1":
        interface = input("Enter interface for Live Network Capture (e.g., 1 or eth0) [default: 1]: ").strip()
        if not interface:
            interface = "1"
            
        duration_input = input("Enter Capture duration (seconds) [default: 60]: ").strip()
        duration = int(duration_input) if duration_input.isdigit() else 60
        
        pcap_file = run_capture(interface, duration, log_dir)
    else:
        pcap_path = input("Enter the full path to the existing PCAP file: ").strip()
        # Remove quotes if dragged and dropped
        pcap_path = pcap_path.strip('"').strip("'")
        if os.path.isdir(pcap_path):
            if os.path.isfile(os.path.join(pcap_path, "capture.pcap")):
                pcap_file = os.path.join(pcap_path, "capture.pcap")
            elif os.path.isfile(os.path.join(pcap_path, "capture.pcapng")):
                pcap_file = os.path.join(pcap_path, "capture.pcapng")
            else:
                log(f"Provided path is a directory and no capture.pcap was found inside: {pcap_path}", "ERROR")
                sys.exit(1)
        elif os.path.isfile(pcap_path):
            pcap_file = pcap_path
        else:
            log(f"PCAP file not found: {pcap_path}", "ERROR")
            sys.exit(1)
    
    if pcap_file and os.path.exists(pcap_file):
        print("\n==========================================================")
        log("Triggering parsing and analysis...", "INFO")
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parser_script = os.path.join(script_dir, "internet_usage_parser.py")
        
        if os.path.exists(parser_script):
            try:
                subprocess.run([sys.executable, parser_script, pcap_file, report_dir, org_name], check=True)
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
