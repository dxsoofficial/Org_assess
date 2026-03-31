import os
import sys
import subprocess
import time
from datetime import datetime
import shutil

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
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name, "out_zeek_internet_usage"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(base_out_dir, f"logs_{timestamp}")
    report_dir = os.path.join(base_out_dir, f"report_{timestamp}")
    
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    
    # Allow zeek (if it drops privileges) to write
    os.chmod(log_dir, 0o777)
    os.chmod(report_dir, 0o777)
    
    log(f"Created log directory: {log_dir}", "SUCCESS")
    log(f"Created report directory: {report_dir}", "SUCCESS")
    
    return log_dir, report_dir

def check_zeek():
    if shutil.which("zeek"):
        return True
    try:
        subprocess.run(["zeek", "--version"], capture_output=True, check=True)
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False

def run_capture(interface, duration, log_dir):
    log(f"Starting native Zeek capture on interface '{interface}' for {duration} seconds...", "WARN")
    
    # We set cwd to log_dir so all .log files naturally drop in there
    cmd = ["zeek", "-i", interface]
    try:
        start_time = time.time()
        # Natively, Zeek writes to stdout occasionally. We can DEVNULL standard outputs. 
        process = subprocess.Popen(cmd, cwd=log_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        
        while process.poll() is None:
            elapsed = int(time.time() - start_time)
            display_elapsed = min(elapsed, duration) 
            sys.stdout.write(f"\rCapturing... {display_elapsed}/{duration} seconds elapsed")
            sys.stdout.flush()
            
            if elapsed >= duration:
                # Time's up, send SIGINT to terminate cleanly so buffers flush to disk
                process.send_signal(subprocess.signal.SIGINT if hasattr(subprocess.signal, 'SIGINT') else 2)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                break
                
            time.sleep(1)
            
        sys.stdout.write("\n")
        
        if process.returncode is not None and process.returncode not in (0, -2, 2, 130): 
            err_out = process.stderr.read().strip()
            log(f"Zeek encountered an error/warning (Code {process.returncode}): {err_out}", "ERROR")
            # Don't fail immediately, check if conn.log was created regardless
            
        conn_log = os.path.join(log_dir, "conn.log")
        if os.path.exists(conn_log) and os.path.getsize(conn_log) > 0:
            log(f"Capture complete. Zeek logs saved successfully in {log_dir}", "SUCCESS")
            return log_dir
        else:
            log("Capture completed but Zeek conn.log is missing/empty. Check privileges or interface traffic.", "ERROR")
            err = process.stderr.read().strip()
            if err: log(f"Stderr context: {err}", "ERROR")
            return ""
            
    except Exception as e:
        log(f"Error launching Zeek: {e}", "ERROR")
        return ""

def main():
    print("==========================================================")
    print("      Zeek Internet Usage Monitoring - Wrapper            ")
    print("==========================================================")
    
    if not check_zeek():
        log("Zeek is not natively installed in PATH. Please install it ('sudo apt install zeek').", "ERROR")
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
    
    valid_log_dir = run_capture(interface, duration, log_dir)
    
    if valid_log_dir:
        print("\n==========================================================")
        log("Triggering parsing and analysis...", "INFO")
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parser_script = os.path.join(script_dir, "zeek_internet_usage_parser.py")
        
        if os.path.exists(parser_script):
            try:
                subprocess.run([sys.executable, parser_script, valid_log_dir, report_dir], check=True)
            except subprocess.CalledProcessError as e:
                log(f"Parsing script encountered an error: {e}", "ERROR")
        else:
            log(f"Parser script not found at {parser_script}", "ERROR")
            
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        log("Zeek internet usage monitoring interrupted by user.", "WARN")
        sys.exit(0)
