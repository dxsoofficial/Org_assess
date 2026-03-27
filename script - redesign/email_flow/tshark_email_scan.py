import os
import sys
import subprocess
import argparse

ASSESSMENT_FOCUS = [
    "Recipient/Domain Tracking",
    "User Behavior Monitoring",
    "Historical Email Logging",
    "Real-Time Flow Alerts"
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

def run_tshark_email(out_dir, interface, duration_mins):
    duration_secs = duration_mins * 60
    log(f"Starting Live TShark Email Flow Capture on {interface} for {duration_mins} minute(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    pcap_out = os.path.join(out_dir, "email_traffic.pcap")
    log_out = os.path.join(out_dir, "historical_email_flows.txt")
    
    mail_ports = "tcp port 25 or tcp port 465 or tcp port 587 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"
    
    try:
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration_secs}", "-f", mail_ports, "-w", pcap_out], 
                       capture_output=True, text=True)
        
        if os.path.exists(pcap_out):
            analysis = subprocess.run(["tshark", "-r", pcap_out, "-q", "-z", "conv,tcp"], capture_output=True, text=True)
            with open(log_out, "w") as f:
                f.write(f"--- FILTERED EMAIL TRAFFIC LOG: {mail_ports} ---\n\n")
                f.write(analysis.stdout)
                
            log(f"Live email flow logging complete! Wrote PCAP to {pcap_out}.", "SUCCESS")
        else:
            log("TShark did not successfully generate a PCAP file.", "WARN")
            
    except FileNotFoundError:
        log("TShark is not installed. Skipping live flow capture.", "ERROR")
    except Exception as e:
        log(f"Error executing TShark: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run TShark live email traffic capture.")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument("--interface", required=True, help="Network interface")
    parser.add_argument("--duration-mins", type=int, required=True, help="Duration in minutes")
    
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    run_tshark_email(args.out_dir, args.interface, args.duration_mins)
