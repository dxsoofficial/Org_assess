import os
import sys
import subprocess
import time
from datetime import datetime
import shutil
import tempfile

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

def check_tshark():
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False

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

def set_ip_forwarding(enable=True):
    val = "1" if enable else "0"
    state = "Enabling" if enable else "Disabling"
    log(f"{state} IP Forwarding...", "INFO")
    try:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], capture_output=True, check=True)
    except Exception as e:
        log(f"Failed to set IP forwarding: {e}", "WARN")

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
            
        log("ARP Spoofing is now active.", "SUCCESS")
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

def run_capture(interface, duration, log_dir):
    temp_pcap = os.path.join(tempfile.gettempdir(), f"email_capture_temp_{int(time.time())}.pcap")
    pcap_file = os.path.join(log_dir, "email_capture.pcap")
    
    mail_ports = "tcp port 25 or tcp port 465 or tcp port 587 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"
    log(f"Starting TShark Email Flow capture on interface '{interface}' for {duration} seconds...", "WARN")
    
    cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-f", mail_ports, "-w", temp_pcap, "-q"]
    try:
        start_time = time.time()
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        
        while process.poll() is None:
            elapsed = int(time.time() - start_time)
            display_elapsed = min(elapsed, duration) 
            sys.stdout.write(f"\rCapturing Email Traffic... {display_elapsed}/{duration} seconds elapsed")
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
            log("Capture completed but PCAP file is empty. There may have been no email traffic on interface.", "ERROR")
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)
            return ""
            
    except Exception as e:
        log(f"Error launching TShark: {e}", "ERROR")
        return ""

def main():
    print("==========================================================")
    print("      Email Flow Monitoring & Content Analysis            ")
    print("==========================================================")
    
    if not check_tshark():
        log("TShark is not installed or not in PATH. Please install Wireshark/TShark first.", "ERROR")
        sys.exit(1)
        
    arpspoof_procs = []
    is_spoofing = False

    try:
        org_name = input("\nEnter the organization name [default: Unknown_Org]: ").strip().replace(" ", "_")
        if not org_name:
            org_name = "Unknown_Org"
            
        mode = input("Do you want to (1) Live Capture or (2) Analyze existing PCAP? [default: 2]: ").strip()
        if not mode:
            mode = "2"
            
        log_dir, report_dir = setup_output_dir(org_name)
        
        pcap_file = ""
        if mode == "1":
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                log("WARNING: TShark (raw socket access) and ARP Spoofing require root (sudo).", "WARN")
                time.sleep(2)
                
            interface = input("Enter interface for Live Network Capture (e.g., eth0) [default: eth0]: ").strip()
            if not interface:
                interface = "eth0"
                
            duration_input = input("Enter Capture duration (seconds) [default: 60]: ").strip()
            duration = int(duration_input) if duration_input.isdigit() else 60
            
            spoof_choice = input("Enable Active ARP Spoofing to intercept network email traffic? (y/N): ").strip().lower()
            if spoof_choice == 'y':
                gateway_ip = input("  Enter Router/Gateway IP (e.g., 192.168.1.1): ").strip()
                target_ip = input("  Enter Target IP (leave empty to intercept ALL subnet traffic): ").strip()
                
                if gateway_ip:
                    is_spoofing = True
                    set_ip_forwarding(enable=True)
                    arpspoof_procs = start_arp_spoofing(interface, gateway_ip, target_ip)
                else:
                    log("Router/Gateway IP is required to arp spoof. Bypassing interception.", "WARN")
                    
            pcap_file = run_capture(interface, duration, log_dir)
        else:
            pcap_path = input("Enter the full path to the existing PCAP file: ").strip()
            pcap_path = pcap_path.strip('"').strip("'")
            if os.path.isdir(pcap_path):
                if os.path.isfile(os.path.join(pcap_path, "email_capture.pcap")):
                    pcap_file = os.path.join(pcap_path, "email_capture.pcap")
                else:
                    log(f"Provided path is a directory and no email_capture.pcap was found inside: {pcap_path}", "ERROR")
                    sys.exit(1)
            elif os.path.isfile(pcap_path):
                pcap_file = pcap_path
            else:
                log(f"PCAP file not found: {pcap_path}", "ERROR")
                sys.exit(1)
        
        eml_file = input("\nEnter path to a raw email file (.eml) for Phase 1 static SpamAssassin assessment [leave blank to skip]: ").strip()
        target_domain = input("Enter Target Domain (e.g., company.com) to automatically assess its public DMARC/SPF Posture [leave blank to skip]: ").strip()
        
        if pcap_file and os.path.exists(pcap_file):
            print("\n==========================================================")
            run_discovery = input("Do you want to run Active Host Discovery to enrich the report? (y/n) [default: n]: ").strip().lower()
            if run_discovery == 'y':
                log("Triggering automated Host Discovery...", "INFO")
                script_dir = os.path.dirname(os.path.abspath(__file__))
                host_dis_sh = os.path.abspath(os.path.join(script_dir, "..", "Host-Discovery", "Host-Dis.sh"))
                if os.path.exists(host_dis_sh):
                    try:
                        host_dis_dir = os.path.dirname(host_dis_sh)
                        subprocess.run(["bash", host_dis_sh], input=org_name + "\n", text=True, check=True, cwd=host_dis_dir)
                        log("Host Discovery complete.", "SUCCESS")
                    except subprocess.CalledProcessError as e:
                        log(f"Host Discovery encountered an error: {e}", "ERROR")
                else:
                    log(f"Host Discovery script not found at {host_dis_sh}", "WARN")
                    
        log("Triggering parsing and analysis...", "INFO")
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parser_script = os.path.join(script_dir, "email_flow_parser.py")
        
        if os.path.exists(parser_script):
            try:
                cmd = [sys.executable, parser_script, 
                       "--pcap", pcap_file if pcap_file else "", 
                       "--report-dir", report_dir, 
                       "--org-name", org_name]
                if eml_file:
                    cmd.extend(["--eml", eml_file])
                if target_domain:
                    cmd.extend(["--domain", target_domain])
                
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                log(f"Parsing script encountered an error: {e}", "ERROR")
        else:
            log(f"Parser script not found at {parser_script}", "ERROR")
            
    except KeyboardInterrupt:
        print("\n")
        log("Email Flow monitoring interrupted by user.", "WARN")
    finally:
        if is_spoofing:
            print("\n--- Clean-up Phase ---")
            stop_arp_spoofing(arpspoof_procs)
            set_ip_forwarding(enable=False)
            
        sys.exit(0)

if __name__ == "__main__":
    main()
