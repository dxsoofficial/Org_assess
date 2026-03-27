import os
import sys
import subprocess
import argparse
import shutil
from datetime import datetime

def setup_output_dir(scan_type="out_scan"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", "Individual_Scan", scan_type))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"results_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)
    try:
        os.chmod(out_dir, 0o777)
    except:
        pass
    return out_dir

ASSESSMENT_FOCUS = [
    "Encryption Protocol Assessment", 
    "Guest Network Configuration", 
    "Firewall Integration", 
    "Bandwidth and Traffic Monitoring", 
    "Authentication Mechanisms"
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

def parse_tshark_pcap(out_dir, pcap_out):
    report_path = os.path.join(out_dir, "tshark_vulnerability_report.txt")
    findings = []
    
    log("Analyzing PCAP for vulnerabilities...", "INFO")
    
    # 1. Detect cleartext protocols (Telnet, FTP, HTTP)
    try:
        cleartext_cmd = ["tshark", "-r", pcap_out, "-Y", "telnet or ftp or http", "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol"]
        result = subprocess.run(cleartext_cmd, capture_output=True, text=True)
        lines = set([line.strip() for line in result.stdout.split('\n') if line.strip()])
        if lines:
            protocols_found = set([line.split()[-1] for line in lines if len(line.split()) > 0])
            findings.append((
                "Cleartext Protocol Used", 
                f"Unencrypted traffic detected: {', '.join(protocols_found)}", 
                "High"
            ))
    except Exception as e:
        log(f"Error checking cleartext protocols: {e}", "ERROR")

    # 2. Detect WEP Data Frames
    try:
        wep_cmd = ["tshark", "-r", pcap_out, "-Y", "wlan.wep.iv", "-T", "fields", "-e", "wlan.sa"]
        result = subprocess.run(wep_cmd, capture_output=True, text=True)
        lines = set([line.strip() for line in result.stdout.split('\n') if line.strip()])
        if lines:
            findings.append((
                "WEP Traffic Detected", 
                f"Active WEP encrypted traffic from MACs: {', '.join(list(lines)[:5])}", 
                "High"
            ))
    except Exception as e:
        pass

    # 3. Detect Deauthentication / Disassociation Frames (Possible WIDS / Attack)
    try:
        deauth_cmd = ["tshark", "-r", pcap_out, "-Y", "wlan.fc.type_subtype == 12 or wlan.fc.type_subtype == 10", "-T", "fields", "-e", "wlan.sa"]
        result = subprocess.run(deauth_cmd, capture_output=True, text=True)
        lines = list([line.strip() for line in result.stdout.split('\n') if line.strip()])
        if len(lines) > 50:
            findings.append((
                "Deauthentication Attack/Spike", 
                "High volume of deauth/disassoc frames detected. Possible evil twin or DoS.", 
                "Medium"
            ))
    except Exception as e:
        pass

    # 4. Authentication Mechanisms (Capture WPA Handshakes)
    try:
        eap_cmd = ["tshark", "-r", pcap_out, "-Y", "eapol", "-T", "fields", "-e", "wlan.bssid"]
        result = subprocess.run(eap_cmd, capture_output=True, text=True)
        lines = set([line.strip() for line in result.stdout.split('\n') if line.strip()])
        if lines:
            findings.append((
                "WPA/WPA2 Authentication Handshakes", 
                f"Captured EAPOL handshakes for {len(lines)} BSSIDs. These can be subjected to offline dictionary/brute-force attacks.", 
                "Medium"
            ))
    except Exception as e:
        pass

    # 5. Firewall Integration (Detect ICMP Unreachable / Drops)
    try:
        fw_cmd = ["tshark", "-r", pcap_out, "-Y", "icmp.type == 3", "-T", "fields", "-e", "ip.src"]
        result = subprocess.run(fw_cmd, capture_output=True, text=True)
        lines = set([line.strip() for line in result.stdout.split('\n') if line.strip()])
        if lines:
            findings.append((
                "Firewall / Filtering Behavior Detected", 
                f"Captured ICMP Destination Unreachable packets from {len(lines)} hosts, indicating active firewall/filtering blocks.", 
                "Low"
            ))
    except Exception as e:
        pass

    # 6. Guest Network Configuration (Detect L2/L3 Internal protocol bleed)
    try:
        bleed_cmd = ["tshark", "-r", pcap_out, "-Y", "udp.port == 5355 or udp.port == 1900 or stp", "-T", "fields", "-e", "wlan.sa"]
        result = subprocess.run(bleed_cmd, capture_output=True, text=True)
        lines = set([line.strip() for line in result.stdout.split('\n') if line.strip()])
        if lines:
            findings.append((
                "Internal Protocol Bleed (Guest Isolation Risk)", 
                "Captured internal discovery protocols (STP/LLMNR/SSDP). Validating guest/client isolation configurations is highly recommended.", 
                "Medium"
            ))
    except Exception as e:
        pass

    with open(report_path, "w") as f:
        f.write("==========================================================\n")
        f.write("             TSHARK VULNERABILITY MAPPING REPORT          \n")
        f.write("==========================================================\n\n")
        
        if not findings:
            f.write("No specific traffic vulnerabilities (cleartext, WEP, attacks) identified in PCAP.\n")
        else:
            for issue, detail, severity in sorted(findings, key=lambda x: {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}.get(x[2], 5)):
                f.write(f"[{severity.upper()}] {issue}\n")
                f.write(f"    Details: {detail}\n\n")
                
    log(f"TShark Vulnerability Report saved to: {report_path}", "SUCCESS")

def run_tshark(out_dir, interface, duration_hours):
    duration_secs = int(duration_hours * 3600)
    log(f"Starting TShark capture on {interface} for {duration_hours} hour(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    pcap_out = os.path.join(out_dir, "capture.pcap")
    tshark_out = os.path.join(out_dir, "tshark_out.txt")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tmp_pcap = f"/tmp/tshark_capture_{timestamp}.pcap"
    
    try:
        tshark_proc = subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration_secs}", "-w", tmp_pcap], 
                       capture_output=True, text=True)
                       
        if os.path.exists(tmp_pcap):
            shutil.move(tmp_pcap, pcap_out)
        
        if os.path.exists(pcap_out):
            analysis = subprocess.run(["tshark", "-r", pcap_out, "-q", "-z", "io,phs"], 
                                      capture_output=True, text=True)
            with open(tshark_out, "w") as f:
                f.write("--- TSHARK PROTOCOL HIERARCHY ANALYSIS ---\n")
                f.write(analysis.stdout)
            log(f"TShark protocol hierarchy analysis saved to: {tshark_out}", "SUCCESS")
            
            # Deep parse PCAP into vulnerability report
            parse_tshark_pcap(out_dir, pcap_out)
        else:
            log("TShark did not successfully generate a PCAP file.", "WARN")
            if tshark_proc.stderr:
                log(f"TShark Error Data:\n{tshark_proc.stderr.strip()}", "ERROR")
    except FileNotFoundError:
        log("TShark is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing TShark: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run TShark capture.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--interface", required=False, help="Monitor mode interface")
    parser.add_argument("--duration-hours", type=float, required=False, help="Duration in hours")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        print("\n--- TShark Capture (Interactive Mode) ---")
        args.interface = input("Enter the monitor mode interface (e.g., wlan0mon): ").strip()
        if not args.interface:
            log("Interface is required.", "ERROR")
            sys.exit(1)
            
        try:
            val = input("Enter hours of monitoring for TShark [default: 0.1]: ").strip()
            args.duration_hours = float(val) if val else 0.1
        except ValueError:
            args.duration_hours = 0.1
            log("Invalid input, defaulting to 0.1 hours.", "WARN")
    else:
        if not args.interface or args.duration_hours is None:
            parser.error("--interface and --duration-hours are required when using command-line arguments.")
            
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_wifi_tshark")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_tshark(args.out_dir, args.interface, args.duration_hours)
