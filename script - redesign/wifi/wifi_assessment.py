import os
import sys
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

# Tool Assessment Matrix defined by requirements
ASSESSMENT_FOCUS = {
    "Kismet": [
        "SSID Review", 
        "Guest Network Configuration", 
        "MAC Address Filtering", 
        "Access Point Placement", 
        "WIDS/WIPS Detection"
    ],
    "TShark": [
        "Encryption Protocol Assessment", 
        "Guest Network Configuration", 
        "Firewall Integration", 
        "Bandwidth and Traffic Monitoring", 
        "Authentication Mechanisms"
    ],
    "Nmap": [
        "CVE Discovery", 
        "Default Credential Detection", 
        "Insecure Service Configurations", 
        "Vulnerability Scripting Engine (NSE) Probing"
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

def setup_output_dir(org_name):
    """Creates a timestamped output directory for the current scan session."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "..", "output", org_name, "out_wifi"))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"assessment_results_{timestamp}")
    try:
        os.makedirs(out_dir, exist_ok=True)
        log(f"Created output directory: {out_dir}", "SUCCESS")
        return out_dir
    except Exception as e:
        log(f"Failed to create directory '{out_dir}': {e}", "ERROR")
        sys.exit(1)

def check_monitor_interface():
    """Checks for a wireless interface natively in monitor mode."""
    log("Checking for monitor mode interfaces...", "INFO")
    try:
        # 'iw dev' is standard on modern Ubuntu/Linux for wireless capabilities
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        current_iface = None
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[1]
            elif "type monitor" in line and current_iface:
                log(f"Detected monitor mode interface: {current_iface}", "SUCCESS")
                return current_iface
                
        log("No monitor mode interface detected.", "WARN")
        return None
    except FileNotFoundError:
        log("'iw' command not found. Cannot determine interface mode (is wireless-tools installed?).", "ERROR")
        return None
    except Exception as e:
        log(f"Error checking interfaces: {e}", "ERROR")
        return None

def run_kismet(out_dir, interface, duration_mins=5):
    """Runs Kismet for the specified duration and stores stdout."""
    duration_secs = duration_mins * 60
    log(f"Starting Kismet scan on {interface} for {duration_mins} minute(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS['Kismet'])}", "INFO")
    
    kismet_out = os.path.join(out_dir, "kismet_out.txt")
    try:
        # Run standard non-interactive kismet headless
        with open(kismet_out, "w") as f:
            process = subprocess.Popen(["kismet", "-c", interface, "--no-ncurses"], stdout=f, stderr=subprocess.STDOUT)
            time.sleep(duration_secs)
            process.terminate()
            process.wait(timeout=10)
        log(f"Kismet scan completed. Text output saved to: {kismet_out}", "SUCCESS")
        log(f"Additional kismet-related db logs are generally saved in the cwd.", "INFO")
    except FileNotFoundError:
        log("Kismet is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing Kismet: {e}", "ERROR")

def run_tshark(out_dir, interface, duration_mins=5):
    """Runs TShark to capture traffic and generates a protocol hierarchy analysis."""
    duration_secs = duration_mins * 60
    log(f"Starting TShark capture on {interface} for {duration_mins} minute(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS['TShark'])}", "INFO")
    
    pcap_out = os.path.join(out_dir, "capture.pcap")
    tshark_out = os.path.join(out_dir, "tshark_out.txt")
    
    try:
        # -a duration stops capture cleanly after specified seconds
        subprocess.run(["tshark", "-i", interface, "-a", f"duration:{duration_secs}", "-w", pcap_out], 
                       capture_output=True, text=True)
        
        # Analyze PCAP and save hierarchy results
        if os.path.exists(pcap_out):
            analysis = subprocess.run(["tshark", "-r", pcap_out, "-q", "-z", "io,phs"], 
                                      capture_output=True, text=True)
            with open(tshark_out, "w") as f:
                f.write("--- TSHARK PROTOCOL HIERARCHY ANALYSIS ---\n")
                f.write(analysis.stdout)
            log(f"TShark capture completed. Saved PCAP to: {pcap_out}", "SUCCESS")
            log(f"TShark protocol hierarchy analysis saved to: {tshark_out}", "SUCCESS")
        else:
            log("TShark did not successfully generate a PCAP file.", "WARN")
    except FileNotFoundError:
        log("TShark is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing TShark: {e}", "ERROR")

def parse_nmap_vulns(xml_file, out_dir):
    """Parses Nmap XML output to extract explicitly identified vulnerabilities."""
    vuln_report = os.path.join(out_dir, "vulnerability_report.txt")
    try:
        if not os.path.exists(xml_file):
            return
            
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        with open(vuln_report, "w") as f:
            f.write("==========================================================\n")
            f.write("                 VULNERABILITY ASSESSMENT REPORT          \n")
            f.write("==========================================================\n\n")
            
            found_vulns = False
            for host in root.findall('host'):
                address_elem = host.find('address')
                if address_elem is None:
                    continue
                address = address_elem.attrib.get('addr', 'Unknown IP')
                
                hostnames = host.findall('hostnames/hostname')
                hostname = hostnames[0].attrib.get('name') if hostnames else ""
                
                f.write(f"--- Target: {address} {f'({hostname})' if hostname else ''} ---\n")
                
                ports = host.findall('ports/port')
                for port in ports:
                    portid = port.attrib.get('portid', 'unknown')
                    protocol = port.attrib.get('protocol', 'tcp')
                    service = port.find('service')
                    service_name = service.attrib.get('name', 'unknown') if service is not None else 'unknown'
                    
                    scripts = port.findall('script')
                    port_has_vuln = False
                    for script in scripts:
                        # Output from vulnerability scripts
                        script_id = script.attrib.get('id', '')
                        script_output = script.attrib.get('output', '')
                        script_elements = script.findall('table') + script.findall('elem')
                        
                        # Only include script output if it contains signs of vulnerabilities
                        if "VULNERABLE:" in script_output or "CVE-" in script_output or "State: VULNERABLE" in script_output or "vuln" in script_id.lower() or len(script_elements) > 0:
                            if not port_has_vuln:
                                f.write(f"\n  [!] Port {portid}/{protocol} ({service_name}) has detected vulnerabilities/information:\n")
                                port_has_vuln = True
                                found_vulns = True
                            
                            f.write(f"      - Script: {script_id}\n")
                            # Format multiline output safely
                            if script_output:
                                formatted_output = "\n".join([f"        {line}" for line in script_output.split("\n")])
                                f.write(f"        Output:\n{formatted_output}\n\n")
                            else:
                                f.write("        (Structured output parsed. See XML for details)\n\n")
                            
            if not found_vulns:
                f.write("No explicit vulnerabilities (CVEs or critical misconfigurations) were identified by Nmap's vulnerability engine.\n")
                
        log(f"Vulnerability report compiled and saved to: {vuln_report}", "SUCCESS")
    except Exception as e:
        log(f"Error parsing Nmap XML: {e}", "ERROR")

def run_nmap(out_dir, target):
    """Runs Nmap scan on the given CIDR/IP and outputs results."""
    log(f"Starting Active Vulnerability scan with Nmap on target {target}...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS['Nmap'])}", "WARN")
    
    nmap_xml = os.path.join(out_dir, "nmap_vuln_scan.xml")
    nmap_txt = os.path.join(out_dir, "nmap_vuln_scan_full.txt")
    
    try:
        log("Running deep vulnerability scan. This may take longer than standard scans...", "INFO")
        # Added --script vuln to perform the actual vulnerability assessment
        # Outputs to both XML (for parsing) and normal text (for full records)
        with open(nmap_txt, "w") as f, open(os.devnull, "w") as devnull:
            subprocess.run(["nmap", "-T4", "-A", "--script", "vuln", "-Pn", "-oX", nmap_xml, target], stdout=f, stderr=devnull)
            
        log(f"Full Nmap scan completed. Text Output saved to: {nmap_txt}", "SUCCESS")
        
        if os.path.exists(nmap_xml):
            parse_nmap_vulns(nmap_xml, out_dir)
            
    except FileNotFoundError:
        log("Nmap is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing Nmap: {e}", "ERROR")

def main():
    print("==========================================================")
    print("        Wi-Fi & Network Security Assessment Script        ")
    print("==========================================================")
    
    # Alert if not running as root
    if os.geteuid() != 0:
        log("WARNING: This script typically must be run as root (sudo) to perform raw packet capture, Kismet runs, and Nmap OS scanning properly.", "WARN")
        time.sleep(2)
        
    try:
        org_name = input("\nEnter the organization name in which the assessment is performed: ").strip().replace(" ", "_")
        if not org_name:
            org_name = "Unknown_Org"
            
        # Request target input
        target = input("\nEnter target IP or CIDR for Nmap (e.g., 192.168.1.0/24) [default: 192.168.1.0/24]: ").strip()
        if not target:
            target = "192.168.1.0/24"
            log(f"No target provided, defaulting to {target}", "INFO")
            
        out_dir = setup_output_dir(org_name)
        
        # Phase 1: Wi-Fi Scans
        print("\n--- Phase 1: Wi-Fi Assessment ---")
        monitor_interface = check_monitor_interface()
        
        if monitor_interface:
            run_kismet(out_dir, monitor_interface, duration_mins=5)
            run_tshark(out_dir, monitor_interface, duration_mins=5)
        else:
            log("Skipping Wi-Fi assessment (Kismet/TShark). No monitor mode interface found.", "WARN")
            log("Hint: Use 'sudo airmon-ng start <interface>' to put a card into monitor mode.", "INFO")
            
        # Phase 2: Internal/Network Scans
        print("\n--- Phase 2: Network Assessment ---")
        run_nmap(out_dir, target)
        
        print("\n==========================================================")
        log(f"Assessment complete! Results are stored in '{os.path.abspath(out_dir)}'", "SUCCESS")
        
    except KeyboardInterrupt:
        print("\n")
        log("Assessment forcefully interrupted by user. Exiting...", "WARN")
        sys.exit(0)

if __name__ == "__main__":
    main()
