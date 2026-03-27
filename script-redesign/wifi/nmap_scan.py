import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import argparse
from datetime import datetime

def setup_output_dir(scan_type="out_scan"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", "Individual_Scan", scan_type))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"results_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

ASSESSMENT_FOCUS = [
    "CVE Discovery", 
    "Default Credential Detection", 
    "Insecure Service Configurations", 
    "Vulnerability Scripting Engine (NSE) Probing"
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

def parse_nmap_vulns(xml_file, out_dir):
    vuln_report = os.path.join(out_dir, "nmap_vulnerability_report.txt")
    try:
        if not os.path.exists(xml_file):
            return
            
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        with open(vuln_report, "w") as f:
            f.write("==========================================================\n")
            f.write("             NMAP VULNERABILITY MAPPING REPORT          \n")
            f.write("==========================================================\n\n")
            
            findings = []
            
            # Check for MAC Address Filtering / Network Segmentation issues
            live_hosts = [host for host in root.findall('host') if host.find('status') is not None and host.find('status').attrib.get('state') == 'up']
            
            if len(live_hosts) == 0:
                findings.append((
                    "MAC Address Filtering / Strict Isolation", 
                    "No live hosts discovered by Nmap. This often indicates the presence of strict MAC address filtering or client isolation on the Wi-Fi network.", 
                    "Low"
                ))
            elif len(live_hosts) > 2: # Very low threshold for internal exposure on a targeted wireless interface
                findings.append((
                    "Network Segmentation Risk", 
                    f"Discovered {len(live_hosts)} visible hosts on this subnet. Validate if guest/wireless should have access to these.", 
                    "Critical"
                ))
            
            for host in live_hosts:
                address_elem = host.find('address')
                if address_elem is None:
                    continue
                address = address_elem.attrib.get('addr', 'Unknown IP')
                
                hostnames = host.findall('hostnames/hostname')
                hostname = hostnames[0].attrib.get('name') if hostnames else ""
                target_id = f"{address} {f'({hostname})' if hostname else ''}"
                
                # Check for Device type/firmware
                osmatch = host.find('os/osmatch')
                if osmatch is not None:
                    os_name = osmatch.attrib.get('name', 'Unknown')
                    if address.endswith('.1') or address.endswith('.254') or "router" in os_name.lower() or "gateway" in os_name.lower() or "ap" in os_name.lower():
                        findings.append((
                            "Router Firmware Update Audit",
                            f"Gateway/Router {target_id} identified as: '{os_name}'. Verify that this firmware version is fully patched and updated.",
                            "Medium"
                        ))
                    else:
                        findings.append((
                            "Device/Firmware Exposure",
                            f"{target_id} identified as: {os_name}",
                            "Low"
                        ))
                
                ports = host.findall('ports/port')
                has_filtered_ports = False
                for port in ports:
                    portid = port.attrib.get('portid', 'unknown')
                    protocol = port.attrib.get('protocol', 'tcp')
                    state_elem = port.find('state')
                    state = state_elem.attrib.get('state', 'unknown') if state_elem is not None else 'unknown'
                    
                    if state == "filtered":
                        has_filtered_ports = True
                        continue
                        
                    service = port.find('service')
                    service_name = service.attrib.get('name', 'unknown') if service is not None else 'unknown'
                    
                    # Mapping insecure services
                    target_port = f"Port {portid}/{protocol} ({service_name}) on {target_id}"
                    if service_name in ['telnet', 'ftp', 'rsh', 'login']:
                        findings.append((f"Insecure Cleartext Service: {service_name.upper()}", target_port, "High"))
                    elif service_name in ['ms-wbt-server', 'rdp', 'smb', 'netbios-ssn', 'ssh']:
                        findings.append((f"Exposed Internal Service: {service_name.upper()}", target_port, "Medium"))
                    elif service_name == 'upnp':
                        findings.append((f"Insecure Device Service: {service_name.upper()}", target_port, "High"))
                    
                    # Parse NSE scripts
                    scripts = port.findall('script')
                    for script in scripts:
                        script_id = script.attrib.get('id', '')
                        script_output = script.attrib.get('output', '')
                        script_elements = script.findall('table') + script.findall('elem')
                        
                        is_vuln = "VULNERABLE:" in script_output or "CVE-" in script_output or "State: VULNERABLE" in script_output or "vuln" in script_id.lower() or len(script_elements) > 0
                        
                        if is_vuln and "cve-20" in script_output.lower():
                            severity = "Critical"
                        elif is_vuln and ("DOS" in script_output.upper() or "RCE" in script_output.upper()):
                            severity = "Critical"
                        elif is_vuln:
                            severity = "High"
                        else:
                            continue
                            
                        findings.append((
                            f"NSE Script Vulnerability: {script_id}", 
                            f"{target_port}\n        Output: {script_output.split(chr(10))[0]}...", 
                            severity
                        ))
                
                if not has_filtered_ports and len(ports) > 0:
                    findings.append(("Firewall Integration Risk (Missing Firewall)", f"Target {target_id} does not appear to filter ports (all observed ports were either open or closed, not dropped).", "Medium"))
                            
            if not findings:
                f.write("No explicit vulnerabilities or critical misconfigurations identified by Nmap.\n")
            else:
                for issue, detail, severity in sorted(findings, key=lambda x: {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}.get(x[2], 5)):
                    f.write(f"[{severity.upper()}] {issue}\n")
                    f.write(f"    Details: {detail}\n\n")
                    
        log(f"Vulnerability report compiled and saved to: {vuln_report}", "SUCCESS")
    except Exception as e:
        log(f"Error parsing Nmap XML: {e}", "ERROR")

def run_nmap(out_dir, target, max_hours=1.0):
    log(f"Starting Active Vulnerability scan with Nmap on target {target} for up to {max_hours} hours...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "WARN")
    
    nmap_xml = os.path.join(out_dir, "nmap_vuln_scan.xml")
    nmap_txt = os.path.join(out_dir, "nmap_vuln_scan_full.txt")
    host_timeout = f"{int(max_hours * 60)}m" # Host timeout in minutes
    
    try:
        log("Running deep vulnerability scan. This may take longer than standard scans...", "INFO")
        with open(nmap_txt, "w") as f, open(os.devnull, "w") as devnull:
            subprocess.run(["nmap", "-T4", "-A", "--script", "vuln", "-Pn", f"--host-timeout={host_timeout}", "-oX", nmap_xml, target], stdout=f, stderr=devnull)
            
        log(f"Full Nmap scan completed. Text Output saved to: {nmap_txt}", "SUCCESS")
        
        if os.path.exists(nmap_xml):
            parse_nmap_vulns(nmap_xml, out_dir)
            
    except FileNotFoundError:
        log("Nmap is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing Nmap: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nmap vulnerability scan.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--target", required=True, help="Target IP or CIDR")
    parser.add_argument("--max-hours", type=float, required=False, default=1.0, help="Max duration in hours per host timeout")
    
    args = parser.parse_args()
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_wifi_nmap")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_nmap(args.out_dir, args.target, args.max_hours)
