import os
import sys
import subprocess
import xml.etree.ElementTree as ET
import argparse

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
                        script_id = script.attrib.get('id', '')
                        script_output = script.attrib.get('output', '')
                        script_elements = script.findall('table') + script.findall('elem')
                        
                        if "VULNERABLE:" in script_output or "CVE-" in script_output or "State: VULNERABLE" in script_output or "vuln" in script_id.lower() or len(script_elements) > 0:
                            if not port_has_vuln:
                                f.write(f"\n  [!] Port {portid}/{protocol} ({service_name}) has detected vulnerabilities/information:\n")
                                port_has_vuln = True
                                found_vulns = True
                            
                            f.write(f"      - Script: {script_id}\n")
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
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument("--target", required=True, help="Target IP or CIDR")
    parser.add_argument("--max-hours", type=float, required=False, default=1.0, help="Max duration in hours per host timeout")
    
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    run_nmap(args.out_dir, args.target, args.max_hours)
