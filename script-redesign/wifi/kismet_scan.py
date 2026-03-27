import os
import sys
import time
import subprocess
import argparse
import sqlite3
import json
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
    "SSID Review", 
    "Guest Network Configuration", 
    "MAC Address Filtering", 
    "Access Point Placement", 
    "WIDS/WIPS Detection"
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

def parse_kismetdb(out_dir):
    kismet_dbs = [f for f in os.listdir(out_dir) if f.endswith('.kismet')]
    if not kismet_dbs:
        log("No .kismet database found to analyze.", "WARN")
        return
        
    db_path = os.path.join(out_dir, kismet_dbs[0])
    log(f"Analyzing Kismet database: {db_path}", "INFO")
    
    report_path = os.path.join(out_dir, "kismet_vulnerability_report.txt")
    
    with open(report_path, "w") as f:
        f.write("==========================================================\n")
        f.write("             KISMET VULNERABILITY MAPPING REPORT          \n")
        f.write("==========================================================\n\n")
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            findings = []
            
            # 1. Parse Alerts for WIDS/WIPS (Rogue APs, Deauth attacks, etc.)
            try:
                cursor.execute("SELECT header, text FROM alerts")
                alert_rows = cursor.fetchall()
                for h, t in alert_rows:
                    findings.append((f"WIDS Alert: {h}", t, "High"))
            except sqlite3.OperationalError:
                pass
                
            # 2. Parse Devices for SSIDs, Encryption, Guest Networks
            cursor.execute("SELECT device FROM devices WHERE type = 'Wi-Fi AP' OR type = 'Wi-Fi Client'")
            rows = cursor.fetchall()
            
            for row in rows:
                device_json = row[0]
                if isinstance(device_json, bytes):
                    device_json = device_json.decode('utf-8', errors='ignore')
                try:
                    device = json.loads(device_json)
                except:
                    continue
                
                dot11 = device.get("dot11.device", {})
                bssid = device.get("kismet.device.base.mac", "Unknown")
                
                if device.get("kismet.device.base.type") == "Wi-Fi AP":
                    ssid_map = dot11.get("dot11.device.advertised_ssid_map", [])
                    for ssid_entry in ssid_map:
                        ssid = ssid_entry.get("dot11.advertisedssid.ssid", "Hidden")
                        crypt_str = ssid_entry.get("dot11.advertisedssid.crypt", "")
                        
                        if ssid == "Hidden" or not ssid:
                            findings.append(("Hidden SSID Detected", f"BSSID: {bssid} is obscuring its SSID.", "Medium"))
                        
                        if "Open" in crypt_str or "None" in crypt_str or crypt_str == "":
                            findings.append(("Open Network (Unencrypted)", f"SSID: {ssid} ({bssid}) has no encryption.", "Critical"))
                        elif "WEP" in crypt_str:
                            findings.append(("Weak Encryption (WEP)", f"SSID: {ssid} ({bssid}) uses broken WEP.", "High"))
                        elif "WPA1" in crypt_str or crypt_str == "WPA" and "WPA2" not in crypt_str:
                            findings.append(("Deprecated Encryption (WPA1)", f"SSID: {ssid} ({bssid}) uses WPA1.", "High"))
                            
                        if "guest" in ssid.lower():
                            findings.append(("Guest Network Discovered", f"SSID: {ssid} ({bssid}). Ensure strict client isolation and segmentation.", "Low"))
                            
                        # MAC Address Filtering audit recommendation (if network is hidden and encrypted)
                        if (ssid == "Hidden" or not ssid) and ("WPA" in crypt_str or "WEP" in crypt_str):
                            findings.append(("MAC Address Filtering Audit", f"BSSID: {bssid} is hidden and encrypted. Verify presence of MAC whitelist controls.", "Low"))
                            
                    # AP Placement inference
                    signal_dict = device.get("kismet.device.base.signal", {})
                    last_signal = signal_dict.get("kismet.common.signal.last_signal", -100) if isinstance(signal_dict, dict) else -100
                    if last_signal > -65 and last_signal < 0:
                        findings.append(("Access Point Placement Risk", f"BSSID: {bssid} has a high signal strength ({last_signal} dBm). AP placement may be causing excessive perimeter signal bleed.", "Medium"))
                            
            unique_findings = []
            for item in findings:
                if item not in unique_findings:
                    unique_findings.append(item)
                    
            if not unique_findings:
                f.write("No significant Wi-Fi vulnerabilities detected within the captured time frame.\n")
            else:
                for issue, detail, severity in sorted(unique_findings, key=lambda x: {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}.get(x[2], 5)):
                    f.write(f"[{severity.upper()}] {issue}\n")
                    f.write(f"    Details: {detail}\n\n")
                    
        except sqlite3.OperationalError as e:
            f.write(f"Error reading Kismet database (might lack supported tables): {e}\n")
        except Exception as e:
            f.write(f"Error during Kismet DB parsing: {e}\n")
            
    log(f"Kismet Vulnerability Report saved to: {report_path}", "SUCCESS")

def run_kismet(out_dir, interface, duration_hours):
    duration_secs = int(duration_hours * 3600)
    log(f"Starting Kismet scan on {interface} for {duration_hours} hour(s)...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    kismet_out = os.path.join(out_dir, "kismet_out.txt")
    try:
        with open(kismet_out, "w") as f:
            process = subprocess.Popen(["kismet", "-c", interface, "--no-ncurses"], stdout=f, stderr=subprocess.STDOUT, cwd=out_dir)
            time.sleep(duration_secs)
            process.terminate()
            process.wait(timeout=10)
        log(f"Kismet scan completed. Text output saved to: {kismet_out}", "SUCCESS")
        log(f"Additional kismet-related db logs are generally saved in the cwd.", "INFO")
        
        # Perform deep parsing and vulnerability mapping
        parse_kismetdb(out_dir)
        
    except FileNotFoundError:
        log("Kismet is not installed. Skipping step.", "ERROR")
    except Exception as e:
        log(f"Error executing Kismet: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Kismet scan.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--interface", required=True, help="Monitor mode interface")
    parser.add_argument("--duration-hours", type=float, required=True, help="Duration in hours")
    
    args = parser.parse_args()
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_wifi_kismet")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_kismet(args.out_dir, args.interface, args.duration_hours)
