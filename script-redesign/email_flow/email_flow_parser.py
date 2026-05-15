import sys
import os
import subprocess
import argparse
import csv
from datetime import datetime

def log(msg, level="INFO"):
    print(f"[{level}] {msg}")

def run_spamassassin(eml_file):
    log(f"Running SpamAssassin on {eml_file}...", "INFO")
    try:
        if not os.path.exists(eml_file):
            return "Error: Email file not found."
            
        with open(eml_file, "r") as infile:
            res = subprocess.run(["spamassassin", "-t"], stdin=infile, capture_output=True, text=True)
            return res.stdout
    except FileNotFoundError:
        return "SpamAssassin is not installed! (Install via 'sudo apt install spamassassin')"
    except Exception as e:
        return f"Error executing SpamAssassin: {e}"

def run_dns_posture(domain):
    log(f"Checking External DNS Posture for {domain}...", "INFO")
    report = []
    try:
        report.append(f"--- EXTERNAL DNS SECURITY POSTURE FOR: {domain} ---\n")
        
        # SPF Check
        report.append("[*] Verifying Primary SPF Record...")
        spf_process = subprocess.run(["nslookup", "-type=txt", domain], capture_output=True, text=True)
        spf_lines = [line.strip().replace('"', '') for line in spf_process.stdout.split('\n') if "v=spf1" in line.lower()]
        
        if spf_lines:
            report.append(f"  FOUND RECORD: {spf_lines[0]}")
            if "~all" in spf_lines[0]:
                report.append("  -> RATING: MODERATE (Softfail: '~all' allows delivery but marks as suspicious)")
            elif "-all" in spf_lines[0]:
                report.append("  -> RATING: EXCELLENT (Hardfail: '-all' rejects unauthorized senders perfectly)")
            elif "+all" in spf_lines[0] or "?all" in spf_lines[0]:
                report.append("  -> RATING: CRITICAL RISK (Permissive: explicitly allows unauthorized people to spoof this domain)")
        else:
            report.append("  -> RATING: CRITICAL RISK (No SPF Record Found! Domain can be easily spoofed.)")
        report.append("")
        
        # DMARC Check
        report.append("[*] Verifying DMARC Enforcement Protocols...")
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_process = subprocess.run(["nslookup", "-type=txt", dmarc_domain], capture_output=True, text=True)
        dmarc_lines = [line.strip().replace('"', '') for line in dmarc_process.stdout.split('\n') if "v=DMARC1" in line.upper()]
        
        if dmarc_lines:
            report.append(f"  FOUND RECORD: {dmarc_lines[0]}")
            if "p=reject" in dmarc_lines[0].lower():
                report.append("  -> RATING: EXCELLENT (Policy is Reject: highest protection against impersonation)")
            elif "p=quarantine" in dmarc_lines[0].lower():
                report.append("  -> RATING: GOOD (Policy is Quarantine: spoofed emails go safely into spam/junk)")
            elif "p=none" in dmarc_lines[0].lower():
                report.append("  -> RATING: WEAK (Policy is None: DMARC is essentially turned off.)")
        else:
            report.append("  -> RATING: CRITICAL RISK (No DMARC Record Found at all! No protection against exact-domain spoofing.)")
        report.append("")
        report.append("Note: DKIM checks require cryptographic selectors extracted from active email headers.")
        
        return "\n".join(report)
    except Exception as e:
        return f"Error executing External DNS checks: {e}"

def parse_pcap_email_flow(pcap_file, host_info):
    log("Extracting deeper application-layer email flow details from PCAP...", "INFO")
    
    mail_aspects = []
    
    # Use tshark to extract SMTP MAIL FROM and RCPT TO with timestamps
    try:
        # Check for Internet Message Format (IMF) which gives the highest fidelity
        cmd_imf = [
            "tshark", "-r", pcap_file,
            "-Y", "imf",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "imf.from",
            "-e", "imf.to",
            "-e", "imf.subject"
        ]
        imf_out = subprocess.check_output(cmd_imf, text=True, stderr=subprocess.DEVNULL)
        
        for line in imf_out.splitlines():
            parts = line.split('\t')
            if len(parts) >= 6:
                time_str = parts[0][:23]
                src_ip = parts[1]
                dst_ip = parts[2]
                sender = parts[3]
                receiver = parts[4]
                subject = parts[5]
                
                if sender and receiver:
                    src_host = host_info.get(src_ip, {}).get("hostname", src_ip)
                    dst_host = host_info.get(dst_ip, {}).get("hostname", dst_ip)
                    
                    mail_aspects.append({
                        "time": time_str,
                        "src": f"{src_host} ({src_ip})",
                        "dst": f"{dst_host} ({dst_ip})",
                        "sender_id": sender,
                        "receiver_id": receiver,
                        "subject": subject or "N/A"
                    })
                
        # If IMF not heavily present, fallback to SMTP raw commands
        if not mail_aspects:
            cmd = [
                "tshark", "-r", pcap_file,
                "-Y", "smtp.req.command == \"MAIL\" or smtp.req.command == \"RCPT\"",
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "smtp.req.command",
                "-e", "smtp.req.parameter"
            ]
            smtp_out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
            
            current_mail = {}
            for line in smtp_out.splitlines():
                parts = line.split('\t')
                if len(parts) >= 5:
                    time_str = parts[0][:23]
                    src_ip = parts[1]
                    dst_ip = parts[2]
                    command = parts[3]
                    param = parts[4]
                    
                    if command == "MAIL" and "FROM:" in param.upper():
                        current_mail = {
                            "time": time_str,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "sender_id": param.split(":")[-1].strip("<> "),
                            "receiver_id": "Unknown",
                            "subject": "N/A (SMTP Protocol Level)"
                        }
                    elif command == "RCPT" and "TO:" in param.upper() and current_mail:
                        current_mail["receiver_id"] = param.split(":")[-1].strip("<> ")
                        
                        src_host = host_info.get(current_mail["src_ip"], {}).get("hostname", current_mail["src_ip"])
                        dst_host = host_info.get(current_mail["dst_ip"], {}).get("hostname", current_mail["dst_ip"])
                        
                        mail_aspects.append({
                            "time": current_mail["time"],
                            "src": f"{src_host} ({current_mail['src_ip']})",
                            "dst": f"{dst_host} ({current_mail['dst_ip']})",
                            "sender_id": current_mail["sender_id"],
                            "receiver_id": current_mail["receiver_id"],
                            "subject": current_mail["subject"]
                        })
                        current_mail = {} # Reset for next transaction
    except Exception as e:
        log(f"Deep email flow extraction failed: {e}", "WARN")

    return mail_aspects

def main():
    parser = argparse.ArgumentParser(description="Email Flow Parser")
    parser.add_argument("--pcap", default="", help="Path to PCAP file")
    parser.add_argument("--report-dir", required=True, help="Directory to save report")
    parser.add_argument("--org-name", required=True, help="Organization name")
    parser.add_argument("--eml", default="", help="Path to EML file for SpamAssassin")
    parser.add_argument("--domain", default="", help="Target domain for DNS posture")
    
    args = parser.parse_args()
    
    # 1. Load Host Discovery Data
    script_dir = os.path.dirname(os.path.abspath(__file__))
    host_csv_path = os.path.abspath(os.path.join(script_dir, "..", "..", "Host-Discovery", args.org_name, "Host-Discovery.csv"))
    
    host_info = {}
    if os.path.exists(host_csv_path):
        log(f"Loading Host Discovery data from: {host_csv_path}", "SUCCESS")
        try:
            with open(host_csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = (row.get("IPAddress") or "").strip()
                    if ip:
                        host_info[ip] = {
                            "hostname": (row.get("HostName") or "").strip(),
                            "mac": (row.get("MAC") or "").strip(),
                            "vendor": (row.get("Vendor") or "").strip(),
                            "device_type": (row.get("DeviceType") or "").strip()
                        }
        except Exception as e:
            log(f"Failed to read Host Discovery CSV: {e}", "WARN")
            
    report_content = []
    report_content.append("==========================================================")
    report_content.append("      FULL 3-PILLAR EMAIL SECURITY & POSTURE REPORT       ")
    report_content.append("==========================================================\n")
    report_content.append(f"Organization: {args.org_name}")
    report_content.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.pcap:
        report_content.append(f"PCAP File: {os.path.basename(args.pcap)}\n")
    
    # Pillar 1
    report_content.append("\n--- Pillar 1: Static Endpoint Content Analysis (SpamAssassin) ---")
    if args.eml:
        sa_output = run_spamassassin(args.eml)
        report_content.append(sa_output)
    else:
        report_content.append("No static .eml file processed for Endpoint analysis.")

    # Pillar 2
    report_content.append("\n--- Pillar 2: Live Network Email Flow & Transfer Aspects ---")
    if args.pcap and os.path.exists(args.pcap):
        mail_aspects = parse_pcap_email_flow(args.pcap, host_info)
        if mail_aspects:
            report_content.append(f"{'Time':<25} {'Source (Host/IP)':<30} {'Dest (Host/IP)':<30} {'Sender Mail ID':<30} {'Receiver Mail ID':<30} {'Subject'}")
            report_content.append("-" * 170)
            for m in mail_aspects:
                time_str = (m['time'][:23]) if len(m['time']) > 23 else m['time']
                src_str = (m['src'][:28] + '..') if len(m['src']) > 30 else m['src']
                dst_str = (m['dst'][:28] + '..') if len(m['dst']) > 30 else m['dst']
                sender = (m['sender_id'][:28] + '..') if len(m['sender_id']) > 30 else m['sender_id']
                receiver = (m['receiver_id'][:28] + '..') if len(m['receiver_id']) > 30 else m['receiver_id']
                subject = m['subject'].replace('\n', ' ').replace('\r', '')
                
                report_content.append(f"{time_str:<25} {src_str:<30} {dst_str:<30} {sender:<30} {receiver:<30} {subject}")
        else:
            report_content.append("No clear deep application-layer Mail Transfers (SMTP MAIL/IMF) detected in PCAP. Traffic might be encrypted (STARTTLS) or not present.")
            
        # Optional: Add raw conversation stats
        try:
            conv = subprocess.check_output(["tshark", "-r", args.pcap, "-q", "-z", "conv,tcp"], text=True, stderr=subprocess.DEVNULL)
            report_content.append("\nRaw TCP Transport Connections (Mail Ports):")
            report_content.append(conv)
        except:
            pass
            
    else:
        report_content.append("No live network email flows captured or valid PCAP provided.")
        
    # Pillar 3
    report_content.append("\n--- Pillar 3: External Domain Security Posture (DNS Logs) ---")
    if args.domain:
        dns_output = run_dns_posture(args.domain)
        report_content.append(dns_output)
    else:
        report_content.append("No external domain investigated.")
        
    report_file = os.path.join(args.report_dir, "email_flow_report.txt")
    with open(report_file, "w") as f:
        f.write("\n".join(report_content) + "\n")
        
    log(f"Final 3-Pillar Report compiled successfully: {report_file}", "SUCCESS")

if __name__ == "__main__":
    main()
