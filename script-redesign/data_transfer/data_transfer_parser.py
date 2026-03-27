import json
import os
import ipaddress
from collections import defaultdict

class VulnerabilityReport:
    def __init__(self):
        self.findings = []
        self._seen_signatures = set()

    def add_finding(self, finding, severity, impact, recommendation, deduplicate_key=None):
        if deduplicate_key:
            if deduplicate_key in self._seen_signatures:
                return
            self._seen_signatures.add(deduplicate_key)
            
        self.findings.append({
            "Finding": finding,
            "Severity": severity,
            "Impact": impact,
            "Recommendation": recommendation
        })

def is_internal_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

def parse_eve_json(eve_path):
    report = VulnerabilityReport()
    
    if not os.path.exists(eve_path):
        return report
        
    # Tracking for Exfiltration (Bandwidth and Traffic Monitoring)
    external_transfers = defaultdict(int)
    
    # State tracking
    seen_http = False
    seen_ftp = False
    seen_smb = False
    seen_tls = False
    
    with open(eve_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
            except:
                continue
                
            event_type = event.get("event_type")
            src_ip = event.get("src_ip", "")
            dest_ip = event.get("dest_ip", "")
            
            # 1. Detection Logic - Suricata Alerts & Custom Rules
            if event_type == "alert":
                alert = event.get("alert", {})
                signature = alert.get("signature", "Unknown Alert")
                severity_id = alert.get("severity", 3)
                
                if severity_id == 1:
                    sev, imp, rec = "Critical", "System compromise or severe data leak", "Investigate immediately, block malicious IPs, and review Suricata logs."
                elif severity_id == 2:
                    sev, imp, rec = "High", "Potential unauthorized access or exploit attempt", "Review network controls and isolate affected endpoint."
                else:
                    sev, imp, rec = "Medium", "Suspicious traffic pattern or policy violation", "Monitor endpoint for further anomalous behavior."
                
                report.add_finding(
                    finding=f"IDS Alert Triggered: {signature}",
                    severity=sev,
                    impact=imp,
                    recommendation=rec,
                    deduplicate_key=f"alert_{signature}"
                )
                
            # 2. Encrypted vs Unencrypted Classification & Auth Mechanisms
            if event_type == "http":
                seen_http = True
                http_data = event.get("http", {})
                hostname = http_data.get("hostname", dest_ip)
                url = http_data.get("url", "/")
                
                report.add_finding(
                    finding=f"Unencrypted HTTP communication detected (Host: {hostname})",
                    severity="High",
                    impact="Data exposure, potential credential theft via sniffing.",
                    recommendation="Enforce HTTPS (TLS 1.2+) and disable cleartext HTTP.",
                    deduplicate_key="unencrypted_http"
                )
                
                if http_data.get("http_method") in ["POST", "PUT"] and "login" in url.lower():
                    report.add_finding(
                        finding=f"Cleartext authentication attempt detected over HTTP (POST {url})",
                        severity="Critical",
                        impact="Credentials sent in cleartext, trivial to intercept.",
                        recommendation="Migrate authentication forms strictly to HTTPS.",
                        deduplicate_key="http_cleartext_auth"
                    )
                    
            if event_type == "ftp":
                seen_ftp = True
                report.add_finding(
                    finding="Unencrypted FTP command channel detected.",
                    severity="High",
                    impact="Cleartext passwords and file structures exposed to network eavesdropping.",
                    recommendation="Migrate to SFTP or FTPS for encrypted file transfer.",
                    deduplicate_key="unencrypted_ftp"
                )
                
            if event_type == "tls":
                seen_tls = True
                
            if event_type == "smb":
                seen_smb = True
                
            # 3. Unauthorized Transfer & File Analysis
            if event_type == "fileinfo":
                file_info = event.get("fileinfo", {})
                filename = file_info.get("filename", "unknown")
                magic = file_info.get("magic", "").lower()
                state = file_info.get("state", "UNKNOWN")
                
                if "executable" in magic or filename.endswith(".exe") or filename.endswith(".sh"):
                    if is_internal_ip(dest_ip):
                        report.add_finding(
                            finding=f"Suspicious executable download over cleartext ({filename})",
                            severity="High",
                            impact="Potential malware payload delivery avoiding encrypted channels.",
                            recommendation="Implement network-level file inspection and block dangerous extensions.",
                            deduplicate_key=f"suspicious_file_{filename}"
                        )
                        
            # 4. Bandwidth and Traffic Monitoring (Exfiltration)
            if event_type == "flow":
                flow = event.get("flow", {})
                bytes_toserver = flow.get("bytes_toserver", 0)
                bytes_toclient = flow.get("bytes_toclient", 0)
                
                # Check if data is leaving the internal network to an external IP
                if is_internal_ip(src_ip) and not is_internal_ip(dest_ip):
                    external_transfers[dest_ip] += bytes_toserver
                elif is_internal_ip(dest_ip) and not is_internal_ip(src_ip):
                    # Data leaving network triggered by external host (e.g. reverse shell / ftp GET)
                    external_transfers[src_ip] += bytes_toclient

    # Post-processing Bandwidth (Threshold > 10MB)
    for ext_ip, bytes_transferred in external_transfers.items():
        if bytes_transferred > 10 * 1024 * 1024:  # 10 MB
            mb_size = bytes_transferred / (1024 * 1024)
            report.add_finding(
                finding=f"Large outboard data transfer ({mb_size:.2f} MB) to unknown external IP {ext_ip}",
                severity="High",
                impact="Potential unauthorized data exfiltration or massive policy violation.",
                recommendation="Investigate the process communicating with this IP and enforce strict egress firewall rules.",
                deduplicate_key=f"large_transfer_{ext_ip}"
            )
            
    # Post-processing Encrypted Summaries
    if seen_tls and not (seen_http or seen_ftp or seen_smb):
        report.add_finding(
            finding="Network Traffic encryption baseline.",
            severity="Low",
            impact="Minimal risk. Traffic is generally encrypted.",
            recommendation="Continue enforcing TLS protocols and monitor for downgrade attacks.",
            deduplicate_key="encrypted_baseline"
        )
        
    return report

def generate_report_text(report):
    if not report.findings:
        return "No significant vulnerabilities or anomalous transfers detected during the assessment window.\n"
        
    lines = []
    lines.append("--- VULNERABILITY ASSESSMENT FINDINGS (RISK-BASED) ---")
    
    # Sort by severity
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    sorted_findings = sorted(report.findings, key=lambda x: severity_order.get(x["Severity"], 5))
    
    for i, item in enumerate(sorted_findings, 1):
        lines.append(f"\n[{i}] Finding: {item['Finding']}")
        lines.append(f"    Risk: {item['Severity']}")
        lines.append(f"    Impact: {item['Impact']}")
        lines.append(f"    Recommendation: {item['Recommendation']}")
        
    return "\n".join(lines) + "\n"
