import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime
import json
from zeek_parser import ZeekParser, is_internal_ip, infer_application_from_ip

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

def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024.0:
            return f"{b:.2f} {unit}"
        b /= 1024.0
    return f"{b:.2f} TB"

def generate_report(log_dir, out_dir):
    parser = ZeekParser(log_dir)
    log("Parsing Zeek Logs... This may take a moment for large files.", "INFO")

    # --- Metrics ---
    total_connections = 0
    unique_devices = set()
    total_bandwidth = 0
    
    # Per IP bandwidth: IP -> {"up": 0, "down": 0, "total": 0}
    ip_bandwidth = defaultdict(lambda: {"up": 0, "down": 0, "total": 0})
    
    # Usage Time Analysis: Hour -> count
    active_hours = defaultdict(int)
    
    # Connections per host: IP -> count
    conn_counts = defaultdict(int)
    
    # Top Destinations: IP -> count
    dest_counts = defaultdict(int)

    # Domains & Apps: identifier -> count
    domain_counts = defaultdict(int)

    # Suspicious Activity
    suspicious_high_bw = []
    suspicious_rapid_conns = []

    # 1. Parse CONN.LOG
    conn_generator = parser.parse_conn()
    if conn_generator:
        log("Analyzing conn.log...", "INFO")
        for row in conn_generator:
            total_connections += 1
            
            orig_h = row.get("id.orig_h", "")
            resp_h = row.get("id.resp_h", "")
            
            if orig_h: unique_devices.add(orig_h)
            if resp_h: unique_devices.add(resp_h)
                
            orig_bytes = row.get("orig_bytes", "-")
            resp_bytes = row.get("resp_bytes", "-")
            
            orig_b = int(orig_bytes) if orig_bytes.isdigit() else 0
            resp_b = int(resp_bytes) if resp_bytes.isdigit() else 0
            
            connection_bw = orig_b + resp_b
            total_bandwidth += connection_bw
            
            # Bandwidth tracking for Orig
            ip_bandwidth[orig_h]["up"] += orig_b
            ip_bandwidth[orig_h]["down"] += resp_b
            ip_bandwidth[orig_h]["total"] += connection_bw
            
            # Connection counts
            conn_counts[orig_h] += 1
            if not is_internal_ip(resp_h):
                dest_counts[resp_h] += 1
                
            # Time Analysis
            ts = row.get("ts", "")
            if ts:
                try:
                    dt = datetime.fromtimestamp(float(ts))
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    active_hours[hour_key] += 1
                except ValueError:
                    pass

    # 2. Parse DNS.LOG
    dns_generator = parser.parse_dns()
    if dns_generator:
        log("Analyzing dns.log for domain extraction...", "INFO")
        for row in dns_generator:
            query = row.get("query", "-")
            if query != "-" and query:
                domain_counts[query] += 1

    # 3. Parse SSL.LOG
    ssl_generator = parser.parse_ssl()
    if ssl_generator:
        log("Analyzing ssl.log for server names...", "INFO")
        for row in ssl_generator:
            server_name = row.get("server_name", "-")
            if server_name != "-" and server_name:
                domain_counts[server_name] += 1
                
    # 4. Infer Apps from IP Space if needed
    log("Inferring applications from IP connections...", "INFO")
    for dest_ip, count in dest_counts.items():
        app = infer_application_from_ip(dest_ip)
        if app and app != "Unknown External Service":
            # Add weight based on connection count to application usage
            domain_counts[f"{app} (Inferred from IP {dest_ip})"] += count

    # --- Aggregate and Format Findings ---
    
    # Top BW
    top_bw = sorted(ip_bandwidth.items(), key=lambda x: x[1]['total'], reverse=True)[:5]
    
    # Top Domains
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Peak Hours
    peak_hours = sorted(active_hours.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Anomalies
    for ip, bw in ip_bandwidth.items():
        if bw['total'] > 1 * 1024 * 1024 * 1024:  # > 1GB
            suspicious_high_bw.append((ip, bw['total']))
            
    for ip, count in conn_counts.items():
        if count > 10000: # Arbitrary high connection threshold
            suspicious_rapid_conns.append((ip, count))

    # --- Write Report ---
    report_path = os.path.join(out_dir, "network_usage_report.txt")
    
    try:
        with open(report_path, "w", encoding='utf-8') as f:
            f.write("=== Network Usage Report ===\n\n")
            
            f.write("--- Summary ---\n")
            f.write(f"Total Unique Devices: {len(unique_devices)}\n")
            f.write(f"Total Connections: {total_connections}\n")
            f.write(f"Total Bandwidth Usage: {format_bytes(total_bandwidth)}\n\n")
            
            f.write("--- Top Bandwidth Consumers ---\n")
            if top_bw:
                for ip, data in top_bw:
                    f.write(f"IP: {ip}\n")
                    f.write(f"  Total: {format_bytes(data['total'])} | Up: {format_bytes(data['up'])} | Down: {format_bytes(data['down'])}\n")
            else:
                f.write("No bandwidth data collected.\n")
            f.write("\n")
            
            f.write("--- Application / Website Usage (Top 10) ---\n")
            if top_domains:
                for idx, (domain, count) in enumerate(top_domains, 1):
                    f.write(f"{idx}. {domain} ({count} connections/queries)\n")
            else:
                f.write("No application or domain data extracted.\n")
            f.write("\n")
            
            f.write("--- Usage Time Analysis ---\n")
            f.write("Peak Usage Hours:\n")
            if peak_hours:
                for hr, count in peak_hours:
                    f.write(f"  {hr}: {count} connections\n")
            else:
                f.write("No precise timestamp data found.\n")
            f.write("\n")
            
            f.write("--- Suspicious / Anomalous Activity ---\n")
            found_anomaly = False
            if suspicious_high_bw:
                found_anomaly = True
                f.write("[!] Unusually High Bandwidth Usage:\n")
                for ip, bw in suspicious_high_bw:
                    f.write(f"    - {ip} transacted {format_bytes(bw)}\n")
            
            if suspicious_rapid_conns:
                found_anomaly = True
                f.write("[!] Excessive Connections:\n")
                for ip, count in suspicious_rapid_conns:
                    f.write(f"    - {ip} initiated {count} distinct connections.\n")
                    
            if not found_anomaly:
                f.write("No significant anomalies detected based on standard thresholds.\n")
            f.write("\n")
            
            f.write("--- Recommendations ---\n")
            f.write("1. Enforce strict egress rules for unusual external IP communication.\n")
            f.write("2. Monitor high bandwidth consumers to ensure compliance with acceptable use policies.\n")
            f.write("3. Review connected domains to block potential malicious CDNs or ad-servers.\n")
            
        log(f"Report successfully compiled and saved to: {report_path}", "SUCCESS")
        
    except Exception as e:
        log(f"Failed to write report: {e}", "ERROR")

    # Optional JSON Dump
    json_path = os.path.join(out_dir, "network_usage.json")
    try:
        json_data = {
            "Total_Connections": total_connections,
            "Total_Devices": len(unique_devices),
            "Total_Bandwidth_Bytes": total_bandwidth,
            "Top_Bandwidth": {ip: data for ip, data in top_bw},
            "Top_Domains": {dom: count for dom, count in top_domains},
            "Peak_Hours": {hr: count for hr, count in peak_hours}
        }
        with open(json_path, 'w', encoding='utf-8') as jf:
            json.dump(json_data, jf, indent=4)
        log(f"Raw report data written to: {json_path}", "SUCCESS")
    except Exception as e:
        log(f"Failed to write JSON: {e}", "WARN")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Zeek Network Usage Report.")
    parser.add_argument("--log-dir", required=True, help="Directory containing standard Zeek logs (conn.log, dns.log, etc.)")
    parser.add_argument("--out-dir", required=True, help="Directory to save the finished reports")
    args = parser.parse_args()
    
    os.makedirs(args.out_dir, exist_ok=True)
    generate_report(args.log_dir, args.out_dir)
