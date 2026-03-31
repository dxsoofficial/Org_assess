import sys
import os
import socket
from collections import Counter

def get_local_ip():
    """Attempt to dynamically retrieve the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def format_bytes(b):
    """Format bytes nicely with B, KB, or MB."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    else:
        return f"{b / (1024 * 1024):.1f} MB"

def parse_zeek_logs(log_dir, report_dir):
    print("\n[INFO] Starting Zeek Internet Usage Analysis...")
    own_ip = get_local_ip()
    if own_ip:
        print(f"[INFO] Discovered system IP: {own_ip} (Will be ignored in output)")
    else:
        print("[WARN] Could not discover own IP locally. Run may include scanner's traffic.")
        
    ip_data = {}
    
    conn_log = os.path.join(log_dir, "conn.log")
    dns_log = os.path.join(log_dir, "dns.log")
    
    # 1. Parse conn.log for Bytes & Connections
    if os.path.exists(conn_log):
        print("[INFO] Run 1/2: Extracting connections and bandwidth metrics from conn.log...")
        try:
            with open(conn_log, "r") as f:
                idx_orig = -1
                idx_resp = -1
                idx_ob = -1
                idx_rb = -1
                
                for line in f:
                    if line.startswith("#fields"):
                        headers = line.strip("\r\n").split("\t")
                        if "id.orig_h" in headers: idx_orig = headers.index("id.orig_h")
                        if "id.resp_h" in headers: idx_resp = headers.index("id.resp_h")
                        if "orig_bytes" in headers: idx_ob = headers.index("orig_bytes")
                        if "resp_bytes" in headers: idx_rb = headers.index("resp_bytes")
                        continue
                        
                    if line.startswith("#"):
                        continue
                        
                    parts = line.strip("\r\n").split("\t")
                    if idx_orig != -1 and len(parts) > max(idx_orig, idx_ob, idx_rb, idx_resp):
                        orig_h = parts[idx_orig]
                        resp_h = parts[idx_resp]
                        
                        try:
                            ob = int(parts[idx_ob]) if idx_ob != -1 and parts[idx_ob] != "-" else 0
                        except ValueError:
                            ob = 0
                            
                        try:
                            rb = int(parts[idx_rb]) if idx_rb != -1 and parts[idx_rb] != "-" else 0
                        except ValueError:
                            rb = 0
                            
                        # Handle origin host
                        if orig_h not in ip_data:
                            ip_data[orig_h] = {"tx": 0, "rx": 0, "total": 0, "conn": 0, "domains": [], "top_domain": "N/A"}
                        ip_data[orig_h]['tx'] += ob
                        ip_data[orig_h]['rx'] += rb
                        ip_data[orig_h]['total'] += (ob + rb)
                        ip_data[orig_h]['conn'] += 1
                        
                        # Handle responsive host
                        if resp_h not in ip_data:
                            ip_data[resp_h] = {"tx": 0, "rx": 0, "total": 0, "conn": 0, "domains": [], "top_domain": "N/A"}
                        ip_data[resp_h]['tx'] += rb
                        ip_data[resp_h]['rx'] += ob
                        ip_data[resp_h]['total'] += (ob + rb)
                        ip_data[resp_h]['conn'] += 1
                        
        except Exception as e:
            print(f"[ERROR] Failed plotting conn.log: {e}")
    else:
        print("[WARN] conn.log not found. Ensure Zeek captured actual traffic.")

    # 2. Parse dns.log for Domains
    if os.path.exists(dns_log):
        print("[INFO] Run 2/2: Extracting DNS lookups from dns.log...")
        try:
            with open(dns_log, "r") as f:
                idx_orig = -1
                idx_q = -1
                
                for line in f:
                    if line.startswith("#fields"):
                        headers = line.strip("\r\n").split("\t")
                        if "id.orig_h" in headers: idx_orig = headers.index("id.orig_h")
                        if "query" in headers: idx_q = headers.index("query")
                        continue
                        
                    if line.startswith("#"):
                        continue
                        
                    parts = line.strip("\r\n").split("\t")
                    if idx_orig != -1 and idx_q != -1 and len(parts) > max(idx_orig, idx_q):
                        orig_h = parts[idx_orig]
                        query = parts[idx_q]
                        
                        if orig_h in ip_data and query and query != "-":
                            ip_data[orig_h]["domains"].append(query)
                            
        except Exception as e:
            print(f"[ERROR] Failed parsing dns.log: {e}")
    else:
        print("[WARN] dns.log not found. No DNS queries observed in this session.")

    # 3. Synthesize top domains per IP
    for ip, data in ip_data.items():
        if data["domains"]:
            top_domain = Counter(data["domains"]).most_common(1)[0][0]
            data["top_domain"] = top_domain

    # Create final output report
    report_file_path = os.path.join(report_dir, "internet_usage_report.txt")
    
    header = f"{'IP':<16} {'BYTES (TX / RX)':<25} {'CONNECTIONS':<15} {'TOP DOMAIN'}\n"
    header += "-" * 75 + "\n"
    
    lines = []
    # Sort by total bytes descending
    sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]['total'], reverse=True)
    
    for ip, data in sorted_ips:
        if ip == own_ip:
            continue
        # Skip completely empty metrics if any populated natively
        if data['total'] == 0 and data['conn'] == 0:
            continue
            
        tx_rx_str = f"{format_bytes(data['tx'])} / {format_bytes(data['rx'])}"
        row = f"{ip:<16} {tx_rx_str:<25} {data['conn']:<15} {data['top_domain']}\n"
        lines.append(row)

    output_text = header + "".join(lines)
    
    print("\n" + "="*75)
    print("FINAL INTERNET USAGE OUTPUT (ZEEK EDITION)")
    print("="*75)
    print(output_text)
    
    try:
        with open(report_file_path, "w") as f:
            f.write(output_text)
        print(f"[SUCCESS] Report saved to: {os.path.abspath(report_file_path)}")
    except IOError as e:
        print(f"[ERROR] Could not write report to {report_file_path}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python zeek_internet_usage_parser.py <log_dir> <report_dir>")
        sys.exit(1)
        
    log_arg = sys.argv[1]
    report_arg = sys.argv[2]
    
    if not os.path.exists(log_arg):
        print(f"[ERROR] Log directory not found: {log_arg}")
        sys.exit(1)
        
    if not os.path.isdir(report_arg):
        print(f"[ERROR] Report directory not found: {report_arg}")
        sys.exit(1)
        
    parse_zeek_logs(log_arg, report_arg)
