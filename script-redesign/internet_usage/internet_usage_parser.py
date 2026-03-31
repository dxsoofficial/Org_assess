import sys
import os
import subprocess
import socket
from collections import Counter

def get_local_ip():
    """Attempt to dynamically retrieve the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connect() for UDP doesn't send packets
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

def parse_pcap(pcap_file, report_dir):
    print("\n[INFO] Starting Internet Usage Analysis...")
    own_ip = get_local_ip()
    if own_ip:
        print(f"[INFO] Discovered system IP: {own_ip} (Will be ignored in output)")
    else:
        print("[WARN] Could not discover own IP locally. Run may include scanner's traffic.")

    ip_data = {}

    # 1. Endpoints Parsing (Bytes Transmitted / Received)
    print("[INFO] Run 1/3: Extracting endpoints and bandwidth metrics...")
    try:
        # Note: Added -n to prevent IP hostname resolution which breaks standard column offsets
        endpoints_out = subprocess.check_output(
            ["tshark", "-n", "-r", pcap_file, "-q", "-z", "endpoints,ip"], 
            text=True, stderr=subprocess.DEVNULL
        )
        for line in endpoints_out.splitlines():
            line = line.strip()
            # Skip noise lines, empty spaces, and table headers
            if not line or line.startswith("===") or line.startswith("IPv4") or line.startswith("Filter:") or line.startswith("|"):
                continue
                
            parts = line.split()
            # Example payload: 192.168.1.52  4  528  2  264  2  264
            # We enforce length >= 7 to ensure it contains tx rx elements. Check if it's a valid IPv4
            if len(parts) >= 7 and parts[0].count('.') == 3:
                ip_addr = parts[0]
                if ip_addr == own_ip:
                    continue
                    
                try:
                    total_bytes = int(parts[2])
                    tx_bytes = int(parts[4])
                    rx_bytes = int(parts[6])
                except ValueError:
                    continue
                    
                ip_data[ip_addr] = {
                    "total": total_bytes,
                    "tx": tx_bytes,
                    "rx": rx_bytes,
                    "conn": 0,
                    "domains": [],
                    "top_domain": "N/A"
                }
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Endpoints extraction failed: {e}")
    except Exception as e:
        print(f"[ERROR] Exception in endpoints analysis: {e}")

    # 2. Conversations parsing (Connections)
    print("[INFO] Run 2/3: Extracting TCP conversations...")
    try:
        conv_out = subprocess.check_output(
            ["tshark", "-n", "-r", pcap_file, "-q", "-z", "conv,tcp"], 
            text=True, stderr=subprocess.DEVNULL
        )
        for line in conv_out.splitlines():
            if "<->" in line:
                # Example: 192.168.1.52:54321    <-> 8.8.8.8:443      10  1000  20  2000  30  3000   0.000  1.22
                parts = line.split("<->")
                if len(parts) < 2:
                    continue
                
                # Clean source part, drop port via ':'
                src_part = parts[0].strip()
                if ':' in src_part:
                    src_ip = src_part.split(":")[0]
                else:
                    src_ip = src_part
                    
                # Clean dest part, isolate the first block of text from left, drop port via ':'
                dst_part = parts[1].strip().split()[0]
                if ':' in dst_part:
                    dst_ip = dst_part.split(":")[0]
                else:
                    dst_ip = dst_part
                
                if src_ip in ip_data:
                    ip_data[src_ip]["conn"] += 1
                if dst_ip in ip_data:
                    ip_data[dst_ip]["conn"] += 1
                    
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Conversations extraction failed: {e}")
    except Exception as e:
        print(f"[ERROR] Exception in conversations analysis: {e}")

    # 3. DNS parsing (Top Domain)
    print("[INFO] Run 3/3: Extracting DNS lookups...")
    try:
        # User defined argument payload: -Y "dns" -T fields -e ip.src -e dns.qry.name
        dns_out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-Y", "dns", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"], 
            text=True, stderr=subprocess.DEVNULL
        )
        for line in dns_out.splitlines():
            line = line.strip()
            if not line: continue
            
            parts = line.split('\t')
            if len(parts) >= 2:
                ip_src = parts[0].strip()
                if ip_src in ip_data:
                    # Some packets contain multiple DNS questions comma-separated
                    domains = parts[1].strip().split(',')
                    # Filter empty domains
                    domains = [d for d in domains if d]
                    ip_data[ip_src]["domains"].extend(domains)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] DNS lookups extraction failed: {e}")
    except Exception as e:
        print(f"[ERROR] Exception in DNS analysis: {e}")

    # 4. Synthesize top domains per IP
    for ip, data in ip_data.items():
        if data["domains"]:
            # most_common(1) returns [('domain.com', 5)]
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
        tx_rx_str = f"{format_bytes(data['tx'])} / {format_bytes(data['rx'])}"
        row = f"{ip:<16} {tx_rx_str:<25} {data['conn']:<15} {data['top_domain']}\n"
        lines.append(row)

    output_text = header + "".join(lines)
    
    print("\n" + "="*75)
    print("FINAL INTERNET USAGE OUTPUT")
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
        print("Usage: python internet_usage_parser.py <pcap_file> <report_dir>")
        sys.exit(1)
        
    pcap_arg = sys.argv[1]
    report_arg = sys.argv[2]
    
    if not os.path.exists(pcap_arg):
        print(f"[ERROR] PCAP file not found: {pcap_arg}")
        sys.exit(1)
        
    if not os.path.isdir(report_arg):
        print(f"[ERROR] Report directory not found: {report_arg}")
        sys.exit(1)
        
    parse_pcap(pcap_arg, report_arg)
