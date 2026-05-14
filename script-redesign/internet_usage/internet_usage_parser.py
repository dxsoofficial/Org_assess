import sys
import os
import subprocess
import re
import datetime
import ipaddress
import csv
from collections import Counter

def log(msg, level="INFO"):
    print(f"[{level}] {msg}")

def parse_size(val):
    val = val.replace(",", "")
    if "GB" in val:
        return float(val.replace("GB", "").strip()) * 1024 * 1024 * 1024
    elif "MB" in val:
        return float(val.replace("MB", "").strip()) * 1024 * 1024
    elif "kB" in val or "KB" in val:
        return float(val.replace("kB", "").replace("KB", "").strip()) * 1024
    elif "bytes" in val:
        return float(val.replace("bytes", "").strip())
    else:
        return float(val)

def parse_pcap(pcap_file, report_dir, org_name):
    log("Analyzing PCAP...", "INFO")
    ip_data = {}

    # 1. Ingest Host Discovery Data
    script_dir = os.path.dirname(os.path.abspath(__file__))
    host_csv_path = os.path.join(os.path.dirname(script_dir), "Host-Discovery", org_name, "Host-Discovery.csv")
    
    host_info = {}
    if os.path.exists(host_csv_path):
        log(f"Loading enrichment data from: {host_csv_path}", "SUCCESS")
        try:
            with open(host_csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row.get("IPAddress", "").strip()
                    if ip:
                        host_info[ip] = {
                            "hostname": row.get("HostName", "").strip(),
                            "mac": row.get("MAC", "").strip(),
                            "vendor": row.get("Vendor", "").strip(),
                            "device_type": row.get("DeviceType", "").strip()
                        }
        except Exception as e:
            log(f"Failed to read Host Discovery CSV: {e}", "WARN")
    else:
        log(f"Host Discovery CSV not found for '{org_name}'. Device names and vendors will be N/A.", "WARN")

    # 2. Endpoints
    log("Run 1/3: Extracting endpoints and bandwidth metrics...", "INFO")
    endpoints = ""
    try:
        endpoints = subprocess.check_output(
            ["tshark", "-n", "-r", pcap_file, "-q", "-z", "endpoints,ip"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in endpoints.splitlines():
            line = line.strip()
            if not re.match(r"^\d+\.\d+\.\d+\.\d+", line):
                continue
            
            line = line.replace(" GB", "GB").replace(" MB", "MB").replace(" kB", "kB").replace(" KB", "KB").replace(" bytes", "bytes")
            parts = re.split(r"\s+", line)
            
            try:
                ip = parts[0]
                if ip.startswith(("224.", "239.", "255.")) or ip == "0.0.0.0":
                    continue
                ip_data[ip] = {
                    "total_pkts": int(parts[-6].replace(",", "")),
                    "total": parse_size(parts[-5]),
                    "tx_pkts": int(parts[-4].replace(",", "")),
                    "tx": parse_size(parts[-3]),
                    "rx_pkts": int(parts[-2].replace(",", "")),
                    "rx": parse_size(parts[-1]),
                    "conn": 0,
                    "peers": set(),
                    "type": "unknown",
                    "domains": [],
                    "top_domain": "N/A"
                }
            except Exception as e:
                continue
    except Exception as e:
        log(f"Endpoints extraction failed: {e}", "ERROR")

    # 3. Conversations
    log("Run 2/3: Extracting TCP conversations...", "INFO")
    try:
        conv = subprocess.check_output(
            ["tshark", "-n", "-r", pcap_file, "-q", "-z", "conv,tcp"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in conv.splitlines():
            if "<->" not in line:
                continue
            try:
                src = line.split("<->")[0].strip().split(":")[0]
                dst = line.split("<->")[1].strip().split()[0].split(":")[0]
                if src in ip_data:
                    ip_data[src]["conn"] += 1
                    ip_data[src]["peers"].add(dst)
                if dst in ip_data:
                    ip_data[dst]["conn"] += 1
                    ip_data[dst]["peers"].add(src)
            except:
                continue
    except Exception as e:
        log(f"Conversations extraction failed: {e}", "ERROR")

    # 4. DNS / Top Domain Extraction
    log("Run 3/3: Extracting Domains (DNS)...", "INFO")
    try:
        dns_out = subprocess.check_output(
            ["tshark", "-r", pcap_file, "-Y", "dns", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in dns_out.splitlines():
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                ip_src = parts[0].strip()
                domains = parts[1].strip().split(',')
                if ip_src in ip_data:
                    ip_data[ip_src]["domains"].extend([d for d in domains if d])
    except Exception as e:
        log(f"DNS extraction failed: {e}", "WARN")

    for ip, data in ip_data.items():
        if data["domains"]:
            data["top_domain"] = Counter(data["domains"]).most_common(1)[0][0]

    # 5. Classify and correlate
    observations = []
    
    for ip, data in ip_data.items():
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                data["type"] = "internal"
            else:
                data["type"] = "external"
        except ValueError:
            data["type"] = "unknown"

    sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]["total"], reverse=True)

    for ip, data in sorted_ips:
        if data["type"] != "internal":
            continue
            
        mb_total = data["total"] / (1024 * 1024)
        
        # Behavioral Tags
        if data["top_domain"] != "N/A" and mb_total > 1.0:
            data["cor_tag"] = "USER_DEVICE"
            if mb_total > 20: # High usage threshold
                observations.append(f"[INFO] {ip} heavy internet usage ({data['cor_tag']})")
        elif mb_total > 10.0 and data["top_domain"] == "N/A" and len(data["peers"]) <= 5:
            data["cor_tag"] = "IOT/INTERNAL"
            observations.append(f"[INFO] {ip} identified as {data['cor_tag']} device (high traffic, no domains)")
        else:
            data["cor_tag"] = "UNKNOWN"

    # 6. Build Report
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = os.path.join(report_dir, "internet_usage_report.txt")

    with open(report_file, "w") as f:
        f.write("========== INTERNET USAGE REPORT ==========\n")
        f.write(f"Organization: {org_name}\n")
        f.write(f"Date: {now}\n")
        f.write(f"PCAP File: {os.path.basename(pcap_file)}\n\n")

        f.write(f"{'IP Address':<15} {'Device Name':<20} {'Vendor':<15} {'Upload':<10} {'Download':<10} {'Top Domains'}\n")
        f.write("-" * 90 + "\n")

        for ip, data in sorted_ips:
            up_mb = data["tx"] / (1024 * 1024)
            down_mb = data["rx"] / (1024 * 1024)
            
            h_info = host_info.get(ip, {})
            device_name = h_info.get("hostname", "") or "N/A"
            vendor = h_info.get("vendor", "") or "N/A"
            
            # Truncate for clean table formatting
            device_name = (device_name[:17] + '..') if len(device_name) > 19 else device_name
            vendor = (vendor[:12] + '..') if len(vendor) > 14 else vendor
            top_domain = (data['top_domain'][:25] + '..') if len(data['top_domain']) > 27 else data['top_domain']
            
            up_str = f"{up_mb:.1f} MB"
            down_str = f"{down_mb:.1f} MB"

            f.write(f"{ip:<15} {device_name:<20} {vendor:<15} {up_str:<10} {down_str:<10} {top_domain}\n")

        f.write("\nObservations:\n")
        if not observations:
            f.write("[INFO] No significant behavioral anomalies detected.\n")
        for obs in observations:
            f.write(obs + "\n")

    log(f"Report saved: {report_file}", "SUCCESS")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python internet_usage_parser.py <pcap_file> <report_dir> <org_name>")
        sys.exit(1)
    parse_pcap(sys.argv[1], sys.argv[2], sys.argv[3])
