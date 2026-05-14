import sys
import os
import subprocess
import re
import datetime
import ipaddress

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

    # ---------------------------
    # Endpoints
    # ---------------------------
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
            
            # Normalize spaces before unit sizes so re.split doesn't split the number from its unit
            line = line.replace(" GB", "GB").replace(" MB", "MB").replace(" kB", "kB").replace(" KB", "KB").replace(" bytes", "bytes")
            
            parts = re.split(r"\s+", line)
            try:
                ip = parts[0]
                # Skip noise
                if ip.startswith(("224.", "239.", "255.")) or ip == "0.0.0.0":
                    continue
                # Using negative indexing to avoid GeoIP shifting issues
                ip_data[ip] = {
                    "total_pkts": int(parts[-6].replace(",", "")),
                    "total": parse_size(parts[-5]),
                    "tx_pkts": int(parts[-4].replace(",", "")),
                    "tx": parse_size(parts[-3]),
                    "rx_pkts": int(parts[-2].replace(",", "")),
                    "rx": parse_size(parts[-1]),
                    "conn": 0,
                    "peers": set(),
                    "type": "unknown"
                }
            except Exception as e:
                log(f"Row parse error on line '{line}': {e}", "WARN")
                continue
    except Exception as e:
        log(f"Endpoints extraction failed: {e}", "ERROR")

    # ---------------------------
    # Conversations
    # ---------------------------
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

    # ---------------------------
    # Findings
    # ---------------------------
    if not ip_data:
        log("DEBUG: ip_data is empty! Dumping raw tshark output:", "WARN")
        log(endpoints, "WARN")
        
    findings = []

    # Classify each IP using behavior and ipaddress module
    for ip, data in ip_data.items():
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                # IoT heuristic: > 50MB and <= 3 peers
                if data["total"] > 50 * 1024 * 1024 and len(data["peers"]) <= 3:
                    data["type"] = "iot_suspect"
                    findings.append(f"[HIGH] IoT Device Detected: {ip}")
                else:
                    data["type"] = "internal"
            else:
                data["type"] = "external"
        except ValueError:
            data["type"] = "unknown"

    sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]["total"], reverse=True)

    # Top talker
    if sorted_ips:
        ip, data = sorted_ips[0]
        if data["total"] > 100 * 1024 * 1024:
            findings.append(f"[HIGH] Top Talker: {ip} (Heavy traffic)")

    # Lateral movement
    for ip, data in ip_data.items():
        if len(data["peers"]) > 10 and data["type"] in ["internal", "iot_suspect"]:
            findings.append(f"[MEDIUM] High lateral communication: {ip} → {len(data['peers'])} hosts")

    # Dynamic internal ratio
    internal_count = sum(1 for data in ip_data.values() if data["type"] in ["internal", "iot_suspect"])
    external_count = sum(1 for data in ip_data.values() if data["type"] == "external")

    if internal_count > external_count * 3 and internal_count > 0:
        findings.append("[MEDIUM] Traffic mostly internal")

    findings.append("[INFO] DNS visibility low (encrypted/internal traffic likely)")

    # ---------------------------
    # Report
    # ---------------------------
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = os.path.join(report_dir, "internet_usage_report.txt")

    with open(report_file, "w") as f:
        f.write("=========================================\n")
        f.write("     INTERNET USAGE MONITORING REPORT\n")
        f.write("=========================================\n\n")
        f.write(f"Organization: {org_name}\n")
        f.write(f"Date: {now}\n")
        f.write(f"PCAP File: {os.path.basename(pcap_file)}\n\n")

        f.write("=== FINDINGS ===\n")
        for item in findings:
            f.write(item + "\n")

        f.write("\n=== ALL SYSTEMS (Sorted by Volume) ===\n")
        f.write(f"{'IP':<16} {'TYPE':<13} {'TOTAL MB':<10} {'TX MB':<10} {'RX MB':<10} {'CONN':<6} {'PEERS'}\n")
        f.write("-" * 75 + "\n")

        for ip, data in sorted_ips:
            tot_mb = data["total"] / (1024 * 1024)
            tx_mb = data["tx"] / (1024 * 1024)
            rx_mb = data["rx"] / (1024 * 1024)
            f.write(f"{ip:<16} {data['type']:<13} {tot_mb:<10.1f} {tx_mb:<10.1f} {rx_mb:<10.1f} {data['conn']:<6} {len(data['peers'])}\n")

    log(f"Report saved: {report_file}", "SUCCESS")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python internet_usage_parser.py <pcap_file> <report_dir> <org_name>")
        sys.exit(1)
    parse_pcap(sys.argv[1], sys.argv[2], sys.argv[3])
