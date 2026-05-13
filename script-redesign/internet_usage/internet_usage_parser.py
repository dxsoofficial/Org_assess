import sys
import os
import subprocess
import re
import datetime

def log(msg, level="INFO"):
    print(f"[{level}] {msg}")

def parse_size(val):
    val = val.replace(",", "")
    if "MB" in val:
        return float(val.replace("MB", "").strip()) * 1024 * 1024
    elif "kB" in val:
        return float(val.replace("kB", "").strip()) * 1024
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
    try:
        endpoints = subprocess.check_output(
            ["tshark", "-n", "-r", pcap_file, "-q", "-z", "endpoints,ip"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in endpoints.splitlines():
            line = line.strip()
            if not re.match(r"^\d+\.\d+\.\d+\.\d+", line):
                continue
            parts = re.split(r"\s+", line)
            try:
                ip = parts[0]
                # Skip noise
                if ip.startswith(("224.", "239.", "255.")) or ip == "0.0.0.0":
                    continue
                # Using negative indexing to avoid GeoIP shifting issues
                ip_data[ip] = {
                    "total": parse_size(parts[-5]),
                    "tx": parse_size(parts[-3]),
                    "rx": parse_size(parts[-1]),
                    "conn": 0,
                    "peers": set()
                }
            except Exception:
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
    findings = []
    sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]["total"], reverse=True)

    # Top talker
    if sorted_ips:
        ip, data = sorted_ips[0]
        if data["total"] > 100 * 1024 * 1024:
            findings.append(f"[HIGH] Top Talker: {ip} (Heavy traffic)")

    # Lateral movement
    for ip, data in ip_data.items():
        if len(data["peers"]) > 10:
            findings.append(f"[HIGH] Possible Lateral Movement: {ip} → {len(data['peers'])} hosts")

    # Internal heavy
    internal = sum(1 for ip in ip_data if ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."))
    external = len(ip_data) - internal

    if internal > external * 3 and internal > 0:
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

        f.write("\n=== TOP SYSTEMS ===\n")
        f.write(f"{'IP':<16} {'MB':<10} {'CONN':<10} {'PEERS'}\n")
        f.write("-" * 50 + "\n")

        for ip, data in sorted_ips[:15]:
            mb = data["total"] / (1024 * 1024)
            f.write(f"{ip:<16} {mb:.1f} MB   {data['conn']:<10} {len(data['peers'])}\n")

    log(f"Report saved: {report_file}", "SUCCESS")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python internet_usage_parser.py <pcap_file> <report_dir> <org_name>")
        sys.exit(1)
    parse_pcap(sys.argv[1], sys.argv[2], sys.argv[3])
