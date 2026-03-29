import os
import ipaddress
import json

# Minimal simulated IP ranges for demonstration
KNOWN_IP_RANGES = {
    "Google/YouTube": ["8.8.8.8", "8.8.4.4", "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19"],
    "Facebook/Instagram": ["157.240.0.0/16", "31.13.24.0/21", "69.171.224.0/19", "185.60.216.0/22"],
    "Cloudflare (CDN)": ["104.16.0.0/12", "172.64.0.0/13", "1.1.1.1", "1.0.0.1"],
    "Amazon AWS": ["52.0.0.0/10", "3.0.0.0/9", "54.0.0.0/8"],
    "Microsoft/Azure": ["20.0.0.0/10", "40.74.0.0/15", "52.145.0.0/16"],
}

class ZeekParser:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.conn_log = os.path.join(log_dir, "conn.log")
        self.dns_log = os.path.join(log_dir, "dns.log")
        self.ssl_log = os.path.join(log_dir, "ssl.log")
        self.http_log = os.path.join(log_dir, "http.log")

    def _parse_tsv_log(self, filepath):
        if not os.path.exists(filepath):
            return

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            headers = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Zeek logs start with # describing format
                if line.startswith('#'):
                    if line.startswith('#fields'):
                        headers = line.split('\t')[1:]
                    continue
                
                # Yield parsed rows as dictionary
                if headers:
                    fields = line.split('\t')
                    if len(fields) == len(headers):
                        yield dict(zip(headers, fields))

    def parse_conn(self):
        return self._parse_tsv_log(self.conn_log)

    def parse_dns(self):
        return self._parse_tsv_log(self.dns_log)

    def parse_ssl(self):
        return self._parse_tsv_log(self.ssl_log)

    def parse_http(self):
        return self._parse_tsv_log(self.http_log)

def is_internal_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def infer_application_from_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback:
            return "Internal Network"
            
        for service, ranges in KNOWN_IP_RANGES.items():
            for r in ranges:
                if '/' in r:
                    network = ipaddress.ip_network(r, strict=False)
                    if ip_obj in network:
                        return service
                else:
                    if ip_str == r:
                        return service
    except ValueError:
        pass
    return None
