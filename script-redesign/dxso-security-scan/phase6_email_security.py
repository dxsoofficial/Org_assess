import os
import subprocess
import argparse
from pathlib import Path

# Phase 6: Email Security Analysis & Brand Protection
# Dependencies: urlcrazy, dnsrecon

def run_email_security(target_domain, output_dir="dxso_reports/6_Email_Security"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n=== PHASE 6: Email Security Analysis & Brand Protection ===")
    
    # 1. Typosquatting & Phishing Clones (URLCrazy)
    print(f"[*] 1/2 Hunting for Typosquatted Phishing Domains ({target_domain}) using URLCrazy...")
    urlcrazy_file = os.path.join(output_dir, "phishing_domains.csv")
    cmd_urlcrazy = f"urlcrazy -f csv -o {urlcrazy_file} {target_domain}"
    try:
        subprocess.run(cmd_urlcrazy, shell=True, timeout=120, stdout=subprocess.DEVNULL)
        print(f"    [+] Saved URL variations and identified phishing clones to {urlcrazy_file}")
    except subprocess.TimeoutExpired:
        print("    [!] URLCrazy timed out. Ensure it is installed and internet connection is stable.")
    except Exception as e:
        print(f"    [!] Error running URLCrazy: {e}")

    # 2. DNS Enumeration & SPF/DKIM/DMARC Hygiene
    print(f"\n[*] 2/2 Validating Email Spoofing Protections via DNSRecon...")
    dnsrecon_file = os.path.join(output_dir, "dns_records_hygiene.txt")
    cmd_dnsrecon = f"dnsrecon -d {target_domain} -t std,txt > {dnsrecon_file}"
    try:
        subprocess.run(cmd_dnsrecon, shell=True, timeout=60, stderr=subprocess.DEVNULL)
        print(f"    [+] DNS & Email Security Hygiene logs saved to {dnsrecon_file}")
    except Exception as e:
        print(f"    [!] Error running DNSRecon: {e}")
        
    # 3. DNS Blacklist (Spam/Compromise) Check
    print(f"\n[*] 3/4 Checking Domain against Global Spam Blacklists (DNSBL)...")
    blacklist_file = os.path.join(output_dir, "spam_blacklist_status.txt")
    blacklists = ["dbl.spamhaus.org", "multi.surbl.org"]
    
    with open(blacklist_file, "w") as f:
        f.write(f"=== SPAM BLACKLIST CHECK FOR {target_domain} ===\n\n")
        import socket
        compromised = False
        for bl in blacklists:
            query = f"{target_domain}.{bl}"
            try:
                res = socket.gethostbyname(query)
                print(f"    [!] WARNING: {target_domain} is BLACKLISTED on {bl} (Returned {res})")
                f.write(f"[!] BLACKLISTED: {bl} (IP: {res})\n")
                compromised = True
            except socket.gaierror: # Domain not found means clean!
                print(f"    [+] Clean on {bl}")
                f.write(f"[+] Clean: {bl}\n")
        
        if compromised:
            print("    [!] ALERT: Domain is currently blacklisted. Email is likely compromised and blocked by spam filters.")
            f.write("\n[!] ALERT: Corporate email infrastructure is actively flagged as a spam source!\n")

    # 4. OSINT / Dark Web Breach Extraction (theHarvester)
    print(f"\n[*] 4/4 Hunting for Leaked Employee Emails on Dark Web/OSINT...")
    harvest_file = os.path.join(output_dir, "darkweb_leak_harvest")
    # theHarvester scrapes search engines, PGP servers, and threat databases
    cmd_harvester = f"theHarvester -d {target_domain} -b all -l 100 -f {harvest_file}.html"
    try:
        print("    [!] Running theHarvester (this takes a couple of minutes)...")
        subprocess.run(cmd_harvester, shell=True, timeout=240, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(f"{harvest_file}.html"):
            print(f"    [+] Leak data saved to {harvest_file}.html")
        else:
            print("    [!] theHarvester completed but no HTML file generated. Check terminal for missing tool.")
    except subprocess.TimeoutExpired:
        print("    [!] theHarvester timed out.")
    except Exception as e:
        print(f"    [!] Error running theHarvester: {e}")
        
    print("\n[+] Phase 6 Complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 6: Email Security Analysis")
    parser.add_argument("-d", "--domain", required=True, help="Target primary domain (e.g. company.com)")
    args = parser.parse_args()
    
    run_email_security(args.domain)
