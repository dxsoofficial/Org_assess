import os
import subprocess
import argparse
from pathlib import Path

def run_endpoint_audit(target_ips, admin_user, admin_pass, output_dir="dxso_reports/2_Endpoint_Audit"):
    os.makedirs(output_dir, exist_ok=True)
    print("\n=== PHASE 2: Endpoint Deep Discovery ===")
    
    script_path = os.path.abspath("scripts/audit.ps1")
    if not os.path.exists(script_path):
        print(f"[!] Audit script not found at {script_path}. Please ensure scripts/audit.ps1 exists.")
        return

    for ip in target_ips:
        ip = ip.strip()
        print(f"[*] Auditing endpoint: {ip}")
        # Command to run PsExec and execute the local PowerShell audit across the network
        cmd = f"psexec \\\\{ip} -u {admin_user} -p {admin_pass} powershell -ExecutionPolicy Bypass -File \"{script_path}\""
        print(f"[*] Executing: {cmd}")
        
        # In a real setup, output from the remote script would be saved locally or exported.
        # This wrapper captures stdout depending on network config.
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Parse the combined output to separate Endpoint vs Browser logic
            full_out = result.stdout
            browser_data = ""
            endpoint_data = full_out

            if "@@@ BROWSER_START @@@" in full_out and "@@@ BROWSER_END @@@" in full_out:
                parts = full_out.split("@@@ BROWSER_START @@@")
                endpoint_data = parts[0]
                browser_part = parts[1].split("@@@ BROWSER_END @@@")
                browser_data = browser_part[0].strip()
                endpoint_data += browser_part[1].strip() # Append anything after the end tag

            # Save the Endpoint Audit
            ep_file = f"{output_dir}/{ip}_endpoint_audit.txt"
            with open(ep_file, "w") as f:
                f.write(endpoint_data.strip())
                if result.stderr:
                    f.write(f"\nERRORS:\n{result.stderr}")
            print(f"    [+] Endpoint Audit saved to: {ep_file}")

            # Save the Browser Audit
            if browser_data:
                br_file = f"{output_dir}/{ip}_browser_security.txt"
                with open(br_file, "w") as f:
                    f.write(f"=== BROWSER & INTERNET SECURITY AUDIT for {ip} ===\n\n")
                    f.write(browser_data)
                print(f"    [+] Browser Security Audit saved to: {br_file}")

        except Exception as e:
             print(f"    [!] Error auditing {ip}: {e}")

    print(f"[+] Phase 2 expected results in {output_dir}")

if __name__ == "__main__":
    import getpass
    parser = argparse.ArgumentParser(description="Phase 2: Endpoint Configuration & Software Audit")
    parser.add_argument("--ips", required=True, help="Comma-separated list of target IPs")
    parser.add_argument("-u", "--user", help="Admin username. If omitted, you will be prompted.")
    parser.add_argument("-p", "--password", help="Admin password. If omitted, you will be prompted securely.")
    args = parser.parse_args()
    
    ips = args.ips.split(",")
    user = args.user or input("Enter Admin Username: ")
    password = args.password or getpass.getpass("Enter Admin Password: ")
    
    run_endpoint_audit(ips, user, password)
