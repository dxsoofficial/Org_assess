import os
import sys
import subprocess
import argparse
from datetime import datetime

def setup_output_dir(scan_type="out_scan"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_out_dir = os.path.abspath(os.path.join(script_dir, "output", "Individual_Scan", scan_type))
    os.makedirs(base_out_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(base_out_dir, f"results_{timestamp}")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

ASSESSMENT_FOCUS = [
    "Spam Detection",
    "Header Analysis",
    "Phishing Detection"
]

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

def run_spamassassin(out_dir, eml_file):
    if not eml_file:
        return
        
    log(f"Starting Static Content Analysis using SpamAssassin on '{eml_file}'...", "INFO")
    log(f"Assessment Focus: {', '.join(ASSESSMENT_FOCUS)}", "INFO")
    
    sa_out = os.path.join(out_dir, "spamassassin_report.txt")
    
    try:
        if not os.path.exists(eml_file):
            log(f"Email file '{eml_file}' not found. Cannot analyze.", "ERROR")
            return
            
        with open(eml_file, "r") as infile, open(sa_out, "w") as outfile:
            subprocess.run(["spamassassin", "-t"], stdin=infile, stdout=outfile, stderr=subprocess.STDOUT)
            
        log(f"SpamAssassin analysis complete. Component text report generated.", "SUCCESS")
    except FileNotFoundError:
        log("SpamAssassin is not installed! (Install via 'sudo apt install spamassassin')", "ERROR")
    except Exception as e:
        log(f"Error executing SpamAssassin: {e}", "ERROR")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run SpamAssassin static analysis.")
    parser.add_argument("--out-dir", required=False, help="Output directory (auto-generated if not provided)")
    parser.add_argument("--eml-file", required=True, help="Path to raw email file (.eml)")
    
    args = parser.parse_args()
    if not args.out_dir:
        args.out_dir = setup_output_dir(scan_type="out_spamassassin")
    else:
        os.makedirs(args.out_dir, exist_ok=True)
        
    run_spamassassin(args.out_dir, args.eml_file)
