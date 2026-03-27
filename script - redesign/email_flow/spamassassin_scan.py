import os
import sys
import subprocess
import argparse

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
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument("--eml-file", required=True, help="Path to raw email file (.eml)")
    
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    run_spamassassin(args.out_dir, args.eml_file)
