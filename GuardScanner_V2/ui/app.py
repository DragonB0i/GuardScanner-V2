from flask import Flask, render_template, request, jsonify, send_file
import os
import json

# Absolute base directory for stable file handling
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Core and Module Imports
from core.engine import run_full_analysis
from modules.recon.crawler import Spider
from modules.recon.advanced_recon import AdvancedRecon
from modules.recon.fingerprint import Fingerprinter
from modules.scanner.sqli import SQLiScanner
from modules.scanner.xss import XSSScanner
from modules.scanner.cmd_injection import CommandInjectionScanner
from modules.scanner.path_traversal import PathTraversalScanner
from modules.scanner.open_redirect import OpenRedirectScanner
from core.reporting import ReportEngine
from reports.pdf_report import generate_pdf

app = Flask(__name__)
# Configure Flask to look for templates in the correct directory
app.template_folder = os.path.join(os.path.dirname(__file__), 'templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('url')
    mode = data.get('mode')
    results = {}

    try:
        # --- PHASE A: Recursive Logic Reconnaissance ---
        if mode == "modeRecon":
            print(f"[*] Starting Deep Logic Recon for: {target}")
            spider = Spider(target, max_depth=1)
            endpoints = spider.crawl()

            agg = {
                "tech_stack": set(),
                "api_hints": set(),
                "js_logic_hints": set(),
                "cookie_analysis": [],
                "storage_analysis": set(),
                "form_analysis": [],
                "security_risk": set()
            }

            for url in endpoints:
                # Black-Box logic discovery on every discovered page
                adv = AdvancedRecon(url).analyze()

                # Deduplicate complex objects (Cookies/Forms) by unique identifiers
                for cookie in adv.get("cookie_analysis", []):
                    if cookie["name"] not in [c["name"] for c in agg["cookie_analysis"]]:
                        agg["cookie_analysis"].append(cookie)

                for form in adv.get("form_analysis", []):
                    if form["action"] not in [f["action"] for f in agg["form_analysis"]]:
                        agg["form_analysis"].append(form)

                for key in ["tech_stack", "api_hints", "js_logic_hints", "storage_analysis", "security_risk"]:
                    agg[key].update(adv.get(key, []))

            # Merge with raw infrastructure fingerprint
            infra = Fingerprinter(target).analyze()

            results = {
                "tech_stack": list(agg["tech_stack"]) + infra.get("tech_stack", []),
                "api_hints": list(agg["api_hints"]),
                "js_logic_hints": list(agg["js_logic_hints"]),
                "cookie_analysis": agg["cookie_analysis"],
                "storage_analysis": list(agg["storage_analysis"]),
                "form_analysis": agg["form_analysis"],
                "security_risk": list(agg["security_risk"]) + infra.get("security_risk", [])
            }
            return jsonify(results)

        # --- PHASE B: Targeted Attack Modules ---
        targeted_map = {
            "modeSQLi": (SQLiScanner, "SQLi"),
            "modeXSS": (XSSScanner, "XSS"),
            "modeCMD": (CommandInjectionScanner, "CommandInjection"),
            "modePath": (PathTraversalScanner, "PathTraversal"),  # Key sync with reporting.py
            "modeRedirect": (OpenRedirectScanner, "OpenRedirect")
        }

        if mode in targeted_map:
            scanner_cls, label = targeted_map[mode]
            print(f"[*] Launching module: {label}")
            
            # MANDATORY: Deep Crawl to find attack surface
            spider = Spider(target, max_depth=1)
            endpoints = spider.crawl()

            # FIX: Ensure recon data is captured so Phase 1 is not empty in the PDF
            results['recon'] = Fingerprinter(target).analyze()
            results[label] = [] # Initialize findings list
            
            for url in endpoints:
                findings = scanner_cls(url).scan()
                if findings:
                    results[label].extend(findings)

            # Process findings into intelligent_report.json and build PDF
            save_and_process(results, f"{label} Targeted Audit")
            return jsonify(results)

        # --- PHASE C: Full deep audit suite ---
        elif mode == "modeFull":
            print(f"[*] Launching Full Deep Audit for: {target}")
            results = run_full_analysis(target)
            generate_pdf("Full Security Audit")
            return jsonify(results)

    except Exception as e:
        print(f"[!] Critical Error in {mode}: {str(e)}")
        return jsonify({"error": str(e)}), 500

def save_and_process(results, label):
    """Bridges raw results to the intelligent PDF engine"""
    os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)
    raw_path = os.path.join(BASE_DIR, "reports", "final_report.json")
    with open(raw_path, "w") as f:
        json.dump(results, f, indent=4)

    # Process and map vulnerabilities to OWASP categories
    re = ReportEngine(raw_data_path=raw_path)
    re.process(mode="targeted")
    generate_pdf(label)

@app.route('/download-latest')
def download():
    """Fetches the latest generated PDF pointer"""
    try:
        with open(os.path.join(BASE_DIR, "reports", "latest_file.txt"), "r") as f:
            rel_path = f.read().strip()
        abs_path = os.path.abspath(os.path.join(BASE_DIR, rel_path))
        if os.path.exists(abs_path):
            return send_file(abs_path, as_attachment=True)
        return "Report file not found.", 404
    except Exception as e:
        return f"Download error: {str(e)}", 404

if __name__ == '__main__':
    # Running on port 5000 as configured in the project
    app.run(debug=True, port=5000)
