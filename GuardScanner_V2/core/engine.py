from modules.recon.fingerprint import Fingerprinter
from modules.recon.advanced_recon import AdvancedRecon
from modules.recon.crawler import Spider
from modules.scanner.path_traversal import PathTraversalScanner
from modules.scanner.cmd_injection import CommandInjectionScanner
from modules.scanner.open_redirect import OpenRedirectScanner
from modules.scanner.sensitive_files import SensitiveFileScanner
from modules.scanner.xss import XSSScanner
from modules.scanner.sqli import SQLiScanner
from core.reporting import ReportEngine
import json
import os

def run_full_analysis(target_url):
    """
    Orchestrates the complete security audit: Recon -> Crawl -> Scan -> Report.
    """
    results = {
        'recon': {},
        'SQLi': [],
        'XSS': [],
        'PathTraversal': [],
        'CommandInjection': [],
        'OpenRedirect': [],
        'SensitiveFiles': []
    }

    # Phase 1: Advanced Reverse Engineering
    print("[*] Phase 1: Launching Black-Box Reverse Engineering...")
    basic_data = Fingerprinter(target_url).analyze()
    adv_data = AdvancedRecon(target_url).analyze()
    
    # Professional Merge
    results['recon'] = {**adv_data, **basic_data}
    # Ensure tech_stack is a list for JSON compatibility
    results['recon']["tech_stack"] = list(set(basic_data.get("tech_stack", []) + list(adv_data.get("tech_stack", []))))

    print(f"  [+] Infrastructure Identified: {', '.join(results['recon']['tech_stack'])}")

    # Phase 2: Deep Crawling
    print("[*] Phase 2: Deep Crawling Target Endpoints...")
    spider = Spider(target_url, max_depth=1) 
    endpoints = spider.crawl()
    print(f"[+] Found {len(endpoints)} unique endpoints for deep analysis.")

    # Phase 3: Multi-Vector Vulnerability Scanning
    print("[*] Phase 3: Multi-Vector Vulnerability Scanning...")
    for url in endpoints:
        print(f"--- Analyzing Endpoint: {url} ---")
        results['SQLi'].extend(SQLiScanner(url).scan())
        results['XSS'].extend(XSSScanner(url).scan())
        results['PathTraversal'].extend(PathTraversalScanner(url).scan())
        results['CommandInjection'].extend(CommandInjectionScanner(url).scan())
        results['OpenRedirect'].extend(OpenRedirectScanner(url).scan())
    
    results['SensitiveFiles'] = SensitiveFileScanner(target_url).scan()

    # Phase 4: Finalizing Audit & Sanitization
    print("[*] Phase 4: Finalizing Audit & Generating Professional Report...")
    
    # JSON Sanitization: Convert any remaining sets to lists
    sanitized_results = {}
    for key, value in results.items():
        if isinstance(value, dict):
            sanitized_results[key] = {
                k: list(v) if isinstance(v, (set, list)) else v 
                for k, v in value.items()
            }
        elif isinstance(value, set):
            sanitized_results[key] = list(value)
        else:
            sanitized_results[key] = value

    os.makedirs("reports", exist_ok=True)
    with open("reports/final_report.json", "w") as f:
        json.dump(sanitized_results, f, indent=4)
    
    re = ReportEngine()
    re.process(mode="full")

    return sanitized_results

def run_full_recon(target_url):
    basic = Fingerprinter(target_url).analyze()
    advanced = AdvancedRecon(target_url).analyze()
    final_recon = {**advanced, **basic}
    # Convert sets to list for UI/JSON compatibility
    final_recon["tech_stack"] = list(set(basic.get("tech_stack", []) + list(advanced.get("tech_stack", []))))
    return final_recon
