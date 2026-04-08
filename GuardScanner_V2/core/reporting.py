import json
import os
from datetime import datetime

class ReportEngine:
    def __init__(self, raw_data_path="reports/final_report.json"):
        self.raw_data_path = raw_data_path
        self.output_path = "reports/intelligent_report.json"

    def process(self, mode="targeted"):
        try:
            if not os.path.exists(self.raw_data_path):
                return None
            with open(self.raw_data_path, 'r') as f:
                raw = json.load(f)
        except Exception as e:
            print(f"Reporting Error: {e}")
            return None

        # Initialize report structure
        report_data = {
            "mode": mode, 
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"), 
            "recon_summary": "No reconnaissance data was captured for this session.",
            "findings": []
        }
        
        # 1. Capture Recon Details (Phase 1)
        recon = raw.get('recon', {})
        if recon:
            # Ensure we are joining lists into readable strings for the PDF
            tech = ", ".join(recon.get("tech_stack", ["Detection Obscured"]))
            risks = ", ".join(recon.get("security_risk", ["No infrastructure risks identified"]))
            report_data["recon_summary"] = f"Target Environment: {tech}. Infrastructure Risks: {risks}."

        # 2. Security Mapping (Key names must match exactly)
        mapping = {
            "SQLi": {"severity": "Critical", "score": 9.8, "owasp": "A03:2021-Injection"},
            "XSS": {"severity": "High", "score": 6.1, "owasp": "A03:2021-Injection"},
            "CommandInjection": {"severity": "Critical", "score": 10.0, "owasp": "A03:2021-Injection"},
            "PathTraversal": {"severity": "High", "score": 7.5, "owasp": "A01:2021-Broken Access Control"},
            "OpenRedirect": {"severity": "Medium", "score": 4.7, "owasp": "A01:2021-Broken Access Control"}
        }

        # 3. Aggregate Findings (Phase 2)
        for vuln_key, findings in raw.items():
            if vuln_key in mapping and isinstance(findings, list):
                for item in findings:
                    meta = mapping[vuln_key]
                    report_data["findings"].append({
                        "type": vuln_key, 
                        "url": item.get("url", "N/A"), 
                        "payload": item.get("payload", "N/A"),
                        "severity": meta["severity"], 
                        "cvss": meta["score"], 
                        "owasp": meta["owasp"]
                    })

        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        with open(self.output_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        return report_data
