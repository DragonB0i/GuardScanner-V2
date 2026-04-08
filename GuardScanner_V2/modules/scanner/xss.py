import requests
from html import escape

class XSSScanner:
    def __init__(self, target_url):
        self.url = target_url
        # Professional payloads that bypass simple filters
        self.payloads = [
            "<script>alert('XSS')</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]
        self.findings = []

    def scan(self):
        print(f"[*] Testing XSS on: {self.url}")
        for payload in self.payloads:
            # Only test if the URL has parameters
            if "?" not in self.url:
                continue
                
            test_url = f"{self.url}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                # Detection: Check if the unescaped payload is in the response body
                if payload in response.text:
                    self.findings.append({
                        "url": test_url,
                        "payload": payload,
                        "evidence": "Payload reflected unescaped in HTML body"
                    })
                    break 
            except Exception:
                continue
        return self.findings
