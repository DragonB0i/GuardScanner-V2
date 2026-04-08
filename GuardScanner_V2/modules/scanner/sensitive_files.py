import requests

class SensitiveFileScanner:
    def __init__(self, target_url):
        self.url = target_url.rstrip('/')
        self.files = [
            ".env", ".git/config", "config.php.bak", 
            "phpinfo.php", "backup.zip", "web.config"
        ]
        self.findings = []

    def scan(self):
        print(f"[*] Hunting for Sensitive Files on: {self.url}")
        for file in self.files:
            test_url = f"{self.url}/{file}"
            try:
                response = requests.get(test_url, timeout=5)
                # If we get a 200 OK, the file likely exists and is exposed
                if response.status_code == 200 and len(response.text) > 0:
                    self.findings.append({
                        "url": test_url,
                        "payload": file,
                        "evidence": f"Exposed sensitive file found (Size: {len(response.text)} bytes)"
                    })
            except Exception:
                continue
        return self.findings
