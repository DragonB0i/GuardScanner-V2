import requests

class OpenRedirectScanner:
    def __init__(self, target_url):
        self.url = target_url
        self.payloads = [
            "https://google.com",
            "//google.com",
            "/%09/google.com",
            "/redirect?url=https://google.com"
        ]
        self.findings = []

    def scan(self):
        print(f"[*] Testing Open Redirects on: {self.url}")
        for payload in self.payloads:
            # Append payload to common redirect parameters
            params = ["url", "redirect", "next", "return"]
            for p in params:
                test_url = f"{self.url}?{p}={payload}"
                try:
                    # We set allow_redirects=False to catch the 301/302 header
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    if response.status_code in [301, 302]:
                        location = response.headers.get("Location", "")
                        if "google.com" in location:
                            self.findings.append({
                                "url": test_url,
                                "payload": payload,
                                "evidence": f"Redirected to: {location}"
                            })
                            break
                except Exception:
                    continue
        return self.findings
