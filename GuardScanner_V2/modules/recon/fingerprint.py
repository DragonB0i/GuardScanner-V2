import requests

class Fingerprinter:
    def __init__(self, target_url):
        self.url = target_url

    def analyze(self):
        results = {
            "tech_stack": [],
            "security_risk": []
        }

        try:
            r = requests.get(self.url, timeout=10)
            headers = r.headers

            if 'Server' in headers:
                results["tech_stack"].append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                results["tech_stack"].append(f"Backend: {headers['X-Powered-By']}")

            required = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']
            for h in required:
                if h not in headers:
                    results["security_risk"].append(f"Missing Header: {h}")

        except Exception as e:
            print("[Fingerprint Error]", e)

        return results

