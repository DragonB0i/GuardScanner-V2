import requests
import time

class CommandInjectionScanner:
    def __init__(self, target_url):
        self.url = target_url
        self.findings = []
        
        # Professional payloads covering Unix/Linux and Windows
        self.payloads = [
            "; echo VULN_CHECK",      # Linux/Unix Reflection
            "& echo VULN_CHECK",      # Windows Reflection
            "| whoami",               # Pipe operator
            "; sleep 5",              # Blind Linux (5s delay)
            "& timeout /t 5",         # Blind Windows (5s delay)
            "|| ping -c 5 127.0.0.1"  # Logic chaining
        ]

    def scan(self):
        print(f"[*] Launching Command Injection probe on: {self.url}")
        
        # Only scan if the URL has parameters (the primary entry point)
        if "?" not in self.url:
            return self.findings

        for payload in self.payloads:
            # Construct the test URL
            test_url = f"{self.url}{payload}"
            
            start_time = time.time()
            try:
                # Use a timeout slightly longer than our sleep payloads
                response = requests.get(test_url, timeout=12)
                end_time = time.time()
                duration = end_time - start_time

                # 1. Detection: Reflection (Direct Output)
                # Looking for our echo or common system user strings
                reflection_indicators = ["VULN_CHECK", "root:", "www-data", "nt authority"]
                if any(ind in response.text for ind in reflection_indicators):
                    self.findings.append({
                        "url": test_url,
                        "payload": payload,
                        "evidence": "Command output reflected directly in HTML."
                    })
                    break # Stop scanning this URL if we found a hit

                # 2. Detection: Time-Based (Blind Injection)
                # If we injected a 'sleep 5' and the response took > 5 seconds
                if "sleep" in payload or "timeout" in payload:
                    if duration >= 5:
                        self.findings.append({
                            "url": test_url,
                            "payload": payload,
                            "evidence": f"Blind injection confirmed via {round(duration, 2)}s response delay."
                        })
                        break

            except requests.exceptions.Timeout:
                # A timeout can sometimes indicate a successful blind injection
                if "sleep" in payload or "timeout" in payload:
                    self.findings.append({
                        "url": test_url,
                        "payload": payload,
                        "evidence": "Server timed out, potentially confirming a successful blind command execution."
                    })
            except Exception as e:
                continue
                
        return self.findings
