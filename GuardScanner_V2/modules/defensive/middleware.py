import time
from flask import request, abort

class GuardShield:
    def __init__(self):
        # Dictionary to track malicious attempts: {ip: {"count": 0, "blocked_until": 0}}
        self.threat_log = {}
        self.block_threshold = 5  # Block after 5 suspicious requests
        self.block_duration = 60  # Block for 60 seconds

        # Common attack signatures detected by GuardScanner V2
        self.malicious_signatures = [
            "SELECT", "UNION", "OR 1=1",  # SQLi Patterns
            "etc/passwd", "../", "%2f",   # Path Traversal Patterns
            "<script>", "alert("          # XSS Patterns
        ]

    def check_request(self):
        client_ip = request.remote_addr
        current_time = time.time()

        # 1. Check if the IP is currently blocked
        if client_ip in self.threat_log:
            if current_time < self.threat_log[client_ip].get("blocked_until", 0):
                print(f"[!] Blocked request from: {client_ip}")
                abort(403, description="Your IP has been temporarily blocked due to suspicious activity.")

        # 2. Inspect the request for attack signatures
        is_suspicious = False
        # Check query parameters, form data, and the raw path
        request_data = f"{request.url} {request.get_data(as_text=True)}".upper()
        
        for signature in self.malicious_signatures:
            if signature.upper() in request_data:
                is_suspicious = True
                break

        # 3. Handle suspicious requests
        if is_suspicious:
            print(f"[!] Attack signature detected from: {client_ip}")
            if client_ip not in self.threat_log:
                self.threat_log[client_ip] = {"count": 1, "blocked_until": 0}
            else:
                self.threat_log[client_ip]["count"] += 1

            # Trigger IP block if threshold is reached
            if self.threat_log[client_ip]["count"] >= self.block_threshold:
                self.threat_log[client_ip]["blocked_until"] = current_time + self.block_duration
                print(f"[!!!] IP {client_ip} has been blocked for {self.block_duration}s.")
            
            abort(400, description="Malicious activity detected.")

# Integration instructions for developers:
# In their main Flask app:
# shield = GuardShield()
# @app.before_request
# def limit_malicious_traffic():
#     shield.check_request()
