import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class AdvancedRecon:
    def __init__(self, target_url):
        self.url = target_url
        self.results = {
            "tech_stack": [],
            "api_hints": set(),
            "js_logic_hints": set(),
            "cookie_analysis": [],
            "storage_analysis": set(),
            "form_analysis": []
        }

    def analyze(self):
        try:
            resp = requests.get(self.url, timeout=10)
            content_type = resp.headers.get("Content-Type", "")
            body = resp.text

            # --- 1. API / JSON Endpoint Detection ---
            if "application/json" in content_type or self.url.endswith(".json"):
                self.results["api_hints"].add(f"JSON API Endpoint: {self.url}")

            # Swagger / OpenAPI detection
            if "swagger" in self.url.lower() or "openapi" in body.lower():
                self.results["api_hints"].add(f"Swagger/OpenAPI discovered: {self.url}")

            # --- 2. Cookie Analysis ---
            for cookie in resp.cookies:
                self.results["cookie_analysis"].append({
                    "name": cookie.name,
                    "httpOnly": cookie._rest.get("HttpOnly", False),
                    "secure": cookie.secure
                })

            # --- 3. HTML Logic Reverse Engineering ---
            if "text/html" in content_type:
                soup = BeautifulSoup(body, "html.parser")

                # Forms (Attack Surface Discovery)
                for form in soup.find_all("form"):
                    inputs = []
                    for inp in form.find_all("input"):
                        if inp.get("name"):
                            inputs.append(inp.get("name"))

                    self.results["form_analysis"].append({
                        "action": form.get("action"),
                        "method": form.get("method", "GET").upper(),
                        "inputs": inputs
                    })

                # --- 4. JavaScript Logic Reverse Engineering ---
                scripts = soup.find_all("script")

                for script in scripts:
                    js = script.string
                    if not js:
                        continue

                    # Detect API calls inside JS
                    api_patterns = re.findall(r"(fetch|axios|XMLHttpRequest)\s*\(\s*['\"](.*?)['\"]", js)
                    for _, endpoint in api_patterns:
                        self.results["js_logic_hints"].add(endpoint)
                        self.results["api_hints"].add(f"JS API Call: {endpoint}")

                    # Detect tokens / auth flows
                    if re.search(r"(token|auth|session|jwt)", js, re.I):
                        self.results["js_logic_hints"].add("Auth/Token logic detected in JS")

                # --- 5. External JS files ---
                for script in soup.find_all("script", src=True):
                    js_url = urljoin(self.url, script["src"])
                    self.results["js_logic_hints"].add(f"External JS Loaded: {js_url}")

            return self.results

        except Exception as e:
            return {
                "error": str(e),
                "tech_stack": [],
                "api_hints": [],
                "js_logic_hints": [],
                "cookie_analysis": [],
                "storage_analysis": [],
                "form_analysis": []
            }
