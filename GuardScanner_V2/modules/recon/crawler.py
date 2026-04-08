import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Spider:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited = set()
        self.to_scan = set() # URLs with parameters or unique paths

    def is_valid(self, url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == self.domain

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.base_url
        
        if depth > self.max_depth or url in self.visited:
            return

        self.visited.add(url)
        print(f"[*] Crawling: {url} (Depth: {depth})")

        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Identify if the URL has parameters (prime target for scanners)
            if "?" in url:
                self.to_scan.add(url)

            for link in soup.find_all('a', href=True):
                full_url = urljoin(self.base_url, link['href'])
                
                # Clean URL (remove anchors)
                full_url = full_url.split('#')[0]

                if self.is_valid(full_url):
                    # If it's a new page, crawl deeper
                    if full_url not in self.visited:
                        self.crawl(full_url, depth + 1)
                    
                    # If it's a page with a query param, add to scan list
                    if "?" in full_url:
                        self.to_scan.add(full_url)

        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")

        return list(self.to_scan) if self.to_scan else [self.base_url]
