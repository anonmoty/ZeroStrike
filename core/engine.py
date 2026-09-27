# core/engine.py
import requests
import time
from core.colors import C

class Engine:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.s.max_redirects = 5

    def clean_url(self, url):
        url = url.strip().strip("/")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def get(self, url, timeout=10, allow_redirects=True):
        """Safe GET request with retry"""
        for i in range(3):
            try:
                r = self.s.get(url, timeout=timeout, allow_redirects=allow_redirects)
                return r
            except requests.exceptions.Timeout:
                if i < 2: time.sleep(1); continue
                return None
            except requests.exceptions.ConnectionError:
                if i < 2: time.sleep(2); continue
                return None
            except:
                return None
        return None

    def get_headers(self, url):
        """Sirf headers fetch karo"""
        try:
            r = self.s.head(url, timeout=10)
            return r.headers
        except:
            r = self.get(url)
            return r.headers if r else {}

    def check_path(self, base_url, path, timeout=6):
        """Specific path check karo"""
        url = base_url.rstrip("/") + path
        try:
            r = self.s.get(url, timeout=timeout, allow_redirects=False)
            return r
        except:
            return None
