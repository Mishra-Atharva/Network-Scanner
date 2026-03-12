#!/usr/bin/env python3
import argparse
import re
import sys
import json
import urllib3
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------------
# Router Types
# ------------------------------------------------------------------

TYPE_UNKNOWN = "unknown"
TYPE_GOOGLE_WIFI = "google_wifi"
TYPE_GOOGLE_HOME = "google_home"
TYPE_TRADITIONAL = "traditional"

ROUTER_TYPE_LABELS = {
    TYPE_GOOGLE_WIFI: "Google Wifi / Nest Wifi",
    TYPE_GOOGLE_HOME: "Google Home / Nest Mini / Hub",
    TYPE_TRADITIONAL: "Traditional web-admin router",
    TYPE_UNKNOWN: "Unknown",
}

# ------------------------------------------------------------------
# Regex / Patterns
# ------------------------------------------------------------------

DEVICE_KEYWORDS = re.compile(
    r"attach|connectedDev|client_list|dhcp.?lease|host.?info|lan.?host"
    r"|device.?list|device.?table|station.?list|wireless.?client"
    r"|topolog|mesh.?client|net.?device|arp.?table",
    re.IGNORECASE,
)

JS_URL_PATTERNS = [
    re.compile(r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""fetch\s*\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]"""),
    re.compile(r"""['"]([a-zA-Z0-9_/]+\.(?:php|cgi|asp|lua|json|xml|htm|api)[^'"]*)['"]"""),
    re.compile(r"""url\s*:\s*['"]([^'"]+)['"]"""),
]

# ------------------------------------------------------------------
# Example endpoint lists (trimmed for readability)
# ------------------------------------------------------------------

TRADITIONAL_ENDPOINTS = [
    "php/db/attachedDevTable_data.php",
    "appGet.cgi?hook=get_clientlist()",
    "api/devices",
    "api/clients",
]

GOOGLE_WIFI_ENDPOINTS = [
    {"path": "api/v1/connected-devices", "headers": {"Host": "onhub.here"}},
    {"path": "api/v1/status"},
]

GOOGLE_HOME_ENDPOINTS = [
    {"path": "setup/eureka_info"},
]


# ==================================================================
# Router API Finder Class
# ==================================================================

class RouterApiFinder:

    def __init__(self, host, username=None, password=None, port=None, timeout=10):

        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout

        self.scheme = "http"
        self.netloc = host if port is None else f"{host}:{port}"
        self.base = f"{self.scheme}://{self.netloc}/"

        self.session = self.make_session()

    # --------------------------------------------------------------

    def make_session(self):

        s = requests.Session()

        if self.username and self.password:
            s.auth = (self.username, self.password)

        s.verify = False
        s.timeout = self.timeout

        s.headers.update({
            "User-Agent": "RouterApiFinder/1.0"
        })

        return s

    # --------------------------------------------------------------

    def fetch(self, url, method="GET", **kwargs):

        try:
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)

            if resp.status_code < 400:
                return resp

        except requests.RequestException:
            pass

        return None

    # --------------------------------------------------------------

    def discover_pages(self, max_pages=30):

        html_urls = set()
        js_urls = set()

        to_visit = {self.base}
        visited = set()

        while to_visit and len(visited) < max_pages:

            url = to_visit.pop()

            if url in visited:
                continue

            visited.add(url)

            resp = self.fetch(url)

            if resp is None:
                continue

            ct = resp.headers.get("Content-Type", "")

            if "html" not in ct and "javascript" not in ct:
                continue

            html_urls.add(url)

            soup = BeautifulSoup(resp.text, "html.parser")

            for tag, attr in [("script", "src"), ("a", "href"), ("iframe", "src")]:
                for el in soup.find_all(tag, **{attr: True}):

                    href = el[attr]
                    abs_url = urljoin(url, href)

                    if urlparse(abs_url).netloc == urlparse(self.base).netloc:

                        if href.endswith(".js"):
                            js_urls.add(abs_url)
                        else:
                            to_visit.add(abs_url)

        return html_urls, js_urls

    # --------------------------------------------------------------

    def extract_api_paths(self, urls):

        candidates = set()

        for url in urls:

            resp = self.fetch(url)

            if resp is None:
                continue

            text = resp.text

            for pattern in JS_URL_PATTERNS:

                for match in pattern.findall(text):

                    path = match.strip()

                    abs_url = urljoin(self.base, path)

                    if urlparse(abs_url).netloc == urlparse(self.base).netloc:
                        candidates.add(abs_url)

        return candidates

    # --------------------------------------------------------------

    def detect_router_type(self):

        no_auth = requests.Session()

        base = f"http://{self.host}:{self.port or 80}/"

        resp = self.fetch(urljoin(base, "api/v1/status"))

        if resp:
            try:
                data = resp.json()
                if "system" in data or "software" in data:
                    return TYPE_GOOGLE_WIFI
            except:
                pass

        resp = self.fetch(f"https://{self.host}:8443/setup/eureka_info")

        if resp:
            try:
                data = resp.json()
                if "name" in data:
                    return TYPE_GOOGLE_HOME
            except:
                pass

        return TYPE_TRADITIONAL

    # --------------------------------------------------------------

    def probe_known_endpoints(self):

        alive = set()

        for path in TRADITIONAL_ENDPOINTS:

            url = urljoin(self.base, path)

            resp = self.fetch(url)

            if resp:
                alive.add(url)

        return alive

    # --------------------------------------------------------------

    def looks_like_device_data(self, text):

        indicators = [
            r'"ip"',
            r'"mac"',
            r'"hostname"',
            r'"deviceName"',
            r'"client"',
        ]

        count = 0

        for p in indicators:
            if re.search(p, text, re.IGNORECASE):
                count += 1

        return count >= 2

    # --------------------------------------------------------------

    def rank_candidates(self, candidates):

        results = []

        for url in candidates:

            resp = self.fetch(url)

            if not resp:
                continue

            body = resp.text.strip()

            if not body:
                continue

            score = 0

            if DEVICE_KEYWORDS.search(url):
                score += 3

            if self.looks_like_device_data(body):
                score += 5

            try:
                json.loads(body)
                score += 1
            except:
                pass

            if score > 0:

                results.append({
                    "url": url,
                    "score": score,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "body_preview": body[:300],
                })

        results.sort(key=lambda r: r["score"], reverse=True)

        return results

    # --------------------------------------------------------------

    def scan(self):

        print(f"[*] Target: {self.host}")

        router_type = self.detect_router_type()

        print(f"Detected: {ROUTER_TYPE_LABELS.get(router_type)}")

        if router_type == TYPE_TRADITIONAL and not self.password:
            print("Password required for traditional routers")
            sys.exit(1)

        print("[*] Crawling pages...")

        html_urls, js_urls = self.discover_pages()

        print(f"Found {len(html_urls)} HTML pages")
        print(f"Found {len(js_urls)} JS sources")

        js_candidates = self.extract_api_paths(js_urls | html_urls)

        known = self.probe_known_endpoints()

        candidates = js_candidates | known

        print(f"Ranking {len(candidates)} endpoints")

        return self.rank_candidates(candidates)

    # --------------------------------------------------------------

    def print_results(self, results, as_json=False):

        if not results:
            print("No device API found")
            return

        if as_json:
            print(json.dumps(results, indent=2))
            return

        for i, r in enumerate(results, 1):

            print(f"\n{i}. {r['url']}")
            print(f"Score: {r['score']}")
            print(f"Type: {r['content_type']}")
            print(f"Preview: {r['body_preview'][:120]}")


# ==================================================================
# CLI ENTRY POINT
# ==================================================================

def main():

    parser = argparse.ArgumentParser(
        description="Discover router API endpoint listing connected devices"
    )

    parser.add_argument("host")
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-p", "--password")
    parser.add_argument("--port", type=int)
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    finder = RouterApiFinder(
        host=args.host,
        username=args.username,
        password=args.password,
        port=args.port,
    )

    results = finder.scan()

    finder.print_results(results, args.json)

    if not results:
        sys.exit(1)


if __name__ == "__main__":
    main()