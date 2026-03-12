#!/usr/bin/env python3
import argparse
import re
import sys
import json
import urllib3
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# Suppress insecure-request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RouterApiFinder:
    # Router type constants
    TYPE_UNKNOWN = "Unknown"
    TYPE_GOOGLE_WIFI = "Google Wifi / Nest Wifi"
    TYPE_GOOGLE_HOME = "Google Home / Nest Mini / Hub"
    TYPE_TRADITIONAL = "Traditional web-admin router"

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

    TRADITIONAL_ENDPOINTS = [
        "php/db/attachedDevTable_data.php", "DEV_device.html", "cgi-bin/DEV_device.htm",
        "appGet.cgi?hook=get_clientlist()", "update_clients.asp", "ajax_status.xml",
        "cgi-bin/luci/admin/network/dhcp_leases", "cgi-bin/luci/api/misystem/devicelist",
        "api/s/default/stat/sta", "status.cgi", "DHCPL.htm"
    ]

    def __init__(self, host, username="admin", password=None, port=None):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.session = self._make_session()
        self.detected_type = self.TYPE_UNKNOWN

    def _make_session(self):
        s = requests.Session()
        if self.username and self.password:
            s.auth = (self.username, self.password)
        s.verify = False
        s.timeout = 10
        s.headers.update({"User-Agent": "RouterApiFinder/2.0"})
        return s

    def _fetch(self, url, method="GET", **kwargs):
        try:
            resp = self.session.request(method, url, **kwargs)
            if resp.status_code < 400:
                return resp
        except requests.RequestException:
            pass
        return None

    def detect_router_model(self):
        """Probes the device to identify the specific router family."""
        # 1. Check Google Wifi
        gwifi_base = f"http://{self.host}:{self.port or 80}/api/v1/status"
        resp = self._fetch(gwifi_base)
        if resp and any(k in resp.text for k in ("software", "system", "wan")):
            self.detected_type = self.TYPE_GOOGLE_WIFI
            return self.detected_type

        # 2. Check Google Home
        ghome_base = f"https://{self.host}:8443/setup/eureka_info"
        resp = self._fetch(ghome_base)
        if resp and any(k in resp.text for k in ("device_info", "build_info")):
            self.detected_type = self.TYPE_GOOGLE_HOME
            return self.detected_type

        # 3. Traditional Probe (Generic)
        self.detected_type = self.TYPE_TRADITIONAL
        return self.detected_type

    def _looks_like_device_data(self, text):
        indicators = [r'"ip"', r'"mac"', r'"hostname"', r'"stations"', r'"connected"']
        count = sum(1 for p in indicators if re.search(p, text, re.IGNORECASE))
        return count >= 2

    def find_apis(self):
        """Orchestrates discovery based on detected type."""
        self.detect_router_model()
        results = []

        if self.detected_type == self.TYPE_GOOGLE_WIFI:
            results = self._probe_google_wifi()
        elif self.detected_type == self.TYPE_GOOGLE_HOME:
            results = self._probe_google_home()
        else:
            results = self._probe_traditional()

        return sorted(results, key=lambda x: x['score'], reverse=True)

    def get_best_match(self):
        """Returns only the single best API URL candidate."""
        results = self.find_apis()
        return results[0]['url'] if results else None

    def _probe_google_wifi(self):
        base = f"http://{self.host}:{self.port or 80}/api/v1/connected-devices"
        resp = self._fetch(base, headers={"Host": "onhub.here"})
        if resp:
            return [{"url": base, "score": 10, "note": "Standard Google Wifi API"}]
        return []

    def _probe_google_home(self):
        base = f"https://{self.host}:8443/setup/eureka_info?params=net,wifi,mesh"
        resp = self._fetch(base)
        if resp:
            return [{"url": base, "score": 8, "note": "Google Home Eureka API"}]
        return []

    def _probe_traditional(self):
        found = []
        base_url = f"http://{self.host}:{self.port or 80}/"
        for path in self.TRADITIONAL_ENDPOINTS:
            url = urljoin(base_url, path)
            resp = self._fetch(url)
            if resp:
                score = 5
                if self.DEVICE_KEYWORDS.search(path): score += 3
                if self._looks_like_device_data(resp.text): score += 5
                found.append({"url": url, "score": score})
        return found

# ---------------------------------------------------------------------------
# CLI Usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Router API Finder")
    parser.add_argument("host", help="Router IP")
    parser.add_argument("-p", "--password", help="Admin password")
    args = parser.parse_args()

    finder = RouterApiFinder(args.host, password=args.password)
    
    print(f"[*] Scanning {args.host}...")
    model = finder.detect_router_model()
    print(f"[*] Identified as: {model}")

    best = finder.get_best_match()
    if best:
        print(f"[+] Best API Match: {best}")
    else:
        print("[-] No valid API endpoint found.")
