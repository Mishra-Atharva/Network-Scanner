#!/usr/bin/env python3
"""
Router API Finder — automatically discovers the API endpoint a router uses
to return the list of connected / attached devices.

Supported router families
-------------------------
- Traditional web-admin routers (Netgear, TP-Link, ASUS, Linksys, D-Link,
  OpenWrt, Ubiquiti, Xiaomi, etc.) — uses Basic Auth + page crawling.
- Google Wifi / Nest Wifi — unauthenticated local REST API on port 80
  (http://<ip>/api/v1/…) with special Host header handling.
- Google Home / Nest Mini / Hub — local API on HTTPS port 8443
  (/setup/eureka_info) requiring a cast-local-authorization-token.

Approach
--------
1. Auto-detect the router type by probing fingerprint endpoints.
2. For Google Wifi/Nest: probe the /api/v1/* local API (no auth required).
3. For traditional routers: authenticate (Basic Auth), crawl the landing
   page, parse JS for AJAX/fetch calls, and probe known endpoints.
4. Score and rank every candidate that returned device-like data.
"""

import argparse
import re
import sys
import json
import urllib3
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Suppress insecure-request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Router type constants
# ---------------------------------------------------------------------------
TYPE_UNKNOWN = "unknown"
TYPE_GOOGLE_WIFI = "google_wifi"       # Google Wifi / Nest Wifi
TYPE_GOOGLE_HOME = "google_home"       # Google Home / Nest Mini / Hub
TYPE_TRADITIONAL = "traditional"       # Netgear, ASUS, TP-Link, etc.

# ---------------------------------------------------------------------------
# Keywords that hint an endpoint is about connected devices
# ---------------------------------------------------------------------------
DEVICE_KEYWORDS = re.compile(
    r"attach|connectedDev|client_list|dhcp.?lease|host.?info|lan.?host"
    r"|device.?list|device.?table|station.?list|wireless.?client"
    r"|topolog|mesh.?client|net.?device|arp.?table",
    re.IGNORECASE,
)

# Patterns to extract URLs / paths from JavaScript source code
JS_URL_PATTERNS = [
    # jQuery $.ajax / $.get / $.post with a string URL
    re.compile(r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*['"]([^'"]+)['"]"""),
    # fetch("url") or fetch('url')
    re.compile(r"""fetch\s*\(\s*['"]([^'"]+)['"]"""),
    # XMLHttpRequest .open("METHOD", "url"
    re.compile(r"""\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]"""),
    # Generic path construction like path = "foo/" + bar + ".php"
    re.compile(r"""['"]([a-zA-Z0-9_/]+\.(?:php|cgi|asp|lua|json|xml|htm|api)[^'"]*)['"]"""),
    # url: "..." inside an object literal (common in $.ajax({url: ...}))
    re.compile(r"""url\s*:\s*['"]([^'"]+)['"]"""),
]

# ---- Traditional router endpoints (require auth) -------------------------
TRADITIONAL_ENDPOINTS = [
    # --- Netgear ---
    "php/db/attachedDevTable_data.php",
    "DEV_device.html",
    "cgi-bin/DEV_device.htm",
    # --- TP-Link (new UI) ---
    "cgi-bin/luci/;stok={stok}/admin/status?form=all",
    "cgi-bin/luci/;stok={stok}/admin/dhcps?form=client",
    "admin/dhcps?form=client",
    # --- TP-Link (old / basic) ---
    "DHCPL.htm",
    "userRpm/AssignedIpAddrListRpm.htm",
    # --- ASUS / Merlin ---
    "appGet.cgi?hook=get_clientlist()",
    "update_clients.asp",
    "ajax_status.xml",
    # --- Linksys (Smart Wi-Fi) ---
    "JNAP/",  # POST with specific actions
    "sysinfo.cgi",
    "Status_Devices.asp",
    # --- OpenWrt / LuCI ---
    "cgi-bin/luci/admin/network/dhcp_leases",
    "cgi-bin/luci/rpc/sys",
    "ubus",  # JSON-RPC
    # --- D-Link ---
    "HNAP1/",
    "getcfg.php",
    # --- Ubiquiti ---
    "api/s/default/stat/sta",
    "status.cgi",
    # --- Xiaomi ---
    "cgi-bin/luci/api/misystem/devicelist",
    "cgi-bin/luci/api/xqnetwork/wifi_connect_devices",
    # --- Generic / misc ---
    "api/devices",
    "api/clients",
    "info.cgi",
    "lan.asp",
    "dhcp_clients.asp",
    "connected_devices_computers.asp",
]

# ---- Google Wifi / Nest Wifi local API (no auth, port 80) ----------------
# These endpoints do NOT require authentication.
# /api/v1/connected-devices needs Host header set to "onhub.here".
GOOGLE_WIFI_ENDPOINTS = [
    # Primary — device / station info
    {"path": "api/v1/connected-devices", "headers": {"Host": "onhub.here"}},
    {"path": "api/v1/status"},
    {"path": "api/v1/status?type=wan"},
    {"path": "api/v1/diagnostic-report"},
    {"path": "api/v1/get-shmac"},
    {"path": "api/v1/wan-configuration"},
    {"path": "api/v1/welcome-mat"},  # OnHub-specific
    {"path": "api/v1/developer-configuration"},
    {"path": "api/v1/get-group-configuration"},
]

# ---- Google Home / Nest Mini / Hub local API (HTTPS port 8443) -----------
# Most endpoints require cast-local-authorization-token since June 2019.
# /setup/eureka_info is one of the few that still works without the token.
GOOGLE_HOME_ENDPOINTS = [
    {"path": "setup/eureka_info", "params": "params=version,name,build_info,device_info,net,wifi,setup,settings,opt_in,opencast,multizone,proxy,night_mode_params,user_eq,room_equalizer,mesh"},
    {"path": "setup/eureka_info", "params": "params=net,wifi,mesh"},
    {"path": "setup/scan_results"},
    {"path": "setup/configured_networks"},
    {"path": "setup/bluetooth/status"},
    {"path": "setup/bluetooth/scan"},
]


def make_session(
    username: str | None = None,
    password: str | None = None,
    timeout: int = 10,
) -> requests.Session:
    """Return a Session pre-configured with optional Basic Auth."""
    s = requests.Session()
    if username and password:
        s.auth = (username, password)
    s.verify = False
    s.timeout = timeout
    s.headers.update({"User-Agent": "RouterApiFinder/1.0"})
    return s


def fetch(session: requests.Session, url: str, method: str = "GET", **kwargs) -> requests.Response | None:
    """Quietly fetch a URL; return None on any error."""
    try:
        resp = session.request(method, url, timeout=session.timeout, **kwargs)
        if resp.status_code < 400:
            return resp
    except requests.RequestException:
        pass
    return None


# ---------------------------------------------------------------------------
# 1. Discover pages and JS sources reachable from the landing page
# ---------------------------------------------------------------------------
def discover_pages(session: requests.Session, base: str, max_pages: int = 30) -> tuple[set[str], set[str]]:
    """Return (html_urls, js_urls) found by crawling from *base*."""
    html_urls: set[str] = set()
    js_urls: set[str] = set()
    to_visit = {base}
    visited: set[str] = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)

        resp = fetch(session, url)
        if resp is None:
            continue

        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct and "javascript" not in ct:
            continue

        html_urls.add(url)
        soup = BeautifulSoup(resp.text, "html.parser")

        # Collect <script src="..."> and <a href="...">
        for tag, attr in [("script", "src"), ("a", "href"), ("iframe", "src")]:
            for el in soup.find_all(tag, **{attr: True}):
                href = el[attr]
                abs_url = urljoin(url, href)
                # Stay on the same host
                if urlparse(abs_url).netloc == urlparse(base).netloc:
                    if href.endswith(".js") or "javascript" in ct:
                        js_urls.add(abs_url)
                    elif href.endswith((".html", ".htm", ".asp", ".php")):
                        to_visit.add(abs_url)

        # Inline <script> blocks — treat them as JS too
        for script in soup.find_all("script", src=False):
            if script.string:
                js_urls.add(url)  # mark the page itself so we parse its inline JS

    return html_urls, js_urls


# ---------------------------------------------------------------------------
# 2. Extract candidate API paths from JavaScript
# ---------------------------------------------------------------------------
def extract_api_paths(session: requests.Session, base: str, urls: set[str]) -> set[str]:
    """Parse JS sources and return absolute candidate URLs."""
    candidates: set[str] = set()

    for url in urls:
        resp = fetch(session, url)
        if resp is None:
            continue
        text = resp.text

        # Check for Netgear-style dynamic path construction:
        #   path = "php/db/" + path + "_data.php"
        #   fetchData('target', 'attachedDev', ...)
        fetch_data_calls = re.findall(
            r"fetchData\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]([^'\"]+)['\"]", text
        )
        for name in fetch_data_calls:
            candidates.add(urljoin(base, f"php/db/{name}_data.php"))

        fetch_table_calls = re.findall(
            r"fetchTableData\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]([^'\"]+)['\"]", text
        )
        for name in fetch_table_calls:
            candidates.add(urljoin(base, f"php/db/{name}_data.php"))

        # Generic URL extraction
        for pattern in JS_URL_PATTERNS:
            for match in pattern.findall(text):
                path = match.strip()
                if path and not path.startswith(("http://", "https://", "//")):
                    abs_url = urljoin(base, path)
                else:
                    abs_url = path
                if urlparse(abs_url).netloc == urlparse(base).netloc:
                    candidates.add(abs_url)

    return candidates


# ---------------------------------------------------------------------------
# 3. Auto-detect router type
# ---------------------------------------------------------------------------
def detect_router_type(host: str, port: int | None = None) -> str:
    """Probe fingerprint endpoints to determine the router family."""
    no_auth = make_session()  # no credentials

    # --- Check for Google Wifi / Nest Wifi (port 80, /api/v1/status) -------
    gwifi_base = f"http://{host}:{port or 80}/"
    resp = fetch(no_auth, urljoin(gwifi_base, "api/v1/status"))
    if resp is not None:
        try:
            data = resp.json()
            # Google Wifi status has keys like "software", "system", "wan"
            if any(k in data for k in ("software", "system", "wan")):
                return TYPE_GOOGLE_WIFI
        except (ValueError, AttributeError):
            pass

    # --- Check for Google Home local API (HTTPS port 8443) -----------------
    ghome_base = f"https://{host}:8443/"
    resp = fetch(no_auth, urljoin(ghome_base, "setup/eureka_info"))
    if resp is not None:
        try:
            data = resp.json()
            if any(k in data for k in ("name", "build_info", "device_info")):
                return TYPE_GOOGLE_HOME
        except (ValueError, AttributeError):
            pass

    return TYPE_TRADITIONAL


# ---------------------------------------------------------------------------
# 4. Probe known endpoints (traditional routers)
# ---------------------------------------------------------------------------
def probe_known_endpoints(session: requests.Session, base: str) -> set[str]:
    """Return the subset of TRADITIONAL_ENDPOINTS that return a valid response."""
    alive: set[str] = set()
    for path in TRADITIONAL_ENDPOINTS:
        url = urljoin(base, path)
        resp = fetch(session, url)
        if resp is not None:
            alive.add(url)
    return alive


# ---------------------------------------------------------------------------
# 5. Probe Google Wifi / Nest Wifi endpoints
# ---------------------------------------------------------------------------
def probe_google_wifi(host: str, port: int | None = None) -> list[dict]:
    """Probe Google Wifi local API endpoints and return scored results."""
    base = f"http://{host}:{port or 80}/"
    session = make_session()  # no auth needed
    results = []

    for ep in GOOGLE_WIFI_ENDPOINTS:
        url = urljoin(base, ep["path"])
        extra_headers = ep.get("headers", {})
        resp = fetch(session, url, headers=extra_headers)
        if resp is None:
            continue

        body = resp.text.strip()
        if not body:
            continue

        score = 0
        # connected-devices is the primary device-list endpoint
        if "connected-devices" in ep["path"]:
            score += 8
        # status contains station/wan info
        elif "status" in ep["path"]:
            score += 4
        # diagnostic-report is huge but contains everything
        elif "diagnostic-report" in ep["path"]:
            score += 3

        if looks_like_device_data(body):
            score += 5
        try:
            json.loads(body)
            score += 1
        except (json.JSONDecodeError, ValueError):
            pass

        if score > 0:
            note = ""
            if extra_headers:
                note = f"  (requires header: {extra_headers})"
            results.append({
                "url": url,
                "score": score,
                "content_type": resp.headers.get("Content-Type", ""),
                "body_preview": body[:300],
                "note": note,
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# 6. Probe Google Home local API (port 8443)
# ---------------------------------------------------------------------------
def probe_google_home(host: str) -> list[dict]:
    """Probe Google Home / Nest Mini / Hub local API endpoints."""
    base = f"https://{host}:8443/"
    session = make_session()  # no basic auth
    results = []

    for ep in GOOGLE_HOME_ENDPOINTS:
        url = urljoin(base, ep["path"])
        if "params" in ep:
            url += "?" + ep["params"]
        resp = fetch(session, url)
        if resp is None:
            continue

        body = resp.text.strip()
        if not body:
            continue

        score = 0
        if "eureka_info" in ep["path"]:
            score += 5
        if "net" in ep.get("params", "") or "wifi" in ep.get("params", ""):
            score += 3
        if looks_like_device_data(body):
            score += 5
        try:
            json.loads(body)
            score += 1
        except (json.JSONDecodeError, ValueError):
            pass

        if score > 0:
            results.append({
                "url": url,
                "score": score,
                "content_type": resp.headers.get("Content-Type", ""),
                "body_preview": body[:300],
                "note": "  (may require cast-local-authorization-token header)",
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# 4. Score & rank candidates
# ---------------------------------------------------------------------------
def looks_like_device_data(text: str) -> bool:
    """Heuristic: does the response body look like a device list?"""
    indicators = [
        # Traditional routers
        r'"ip"', r'"mac"', r'"__mac"', r'"__ip"', r'"hostname"',
        r'"name"', r'"deviceName"', r'"client"', r'"connected"',
        r'"MACAddress"', r'"IPAddress"', r'"HostName"',
        r"<AssociatedDevice>", r"<Host>", r"<MACAddress>",
        # Google Wifi / Nest Wifi / Google Home
        r'"hueBridges"', r'"_hueBridges"', r'"stations"',
        r'"stationState"', r'"ipAddresses"', r'"dhcpHostname"',
        r'"wireless"', r'"wifiState"',
    ]
    count = sum(1 for p in indicators if re.search(p, text, re.IGNORECASE))
    return count >= 2


def rank_candidates(session: requests.Session, candidates: set[str]) -> list[dict]:
    """Probe each candidate and return a sorted list of results."""
    results = []
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        resp = fetch(session, url)
        if resp is None:
            continue

        body = resp.text.strip()
        if not body:
            continue

        score = 0
        # Keyword in URL path
        if DEVICE_KEYWORDS.search(url):
            score += 3
        # Body looks like JSON with device fields
        if looks_like_device_data(body):
            score += 5
        # Response is JSON
        try:
            json.loads(body)
            score += 1
        except (json.JSONDecodeError, ValueError):
            pass

        if score > 0:
            results.append({
                "url": url,
                "score": score,
                "content_type": resp.headers.get("Content-Type", ""),
                "body_preview": body[:300],
                "note": "",
            })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
ROUTER_TYPE_LABELS = {
    TYPE_GOOGLE_WIFI: "Google Wifi / Nest Wifi",
    TYPE_GOOGLE_HOME: "Google Home / Nest Mini / Hub",
    TYPE_TRADITIONAL: "Traditional web-admin router",
    TYPE_UNKNOWN: "Unknown",
}


def find_device_api(
    host: str,
    username: str | None = None,
    password: str | None = None,
    port: int | None = None,
) -> list[dict]:
    print(f"[*] Target: {host}")

    # ---- Step 0: detect router type ------------------------------------
    print("[1] Detecting router type …")
    rtype = detect_router_type(host, port)
    print(f"    Detected: {ROUTER_TYPE_LABELS.get(rtype, rtype)}")

    # ---- Google Wifi / Nest Wifi ---------------------------------------
    if rtype == TYPE_GOOGLE_WIFI:
        print("[2] Probing Google Wifi local API endpoints …")
        results = probe_google_wifi(host, port)
        print(f"    {len(results)} endpoint(s) responded")
        return results

    # ---- Google Home / Nest Mini / Hub ---------------------------------
    if rtype == TYPE_GOOGLE_HOME:
        print("[2] Probing Google Home local API (port 8443) …")
        results = probe_google_home(host)
        print(f"    {len(results)} endpoint(s) responded")
        return results

    # ---- Traditional routers (Netgear, ASUS, TP-Link, etc.) ------------
    if not password:
        print("\n[!] This looks like a traditional router that requires")
        print("    authentication.  Re-run with  -p <password>  (and -u if")
        print("    the username is not 'admin').")
        sys.exit(1)

    scheme = "http"
    netloc = host if port is None else f"{host}:{port}"
    base = f"{scheme}://{netloc}/"
    session = make_session(username, password)

    print("[2] Crawling landing page …")
    html_urls, js_urls = discover_pages(session, base)
    print(f"    Found {len(html_urls)} HTML pages, {len(js_urls)} JS sources")

    print("[3] Extracting API paths from JS …")
    js_candidates = extract_api_paths(session, base, js_urls | html_urls)
    print(f"    Extracted {len(js_candidates)} candidate paths")

    print("[4] Probing well-known endpoints …")
    known_alive = probe_known_endpoints(session, base)
    print(f"    {len(known_alive)} known endpoints responded")

    all_candidates = js_candidates | known_alive

    print(f"[5] Ranking {len(all_candidates)} candidates …")
    results = rank_candidates(session, all_candidates)
    return results


def print_results(results: list[dict], as_json: bool = False) -> None:
    if not results:
        print("\n[!] No device-list API endpoints found.")
        return

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'=' * 70}")
        print(f" Found {len(results)} likely device-list endpoint(s)")
        print(f"{'=' * 70}")
        for i, r in enumerate(results, 1):
            print(f"\n  #{i}  [score {r['score']}]  {r['url']}")
            if r.get("note"):
                print(f"       Note:{r['note']}")
            print(f"       Content-Type: {r['content_type']}")
            preview = r["body_preview"].replace("\n", " ")
            if len(preview) > 120:
                preview = preview[:120] + " …"
            print(f"       Preview: {preview}")
        print()
        print(f"Best match → {results[0]['url']}")


def main():
    parser = argparse.ArgumentParser(
        description="Discover the API URL a router uses to list connected devices.\n"
        "Supports traditional routers, Google Wifi/Nest, and Google Home devices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  # Traditional router (Netgear, ASUS, TP-Link, …)\n"
        "  %(prog)s 192.168.1.1 -p MyPassword\n\n"
        "  # Google Wifi / Nest Wifi (no password needed)\n"
        "  %(prog)s 192.168.86.1\n\n"
        "  # Google Home device on port 8443\n"
        "  %(prog)s 192.168.86.25\n",
    )
    parser.add_argument("host", help="Router IP or hostname (e.g. 192.168.1.1, 192.168.86.1)")
    parser.add_argument("-u", "--username", default="admin", help="Admin username (default: admin)")
    parser.add_argument("-p", "--password", default=None, help="Admin password (not needed for Google Wifi/Nest)")
    parser.add_argument("--port", type=int, default=None, help="Custom port (default: auto-detect)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of a table")
    args = parser.parse_args()

    results = find_device_api(args.host, args.username, args.password, args.port)
    print_results(results, as_json=args.json)

    if not results:
        sys.exit(1)


if __name__ == "__main__":
    main()
