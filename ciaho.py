#!/usr/bin/env python3
"""
CIAhO – Cookie Impact Analyzer
===============================
Enter a website address – the tool will fetch everything needed
and compare network traffic after accepting and rejecting cookies.

Usage:
    python ciaho.py bbc.com
    python ciaho.py https://example.com
"""

import sys
import os
import json
import time
import re
import socket
import signal
import subprocess
import atexit
import zipfile
import tempfile
from urllib.parse import urlparse
from collections import defaultdict, Counter
from datetime import datetime

# ─────────────────────────────────────────────
#  Auto-install missing Python packages
# ─────────────────────────────────────────────
REQUIRED_PACKAGES = {
    "selenium": "selenium>=4.15.0",
    "browsermobproxy": "browsermob-proxy>=0.8.0",
    "bs4": "beautifulsoup4>=4.12.0",
    "lxml": "lxml>=4.9.0",
    "matplotlib": "matplotlib>=3.7.0",
    "webdriver_manager": "webdriver-manager>=4.0.0",
    "requests": "requests>=2.31.0",
    "reportlab": "reportlab>=4.0.0",
}

def _ensure_packages():
    missing = []
    for module, pip_name in REQUIRED_PACKAGES.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[*] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing
        )
        print("[+] Packages installed.\n")

_ensure_packages()

# ─────────────────────────────────────────────
#  Auto-download browsermob-proxy if missing
# ─────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BROWSERMOB_PATH = os.path.join(_SCRIPT_DIR, "browsermob-proxy", "bin", "browsermob-proxy")

def _ensure_bmp():
    if os.path.exists(BROWSERMOB_PATH):
        return
    import requests as _req
    BMP_VERSION = "2.1.4"
    BMP_URL = (
        f"https://github.com/lightbody/browsermob-proxy/releases/download/"
        f"browsermob-proxy-{BMP_VERSION}/"
        f"browsermob-proxy-{BMP_VERSION}-bin.zip"
    )
    zip_path = os.path.join(_SCRIPT_DIR, f"browsermob-proxy-{BMP_VERSION}-bin.zip")
    print(f"[*] Pobieram browsermob-proxy {BMP_VERSION} …")
    try:
        with _req.get(BMP_URL, stream=True, timeout=120) as r:
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            downloaded = 0
            with open(zip_path, "wb") as fh:
                for chunk in r.iter_content(65536):
                    fh.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 // total
                        print(f"\r    {pct}% ({downloaded // 1024} KB)", end="", flush=True)
        print()
        print("[*] Extracting …")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(_SCRIPT_DIR)
        extracted = os.path.join(_SCRIPT_DIR, f"browsermob-proxy-{BMP_VERSION}")
        target = os.path.join(_SCRIPT_DIR, "browsermob-proxy")
        if os.path.exists(extracted):
            os.rename(extracted, target)
        os.chmod(BROWSERMOB_PATH, 0o755)
        os.remove(zip_path)
        print("[+] browsermob-proxy ready.\n")
    except Exception as exc:
        print(f"\n[ERROR] Failed to download browsermob-proxy: {exc}")
        print("  Download manually from:")
        print(f"  {BMP_URL}")
        sys.exit(1)

# ─────────────────────────────────────────────
#  Check Java
# ─────────────────────────────────────────────
def _check_java():
    if subprocess.run(["which", "java"], capture_output=True).returncode != 0:
        print("[ERROR] Java is not installed. browsermob-proxy requires Java 8+.")
        print("  Install: sudo apt install openjdk-11-jre")
        sys.exit(1)

# ─────────────────────────────────────────────
#  Browser detection (default system browser)
# ─────────────────────────────────────────────

# .desktop entry keyword → (browser_type, binary candidates in order)
_DESKTOP_MAP = [
    # Chrome / Chromium
    ("google-chrome-stable", "chrome", ["google-chrome-stable", "google-chrome"]),
    ("google-chrome",        "chrome", ["google-chrome-stable", "google-chrome"]),
    ("chromium_chromium",    "chrome", ["/snap/bin/chromium", "chromium", "chromium-browser"]),
    ("chromium-browser",     "chrome", ["chromium-browser", "chromium"]),
    ("chromium",             "chrome", ["chromium", "chromium-browser"]),
    # Edge
    ("microsoft-edge-stable", "edge", ["microsoft-edge-stable", "microsoft-edge"]),
    ("microsoft-edge",        "edge", ["microsoft-edge-stable", "microsoft-edge"]),
    # Firefox family
    ("firefox-esr",   "firefox", ["firefox-esr", "firefox"]),
    ("librewolf",     "firefox", ["librewolf"]),
    ("zen-browser",   "firefox", ["zen-browser", "firefox"]),
    ("firefox",       "firefox", ["firefox"]),
]

_FALLBACK_CHROME  = ["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome",
                     "google-chrome-stable", "google-chrome",
                     "/usr/bin/chromium", "chromium", "chromium-browser"]
_FALLBACK_FIREFOX = ["firefox", "/usr/bin/firefox", "firefox-esr"]
_FALLBACK_EDGE    = ["microsoft-edge-stable", "microsoft-edge"]

def _resolve_binary(candidates: list) -> str | None:
    for c in candidates:
        r = subprocess.run(["which", c], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
        if os.path.isfile(c):
            return c
    return None

def _get_default_browser_desktop() -> str:
    """Return the .desktop file name (without .desktop) for the default browser."""
    # 1. xdg-settings
    try:
        out = subprocess.run(
            ["xdg-settings", "get", "default-web-browser"],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if out:
            return out.replace(".desktop", "").lower()
    except Exception:
        pass
    # 2. $BROWSER env var
    env_b = os.environ.get("BROWSER", "")
    if env_b:
        return os.path.basename(env_b).lower()
    # 3. update-alternatives
    try:
        out = subprocess.run(
            ["update-alternatives", "--display", "x-www-browser"],
            capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            if "currently" in line.lower() or "best link" in line.lower():
                m = re.search(r"/(\S+)$", line)
                if m:
                    return os.path.basename(m.group(1)).lower()
    except Exception:
        pass
    return ""

def _is_shell_script(path: str) -> bool:
    """Return True if path is a shell script (not an ELF binary)."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic[:2] == b"#!"
    except Exception:
        return False

def _resolve_real_firefox() -> str | None:
    """
    Return a usable Firefox binary path for geckodriver.
    Snap wrapper scripts are transparently replaced with the snap ELF binary
    or with the snap launcher path that geckodriver can use.
    """
    # Prefer non-snap real binary
    for candidate in ["/usr/bin/firefox-esr", "firefox-esr"]:
        r = subprocess.run(["which", candidate], capture_output=True, text=True)
        p = r.stdout.strip() if r.returncode == 0 else candidate
        if os.path.isfile(p) and not _is_shell_script(p):
            return p

    # Check snap Firefox ELF binary
    snap_elf = "/snap/firefox/current/usr/lib/firefox/firefox"
    if os.path.isfile(snap_elf):
        return snap_elf

    # Fall back to /snap/bin/firefox (snap runner that geckodriver can call)
    r = subprocess.run(["which", "firefox"], capture_output=True, text=True)
    p = r.stdout.strip()
    if p:
        return p
    return None


def _detect_default_browser() -> tuple:
    """
    Returns (browser_type, binary_path).
    browser_type: "chrome" | "firefox" | "edge"
    """
    desktop = _get_default_browser_desktop()
    print(f"[*] Default system browser: {desktop or '(not detected)'}")

    # Match against known .desktop entries (substring match)
    for key, btype, candidates in _DESKTOP_MAP:
        if key in desktop or desktop.startswith(key):
            if btype == "firefox":
                binary = _resolve_real_firefox()
            else:
                binary = _resolve_binary(candidates)
            if binary:
                print(f"[+] Using {btype.upper()}: {binary}")
                return btype, binary

    # Keyword fallbacks
    if any(k in desktop for k in ("chrome", "chromium")):
        b = _resolve_binary(_FALLBACK_CHROME)
        if b:
            print(f"[+] Using Chrome/Chromium: {b}")
            return "chrome", b
    if any(k in desktop for k in ("firefox", "mozilla", "librewolf", "zen")):
        b = _resolve_real_firefox()
        if b:
            print(f"[+] Using Firefox: {b}")
            return "firefox", b
    if "edge" in desktop:
        b = _resolve_binary(_FALLBACK_EDGE)
        if b:
            print(f"[+] Using Edge: {b}")
            return "edge", b

    # Nothing matched – scan what's installed
    print("[*] No default browser detected – scanning installed browsers…")
    for btype, fallbacks in (("chrome", _FALLBACK_CHROME),
                              ("firefox", _FALLBACK_FIREFOX),
                              ("edge", _FALLBACK_EDGE)):
            if btype == "firefox":
                b = _resolve_real_firefox()
            else:
                b = _resolve_binary(fallbacks)
            if b:
                print(f"[+] Found {btype.upper()}: {b}")
                return btype, b

    print("[ERROR] No supported browser found (Chrome, Chromium, Firefox, Edge).")
    print("  Install one of them and restart.")
    sys.exit(1)

# ─────────────────────────────────────────────
#  Imports (after auto-install)
# ─────────────────────────────────────────────
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.common.by import By

try:
    from webdriver_manager.chrome import ChromeDriverManager
    from webdriver_manager.firefox import GeckoDriverManager
    from webdriver_manager.microsoft import EdgeChromiumDriverManager
    HAS_WDM = True
except ImportError:
    HAS_WDM = False

from browsermobproxy import Server
from bs4 import BeautifulSoup
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────

# ── Disconnect.me tracking-protection list ───────────────────────────────────
_DISCONNECT_URL = (
    "https://raw.githubusercontent.com/disconnectme/"
    "disconnect-tracking-protection/master/services.json"
)
_DISCONNECT_CACHE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".disconnect_cache.json"
)
_CACHE_MAX_AGE_DAYS = 7

# Disconnect.me category → our internal category
_DISCONNECT_CAT_MAP: dict[str, str] = {
    "Advertising":            "advertising",
    "Analytics":              "analytics",
    "Social":                 "social_media",
    "Content":                "cdn_infrastructure",
    "FingerprintingInvasive": "advertising",
    "FingerprintingGeneral":  "analytics",
    "Email":                  "advertising",
}

# ── Hard-coded fallback (always merged in) ────────────────────────────────────
_HARDCODED_CATEGORIES: dict[str, list[str]] = {
    "advertising": [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "advertising.com", "adserver.com", "adnxs.com", "rubiconproject.com",
        "pubmatic.com", "openx.net", "smartadserver.com", "criteo.com",
        "taboola.com", "outbrain.com", "revcontent.com", "sharethrough.com",
        "teads.tv", "moatads.com", "amazon-adsystem.com", "media.net",
        "bidswitch.net", "casalemedia.com", "appnexus.com", "adform.net",
        "adroll.com", "33across.com", "indexexchange.com", "tradedesk.com",
        "thetradedesk.com", "triplelift.com", "sovrn.com", "spotxchange.com",
        "yieldmo.com", "lijit.com", "undertone.com", "conversantmedia.com",
        "mathtag.com", "contextweb.com", "adhigh.net", "adbrn.com",
        "onetag.com", "synacor.com", "sizmek.com", "yieldlove.com",
        "prebid.org", "ogury.com", "quantcast.com",
        # Marketing automation / CRM
        "salesmanago.com", "salesmanago.pl",
        # Audience / tagger platforms
        "opecloud.com", "tagger.opecloud.com",
        # Brand measurement (loads on consent)
        "brandmetrics.com", "collector.brandmetrics.com",
        # Bid- and data-exchange
        "adquery.io", "bidder.adquery.io",
        # ID syncing
        "id5-sync.com", "first-id.fr", "rlcdn.com", "connectad.io",
    ],
    "analytics": [
        "google-analytics.com", "googletagmanager.com", "analytics.google.com",
        "hotjar.com", "mixpanel.com", "segment.com", "amplitude.com",
        "heap.io", "kissmetrics.com", "chartbeat.com", "parsely.com",
        "quantserve.com", "comscore.com", "nielsen.com", "scorecardresearch.com",
        "newrelic.com", "dynatrace.com", "pingdom.com", "statcounter.com",
        "woopra.com", "clicky.com", "crazyegg.com", "fullstory.com",
        "logrocket.com", "mouseflow.com", "contentsquare.com", "optimizely.com",
        "vwo.com", "ab.tasty.com", "abtasty.com",
        # Gemius – CEE audience measurement (Comscore equivalent)
        "gemius.pl", "gemius.com", "gemius.net", "hit.gemius.pl",
        # Userreport – audience survey/analytics
        "userreport.com",
        # Piano – content metering / analytics
        "piano.io",
    ],
    "social_media": [
        "facebook.com", "facebook.net", "fbcdn.net", "twitter.com", "twimg.com",
        "instagram.com", "linkedin.com", "licdn.com", "pinterest.com",
        "snapchat.com", "tiktok.com", "tiktokcdn.com", "youtube.com",
        "youtu.be", "googleapis.com", "gstatic.com", "reddit.com",
        "redditmedia.com", "whatsapp.com", "telegram.org",
    ],
    "cdn_infrastructure": [
        "cloudflare.com", "cloudflare.net", "fastly.net", "akamaized.net",
        "akamai.net", "edgecastcdn.net", "cloudfront.net", "amazonaws.com",
        "azure.net", "azureedge.net", "jsdelivr.net", "unpkg.com",
        "cdnjs.cloudflare.com", "bootstrapcdn.com", "jquery.com",
        "stackpath.com", "bunnycdn.com", "keycdn.com",
    ],
}


def _disconnect_extract_domain(raw: str) -> str:
    """Return a bare registrable domain from a URL or domain string."""
    raw = raw.strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc or raw
    raw = raw.split(":")[0]          # strip port
    raw = raw.lstrip("*").lstrip(".")  # strip leading wildcard
    raw = raw.rstrip("/")
    return raw


def _load_raw_disconnect_data() -> dict:
    """Return the raw Disconnect.me services.json dict (cached locally)."""
    # Use cached file if it is fresh enough
    if os.path.isfile(_DISCONNECT_CACHE):
        age_days = (time.time() - os.path.getmtime(_DISCONNECT_CACHE)) / 86400
        if age_days < _CACHE_MAX_AGE_DAYS:
            try:
                with open(_DISCONNECT_CACHE, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                pass  # fall through to re-download

    import urllib.request as _ureq
    try:
        print("[*] Downloading Disconnect.me list…")
        with _ureq.urlopen(_DISCONNECT_URL, timeout=15) as resp:
            raw_bytes = resp.read()
        data = json.loads(raw_bytes.decode("utf-8"))
        with open(_DISCONNECT_CACHE, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        print(f"[+] Disconnect.me list downloaded ({len(data.get('categories', {}))} categories) and cached.")
        return data
    except Exception as exc:
        print(f"[WARN] Failed to fetch Disconnect.me list: {exc} – using built-in list.")
        return {}


def _build_tracking_categories() -> dict[str, list[str]]:
    """Merge hard-coded fallback with Disconnect.me data into TRACKING_CATEGORIES."""
    result: dict[str, list[str]] = {k: list(v) for k, v in _HARDCODED_CATEGORIES.items()}
    seen: set[str] = {d for domains in result.values() for d in domains}

    data = _load_raw_disconnect_data()
    if not data:
        return result

    categories = data.get("categories", {})
    added = 0
    for disconnect_cat, our_cat in _DISCONNECT_CAT_MAP.items():
        if our_cat not in result:
            result[our_cat] = []
        cat_entries = categories.get(disconnect_cat, [])
        # Each entry is {company_name: {homepage_url: [domains, ...]}}
        for entry in cat_entries:
            if not isinstance(entry, dict):
                continue
            for _company, props in entry.items():
                if not isinstance(props, dict):
                    continue
                for _url_key, domain_list in props.items():
                    if not isinstance(domain_list, list):
                        continue
                    for raw in domain_list:
                        d = _disconnect_extract_domain(str(raw))
                        if d and "." in d and d not in seen:
                            seen.add(d)
                            result[our_cat].append(d)
                            added += 1

    if added:
        print(f"[+] Disconnect.me: added {added} new domains to categories.")
    return result


# Build at import time (uses cache when available – fast after first run)
TRACKING_CATEGORIES: dict[str, list[str]] = _build_tracking_categories()

# ─────────────────────────────────────────────
#  Domain → Company mapping
# ─────────────────────────────────────────────

_HARDCODED_COMPANIES: dict[str, str] = {
    # Google / Alphabet
    "doubleclick.net": "Google", "googlesyndication.com": "Google",
    "googleadservices.com": "Google", "google-analytics.com": "Google",
    "googletagmanager.com": "Google", "analytics.google.com": "Google",
    "googleapis.com": "Google", "gstatic.com": "Google",
    "google.com": "Google", "youtube.com": "Google",
    "adtrafficquality.google": "Google",
    # Meta
    "facebook.com": "Meta", "facebook.net": "Meta", "fbcdn.net": "Meta",
    "instagram.com": "Meta", "whatsapp.com": "Meta",
    # Microsoft
    "linkedin.com": "Microsoft / LinkedIn", "licdn.com": "Microsoft / LinkedIn",
    "bing.com": "Microsoft", "azure.net": "Microsoft", "azureedge.net": "Microsoft",
    "appnexus.com": "Xandr / Microsoft", "adnxs.com": "Xandr / Microsoft",
    # Amazon
    "amazon-adsystem.com": "Amazon", "amazonaws.com": "Amazon",
    "cloudfront.net": "Amazon",
    # X Corp
    "twitter.com": "X Corp (Twitter)", "twimg.com": "X Corp (Twitter)",
    # Bytedance
    "tiktok.com": "ByteDance", "tiktokcdn.com": "ByteDance",
    # Snap / Pinterest / Reddit
    "snapchat.com": "Snap Inc.", "pinterest.com": "Pinterest",
    "reddit.com": "Reddit", "redditmedia.com": "Reddit",
    # Cloudflare / CDNs
    "cloudflare.com": "Cloudflare", "cloudflare.net": "Cloudflare",
    "fastly.net": "Fastly", "akamaized.net": "Akamai", "akamai.net": "Akamai",
    "edgecastcdn.net": "Edgio", "stackpath.com": "StackPath",
    "bunnycdn.com": "BunnyCDN", "keycdn.com": "KeyCDN",
    "jsdelivr.net": "jsDelivr", "unpkg.com": "unpkg",
    "bootstrapcdn.com": "jsDelivr / Bootstrap CDN",
    # Advertising networks
    "criteo.com": "Criteo", "taboola.com": "Taboola", "outbrain.com": "Outbrain",
    "rubiconproject.com": "Magnite", "pubmatic.com": "PubMatic",
    "openx.net": "OpenX", "adform.net": "Adform",
    "smartadserver.com": "Smart AdServer (Equativ)",
    "indexexchange.com": "Index Exchange", "casalemedia.com": "Index Exchange",
    "thetradedesk.com": "The Trade Desk", "tradedesk.com": "The Trade Desk",
    "bidswitch.net": "IPONWEB / Criteo", "33across.com": "33Across",
    "triplelift.com": "TripleLift", "sovrn.com": "Sovrn",
    "yieldmo.com": "Yieldmo", "revcontent.com": "Revcontent",
    "sharethrough.com": "Sharethrough", "teads.tv": "Teads",
    "moatads.com": "Oracle Moat", "media.net": "Media.net",
    "adroll.com": "AdRoll", "ogury.com": "Ogury",
    "quantcast.com": "Quantcast",
    "onetag.com": "OneTag", "id5-sync.com": "ID5",
    "rlcdn.com": "LiveRamp", "connectad.io": "ConnectedAds",
    # Analytics / measurement
    "hotjar.com": "Hotjar", "mixpanel.com": "Mixpanel",
    "segment.com": "Twilio Segment", "amplitude.com": "Amplitude",
    "heap.io": "Heap", "kissmetrics.com": "Kissmetrics",
    "chartbeat.com": "Chartbeat", "parsely.com": "Parse.ly (Automattic)",
    "quantserve.com": "Quantcast", "comscore.com": "Comscore",
    "scorecardresearch.com": "Comscore",
    "nielsen.com": "Nielsen", "statcounter.com": "StatCounter",
    "newrelic.com": "New Relic", "dynatrace.com": "Dynatrace",
    "fullstory.com": "FullStory", "logrocket.com": "LogRocket",
    "mouseflow.com": "Mouseflow", "contentsquare.com": "Contentsquare",
    "optimizely.com": "Optimizely", "vwo.com": "VWO",
    "abtasty.com": "AB Tasty", "crazyegg.com": "Crazy Egg",
    # Polish / CEE
    "gemius.pl": "Gemius", "gemius.com": "Gemius",
    "hit.gemius.pl": "Gemius",
    "salesmanago.com": "SALESmanago", "salesmanago.pl": "SALESmanago",
    "piano.io": "Piano",
    "userreport.com": "UserReport (Audience Project)",
    "opecloud.com": "OPE / Ringier Axel Springer",
    "brandmetrics.com": "BrandMetrics",
    "adquery.io": "AdQuery",
}


def _build_domain_company_map() -> dict[str, str]:
    """Return a domain → company name dict from Disconnect.me + hardcoded entries."""
    result: dict[str, str] = dict(_HARDCODED_COMPANIES)
    data = _load_raw_disconnect_data()   # uses on-disk cache, very fast after first run
    if not data:
        return result
    categories = data.get("categories", {})
    for disconnect_cat in _DISCONNECT_CAT_MAP:
        for entry in categories.get(disconnect_cat, []):
            if not isinstance(entry, dict):
                continue
            for company_name, props in entry.items():
                if not isinstance(props, dict):
                    continue
                for _url_key, domain_list in props.items():
                    if not isinstance(domain_list, list):
                        continue
                    for raw in domain_list:
                        d = _disconnect_extract_domain(str(raw))
                        if d and "." in d and d not in result:
                            result[d] = company_name
    return result


DOMAIN_COMPANY: dict[str, str] = _build_domain_company_map()

# ─────────────────────────────────────────────
#  Persistent cross-site tracker database
# ─────────────────────────────────────────────

DB_PATH = os.path.join(_SCRIPT_DIR, "ciaho_db.json")


def _company_of_domain(domain: str) -> str:
    """Module-level helper – returns company name for a domain (uses DOMAIN_COMPANY)."""
    domain = domain.lower().lstrip(".")
    if domain in DOMAIN_COMPANY:
        return DOMAIN_COMPANY[domain]
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in DOMAIN_COMPANY:
            return DOMAIN_COMPANY[parent]
    return ""


def _save_to_db(analysis: dict) -> None:
    """
    Append (or update) the scan result in the persistent JSON database.
    Each site is stored once – rescanning the same domain overwrites the old entry.
    """
    try:
        if os.path.isfile(DB_PATH):
            with open(DB_PATH, "r", encoding="utf-8") as fh:
                db = json.load(fh)
        else:
            db = {"scans": []}

        dom  = analysis.get("domains", {})
        tracking_cats = {"advertising", "analytics", "social_media"}

        def _domains_to_companies(domain_list: list) -> list:
            companies: set = set()
            for d in domain_list:
                co = _company_of_domain(d)
                if co:
                    companies.add(co)
            return sorted(companies)

        # Flatten category-bucketed domain dicts into flat lists
        accept_all  = [d for domains in dom.get("accept_categories",  {}).values() for d in domains]
        reject_all  = [d for domains in dom.get("reject_categories",  {}).values() for d in domains]
        accept_trk  = [d for cat, domains in dom.get("accept_categories",  {}).items()
                       if cat in tracking_cats for d in domains]
        reject_trk  = [d for cat, domains in dom.get("reject_categories",  {}).items()
                       if cat in tracking_cats for d in domains]
        non_compliant = dom.get("non_compliant_in_reject", [])

        netloc = urlparse(analysis.get("url", "")).netloc or analysis.get("url", "")

        entry = {
            "url":                       analysis.get("url", ""),
            "netloc":                    netloc,
            "timestamp":                 analysis.get("timestamp", ""),
            "privacy_score":             analysis.get("privacy_score", {}).get("score"),
            "grade":                     analysis.get("privacy_score", {}).get("grade"),
            "gdpr_risk":                 analysis.get("gdpr", {}).get("overall_risk", "NONE"),
            "accept_companies":          _domains_to_companies(accept_all),
            "reject_companies":          _domains_to_companies(reject_all),
            "tracking_companies_accept": _domains_to_companies(accept_trk),
            "tracking_companies_reject": _domains_to_companies(reject_trk),
            "non_compliant_companies":   _domains_to_companies(non_compliant),
        }

        # Replace existing entry for the same netloc (rerun = update)
        db["scans"] = [s for s in db["scans"] if s.get("netloc") != netloc]
        db["scans"].append(entry)

        with open(DB_PATH, "w", encoding="utf-8") as fh:
            json.dump(db, fh, indent=2, ensure_ascii=False)

        print(f"[+] Scan saved to database ({len(db['scans'])} site(s) total): {DB_PATH}")
    except Exception as exc:
        print(f"[WARN] Could not save to database: {exc}")


def _print_company_ranking(top_n: int = 25) -> None:
    """
    Read ciaho_db.json and print a leaderboard: which companies track users
    across the most unique sites in the database.
    """
    if not os.path.isfile(DB_PATH):
        print("[!] No database found. Run at least one scan first.")
        return
    try:
        with open(DB_PATH, "r", encoding="utf-8") as fh:
            db = json.load(fh)
    except Exception as exc:
        print(f"[ERROR] Cannot read database: {exc}")
        return

    scans = db.get("scans", [])
    if not scans:
        print("[!] Database is empty.")
        return

    # company -> set of netlocs where it was seen tracking (after accept)
    accept_sites:     dict[str, set] = defaultdict(set)
    nc_sites:         dict[str, set] = defaultdict(set)   # non-compliant (active after reject)

    for s in scans:
        netloc = s.get("netloc", s.get("url", "?"))
        for co in s.get("tracking_companies_accept", []):
            accept_sites[co].add(netloc)
        for co in s.get("non_compliant_companies", []):
            nc_sites[co].add(netloc)

    ranked = sorted(accept_sites.items(), key=lambda x: len(x[1]), reverse=True)

    sep = "═" * 70
    print(f"\n{sep}")
    print(f"  CROSS-SITE TRACKER RANKING  –  {len(scans)} site(s) in database")
    print(f"  Database: {DB_PATH}")
    print(sep)
    print(f"  {'#':<4} {'Company':<30} {'Sites (tracking)':<8}  {'GDPR violations (sites)'}")
    print(f"  {'─'*4} {'─'*30} {'─'*8}  {'─'*28}")
    for i, (company, sites) in enumerate(ranked[:top_n], 1):
        nc = nc_sites.get(company, set())
        sites_preview = ", ".join(sorted(sites)[:3]) + ("…" if len(sites) > 3 else "")
        nc_str = f"🔴 {len(nc)} ({', '.join(sorted(nc)[:2])}{'…' if len(nc)>2 else ''})" if nc else "✅  –"
        print(f"  {i:<4} {company:<30} {len(sites):<8}  {nc_str}")
        print(f"       {'':30} {sites_preview}")
    print(sep)
    print(f"  Full data: {DB_PATH}\n")



ACCEPT_SELECTORS = [
    # OneTrust / CookiePro
    "#onetrust-accept-btn-handler",
    "#onetrust-button-group button.save-preference-btn-handler",
    ".optanon-allow-all", "#optanon-accept-cookies-button",
    # Cookiebot
    "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
    "#CybotCookiebotDialogBodyButtonAccept",
    # Didomi
    "#didomi-notice-agree-button",
    "[id*='didomi'] button[class*='agree']",
    # TrustArc
    "#truste-consent-button",
    ".truste_box_overflow button",
    # Quantcast Choice
    "[data-id='btnAcceptAll']",
    ".qc-cmp2-summary-buttons > button:first-of-type",
    # Sourcepoint
    ".sp_choice_type_11",
    "[title*='Accept All']",
    "[actiontype='11']",
    # iubenda
    "#iubFooterBtn",
    ".iubenda-cs-accept-btn",
    ".iub-btn-accept",
    # Klaro
    ".klaro .cm-btn-success",
    ".cookie-modal button.success",
    # CookieYes / CookieLaw
    ".cky-btn-accept",
    "#cookie-law-info-bar a.cli-plugin-button",
    # Complianz
    "#cmplz-accept",
    ".cmplz-accept",
    # Cookie Script
    "#cookie-script-accept-all",
    # WP Cookie Notice
    "#cn-accept-cookie",
    # Google FC / Funding Choices
    "[jsname='b3VHJd']",
    "[jscontroller='HkZXZe'] [jsname='b3VHJd']",
    "form[action*='consent.google'] button:first-of-type",
    # Piwik PRO
    "[data-consent-settings-all='accepted']",
    # Usercentrics (shadow DOM – handled separately)
    "[data-testid='uc-accept-all-button']",
    # Termly
    "[data-tid='banner-accept']",
    # Conversant
    "div[class*='cookie'] button[class*='accept']",
    # Generic IDs
    "#accept-cookies", "#cookie-accept", "#acceptCookies", "#accept_cookies",
    "#cookieAccept", "#btn-cookie-accept", "#btnAcceptCookies",
    "#accept-all-cookies", "#acceptAllCookies", "#accept_all", "#acceptAll",
    "#cookie-agree", "#cookieAgree", "#cookies-agree",
    # Generic classes
    ".accept-cookies", ".cookie-accept", ".cookieAccept", ".js-accept-cookies",
    ".accept-all-cookies", ".cc-accept", ".cc-allow", ".cc-btn.cc-allow",
    ".cookie-agree", ".js-cookie-agree", ".cookie-consent-accept",
    ".btn-cookie-accept", ".gdpr-accept", ".gdpr-agree",
    # Aria labels
    '[aria-label="Accept all cookies"]',
    '[aria-label="Accept cookies"]',
    '[aria-label="Allow all cookies"]',
    '[aria-label="Allow all"]',
    '[aria-label="Zaakceptuj wszystkie pliki cookie"]',
    '[aria-label="Zaakceptuj wszystkie"]',
    '[aria-label="Zaakceptuj"]',
    '[aria-label="Zgoda"]',
    '[aria-label="Akceptuj"]',
    # Data attributes
    '[data-consent="accept"]',
    '[data-cookieconsent="allow"]',
    '[data-action="accept"]',
    '[data-action="accept-all"]',
    '[data-cmp-action="acceptAll"]',
    '[data-testid*="accept"]',
    '[data-accept-cookies]',
    # Axeptio
    "#axeptio_btn_acceptAll", ".axeptio-widget button.axeptio-main",
    # Funding Choices / Google FC
    'form[action*="consent.google"] button:first-of-type',
    ".fc-button.fc-cta-consent",
    # Borlabs Cookie
    ".borlabs-cookie__btn--accept-all",
    # TechLab Polish CMP
    "#tc-privacy-accept", "[class*='tc-accept']",
    # Civic Cookie Control
    "#ccc-notify-accept", ".ccc-notify-accept",
    # Usercentrics v2
    '[data-testid="uc-accept-all-button"]',
    # iubenda v2
    ".iubenda-cs-accept-btn", ".iub-btn-accept", "#iubFooterBtn",
    ".iubenda-cs-btn-accept-and-close",
    # Generic
    '[data-value="all"]', '[data-layer="accept"]',
    'button[onclick*="accept"]',
    # Button text patterns (CSS)
    'button[class*="accept"]', 'button[class*="Accept"]',
    'button[class*="allow"]', 'button[class*="Allow"]',
    'button[class*="agree"]', 'button[class*="Agree"]',
    'button[class*="zgod"]',  # polskie: zgoda, zgadzam
    'button[class*="akceptuj"]', 'button[class*="Akceptuj"]',
    'a[class*="accept"]', 'a[class*="allow"]', 'a[class*="agree"]',
    '[role="button"][class*="accept"]', '[role="button"][class*="agree"]',
]

REJECT_SELECTORS = [
    # OneTrust / CookiePro
    "#onetrust-reject-all-handler",
    ".optanon-reject-all", "#optanon-reject-cookies-button",
    # Cookiebot
    "#CybotCookiebotDialogBodyButtonDecline",
    # Didomi
    "#didomi-notice-disagree-button",
    # Quantcast
    "[data-id='btnRejectAll']",
    ".qc-cmp2-summary-buttons > button:last-of-type",
    # Sourcepoint
    ".sp_choice_type_13",
    "[actiontype='13']",
    # iubenda
    ".iubenda-cs-reject-btn",
    # Klaro
    ".klaro .cm-btn-decline",
    # CookieYes
    ".cky-btn-reject",
    # Complianz
    "#cmplz-deny",
    ".cmplz-deny",
    # GDPR Cookie Consent (WP plugin)
    "#cookie_action_close_header_reject",
    # Usercentrics shadow DOM
    "[data-testid='uc-deny-all-button']",
    # Termly
    "[data-tid='banner-decline']",
    # Generic IDs
    "#reject-cookies", "#cookie-reject", "#rejectCookies", "#reject_cookies",
    "#cookieReject", "#btn-cookie-reject", "#btnRejectCookies",
    "#reject-all-cookies", "#rejectAllCookies", "#decline-cookies",
    "#cookie-refuse", "#refuseCookies",
    # Generic classes
    ".reject-cookies", ".cookie-reject", ".js-reject-cookies",
    ".reject-all-cookies", ".cc-deny", ".cc-decline", ".cc-btn.cc-deny",
    ".cookie-refuse", ".gdpr-deny", ".gdpr-decline",
    # Aria labels
    '[aria-label="Reject all cookies"]',
    '[aria-label="Reject cookies"]',
    '[aria-label="Deny all cookies"]',
    '[aria-label="Odrzuć wszystkie pliki cookie"]',
    '[aria-label="Odrzuć wszystkie"]',
    '[aria-label="Odrzuć"]',
    '[aria-label="Nie zgadzam się"]',
    # Data attributes
    '[data-consent="reject"]',
    '[data-cookieconsent="deny"]',
    '[data-action="reject"]',
    '[data-action="reject-all"]',
    '[data-cmp-action="rejectAll"]',
    '[data-testid*="reject"]', '[data-testid*="deny"]', '[data-testid*="decline"]',
    # Axeptio
    "#axeptio_btn_closeAll",
    # Funding Choices / Google FC
    'form[action*="consent.google"] button:last-of-type',
    ".fc-cta-do-not-consent",
    # Borlabs Cookie
    ".borlabs-cookie__btn--reject",
    # TechLab Polish CMP
    "#tc-privacy-reject", "[class*='tc-reject']",
    # Civic Cookie Control
    "#ccc-reject-settings",
    # Usercentrics v2
    '[data-testid="uc-deny-all-button"]',
    # Button text patterns (CSS)
    'button[class*="reject"]', 'button[class*="Reject"]',
    'button[class*="deny"]', 'button[class*="Deny"]',
    'button[class*="decline"]', 'button[class*="Decline"]',
    'button[class*="refuse"]', 'button[class*="Refuse"]',
    'button[class*="odrzuc"]', 'button[class*="odrzuć"]',
    'a[class*="reject"]', 'a[class*="decline"]', 'a[class*="deny"]',
    '[role="button"][class*="reject"]', '[role="button"][class*="decline"]',
]

# Text patterns used when CSS selectors don't match
ACCEPT_TEXT_PATTERNS = [
    # English – explicit all/full
    r"\baccept all\b", r"\baccept all cookies\b", r"\baccept cookies\b",
    r"\baccept all & close\b", r"\baccept all and close\b",
    r"\ballow all\b", r"\ballow all cookies\b", r"\ballow cookies\b",
    r"\ballow all and continue\b",
    # English – agree
    r"\bagree to all\b", r"\bi agree\b", r"\bagree\b",
    r"\byes,? i agree\b", r"\bagree & proceed\b",
    # English – ok/got it
    r"\bgot it\b", r"\bok,? i understand\b", r"\bunderstood\b",
    r"\bok,? accept\b", r"^ok$",
    # English – accept generic
    r"\byes,? accept\b", r"\baccept & close\b", r"\baccept and close\b",
    r"\baccept & continue\b", r"\baccept and continue\b",
    r"\bconsent to all\b", r"\byes, consent\b",
    r"^accept$", r"^allow$",
    # English – "I accept" / "I consent"
    r"\bi accept\b", r"\bi consent\b", r"\bi accept all\b",
    # English – continue
    r"\bcontinue to site\b", r"\bcontinue with all\b",
    r"\byes, continue\b",
    # Polish – accept
    r"\bzaakceptuj wszystkie\b", r"\bzaakceptuj\b",
    r"\bakceptuj wszystkie\b", r"\bakceptuj\b",
    r"\bprzyjmij wszystkie\b", r"\bprzyjmij\b",
    r"\bzgadzam się\b", r"\bwyrażam zgodę\b",
    r"\bzezwólna wszystkie\b", r"\bzezwól\b",
    r"^zgoda$", r"^ok$", r"\brozumiem\b",
    r"\bdo\w*czam zgodę\b",
    r"\bzapisz i zamknij\b",
    r"\btak, akceptuję\b", r"\btak, wyrażam zgodę\b",
    r"\bprzyjmuję\b", r"\bprzyjmuję wszystkie\b",
    # Polish – approve
    r"\bzatwierdź wszystkie\b", r"\bzatwierdź\b",
    # French
    r"\btout accepter\b", r"\baccepter tout\b", r"\baccepter\b",
    r"\bj'accepte\b", r"\bje suis d'accord\b",
    # German
    r"\balle akzeptieren\b", r"\bakzeptieren\b", r"\bzustimmen\b",
    r"\balle zulassen\b",
    # Spanish
    r"\baceptar todo\b", r"\baceptar todas\b", r"\baceptar\b",
]

REJECT_TEXT_PATTERNS = [
    # English – reject all
    r"\breject all\b", r"\breject all cookies\b", r"\breject cookies\b",
    r"\bdeny all\b", r"\bdeny all cookies\b", r"\bdeny cookies\b",
    r"\bdecline all\b", r"\bdecline all cookies\b", r"\bdecline cookies\b",
    r"\bdecline\b", r"\brefuse all\b", r"\brefuse\b",
    # English – no thanks
    r"\bno,? thanks\b", r"\bno thank you\b", r"\bno, thanks\b",
    r"\bskip\b",
    # English – necessary/essential as reject fallback
    r"\bonly necessary\b", r"\bonly necessary cookies\b",
    r"\bonly essential\b", r"\bonly essential cookies\b",
    r"\bonly required\b", r"\buse necessary only\b",
    r"\bcontinue without accepting\b", r"\bcontinue without consent\b",
    r"\bwithout accepting\b",
    # English – save/confirm with no extras
    r"\bsave preferences\b", r"\bsave settings\b", r"\bsave & exit\b",
    r"^reject$",
    # Polish – reject
    r"\bodrzuć wszystkie\b", r"\bodrzuć wszystkie pliki\b",
    r"\bodrzuć\b", r"\bodmów\b", r"\bodmów wszystkich\b",
    r"\bnie zgadzam się\b", r"\bnie akceptuję\b", r"\bnie wyrażam zgody\b",
    r"\btylko niezbędne\b", r"\btylko wymagane\b", r"\btylko konieczne\b",
    r"\bzarządzaj (preferencjami|ustawieniami)\b",
    r"\bkontynuuj bez akceptacji\b", r"\bkontynuuj bez zgody\b",
    r"\bprzejdź bez zgody\b",
    r"^nie$",
    # French
    r"\btout refuser\b", r"\brefuser tout\b", r"\brefuser\b",
    r"\brejeter\b",
    # German
    r"\balle ablehnen\b", r"\bablehnen\b",
    # Spanish
    r"\brechazar todo\b", r"\brechazar\b",
]

# Selectors / patterns for "only necessary cookies" scenario
NECESSARY_SELECTORS = [
    # OneTrust
    "#onetrust-reject-all-handler",
    # Cookiebot
    "#CybotCookiebotDialogBodyButtonDecline",
    # Didomi
    "#didomi-notice-disagree-button",
    # Sourcepoint
    ".sp_choice_type_13", "[actiontype='13']",
    # iubenda
    ".iubenda-cs-reject-btn",
    # Klaro
    ".klaro .cm-btn-decline",
    # CookieYes
    ".cky-btn-reject",
    # Complianz
    "#cmplz-deny", ".cmplz-deny",
    # GDPR Cookie Consent WP plugin
    "#cookie_action_close_header_reject",
    # Usercentrics
    "[data-testid='uc-deny-all-button']",
    # Termly
    "[data-tid='banner-decline']",
    # InMobi Choice (cmp.inmobi.com) – used by gryonline.pl and others
    "[class*='inmobi'] button[class*='reject']",
    "[class*='inmobi'] button[class*='decline']",
    "[class*='choice'] button[class*='reject']",
    "[class*='choice'] button[class*='decline']",
    "[class*='choice'] button[class*='necessary']",
    ".pmConsentWall--reject",
    # Specific necessary-only elements
    "[id*='necessary-only']", "[id*='essential-only']",
    "[class*='necessary-only']", "[class*='essential-only']",
    "[data-testid*='necessary']",
    # Generic reject / necessary fallbacks
    "#reject-cookies", "#cookie-reject", "#rejectCookies",
    "#reject-all-cookies", "#rejectAllCookies", "#decline-cookies",
    ".reject-all-cookies", ".cc-deny", ".cc-btn.cc-deny",
    'button[class*="reject"]', 'button[class*="necessary"]',
    'button[class*="essential"]',
    '[aria-label="Reject all cookies"]',
    '[aria-label="Odrzu\u0107 wszystkie"]',
    '[data-consent="reject"]',
]

NECESSARY_TEXT_PATTERNS = [
    # English – necessary/essential
    r"\bonly necessary\b", r"\bonly necessary cookies\b",
    r"\bonly essential\b", r"\bonly essential cookies\b",
    r"\bonly strictly necessary\b", r"\bstrictly necessary only\b",
    r"\buse necessary only\b", r"\buse only necessary\b",
    r"\bnecessary only\b", r"\bessential only\b",
    r"\bset necessary cookies only\b",
    # English – without accepting
    r"\bcontinue without accepting\b", r"\bcontinue without consent\b",
    r"\bwithout accepting\b", r"\bno,? use only necessary\b",
    # English bare keywords
    r"^necessary$", r"^essential$",
    # English – reject as fallback
    r"\breject all\b", r"\bdeny all\b", r"\bdecline all\b",
    # Polish – only necessary
    r"\btylko niezbędne\b", r"\btylko niezbędne pliki cookie\b",
    r"\btylko wymagane\b", r"\btylko konieczne\b",
    r"\btylko ściśle niezbędne\b",
    r"\bkontynuuj bez akceptacji\b", r"\bkontynuuj bez zgody\b",
    r"\bprzejdź bez akceptacji\b",
    r"^niezbędne$",
    # Polish – reject as fallback
    r"\bodrzuć wszystkie\b", r"\bodrzuć\b",
    # French
    r"\bcookies nécessaires uniquement\b", r"\buniquement nécessaires\b",
    r"\btout refuser\b",
    # German
    r"\bnur notwendige\b", r"\bnur erforderliche\b",
]

# Selectors for "Manage preferences / Settings" panel trigger
MANAGE_SELECTORS = [
    # OneTrust
    "#onetrust-pc-btn-handler",
    # Cookiebot
    "#CybotCookiebotDialogBodyLevelButtonCustomize",
    "#CybotCookiebotDialogBodyButtonDetails",
    # Didomi
    ".didomi-components-button.didomi-outline-button",
    # Quantcast
    ".qc-cmp2-summary-buttons > button:last-of-type",
    # Sourcepoint
    ".sp_choice_type_12", "[actiontype='12']",
    # iubenda
    ".iubenda-cs-customize-btn",
    # Generic by attribute
    "button[class*='manage']", "button[class*='setting']",
    "button[class*='customize']", "button[class*='preference']",
    "button[class*='option']", "button[class*='choice']",
    "button[class*='zarz']", "button[class*='ustaw']",
    "a[class*='manage']", "a[class*='setting']",
    "[data-testid*='manage']", "[data-testid*='settings']",
    "[data-testid*='customize']", "[data-testid*='preference']",
    "[class*='manage-cookies']", "[class*='cookie-settings']",
    "[class*='cookie-preferences']", "[class*='privacy-settings']",
    # Axeptio
    ".axeptio-widget button:last-of-type",
    # TechLab
    "#tc-privacy-settings", "[class*='tc-settings']",
]

MANAGE_TEXT_PATTERNS = [
    r"\bmanage (settings|preferences|cookies|options|choices)\b",
    r"\bcustomize\b", r"\bcustomize cookies\b", r"\bmore options\b",
    r"\bcookie settings\b", r"\bprivacy settings\b", r"\bcookie preferences\b",
    r"\bpersonalize\b", r"\bset preferences\b",
    r"\bpreferences\b", r"\bsettings\b",
    r"\bzarządzaj (ustawieniami|preferencjami|plikami cookie|cookies)\b",
    r"\bdostosuj\b", r"\bpreferencje\b", r"\bustawienia\b",
    r"\bwięcej opcji\b", r"\bopcje\b",
]


# ─────────────────────────────────────────────
#  Main analyzer class
# ─────────────────────────────────────────────

class CookieAnalyzer:
    def __init__(self, url: str, output_dir: str = "output",
                 browser_type: str = "chrome", browser_binary: str | None = None,
                 crawl_depth: int = 1):
        self.url = self._normalize_url(url)
        self.output_dir = os.path.abspath(output_dir)
        self.browser_type = browser_type          # "chrome" | "firefox" | "edge"
        self.browser_binary = browser_binary
        self.crawl_depth = max(1, min(int(crawl_depth), 5))  # 1–5 pages per scenario
        self.bmp_server: Server | None = None
        self.proxy = None
        os.makedirs(self.output_dir, exist_ok=True)

    # ── Helpers ──────────────────────────────

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def _categorize_domain(self, domain: str) -> str:
        domain = domain.lower()
        for category, domains in TRACKING_CATEGORIES.items():
            for tracked in domains:
                if domain == tracked or domain.endswith("." + tracked):
                    return category
        return "other"

    def _company_of(self, domain: str) -> str:
        """Return the company (owner) name for a domain, or empty string."""
        domain = domain.lower().lstrip(".")
        if domain in DOMAIN_COMPANY:
            return DOMAIN_COMPANY[domain]
        # Try progressively shorter suffixes (sub.example.com → example.com)
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in DOMAIN_COMPANY:
                return DOMAIN_COMPANY[parent]
        return ""

    # ── Proxy management ─────────────────────

    @staticmethod
    def _free_port() -> int:
        """Return a random free TCP port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    @staticmethod
    def _kill_old_bmp():
        """Kill any lingering browsermob-proxy Java processes."""
        try:
            result = subprocess.run(
                ["pgrep", "-f", "browsermob"],
                capture_output=True, text=True
            )
            pids = result.stdout.strip().split()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                    print(f"    [*] Killed stale BMP process PID {pid}")
                except Exception:
                    pass
            if pids:
                time.sleep(1.5)
        except Exception:
            pass

    def _start_proxy(self):
        print("[*] Starting browsermob-proxy...")
        if not os.path.exists(BROWSERMOB_PATH):
            raise FileNotFoundError(
                f"browsermob-proxy not found at:\n  {BROWSERMOB_PATH}\n\n"
                "Run setup first:  ./setup.sh"
            )
        self._kill_old_bmp()
        port = self._free_port()
        self.bmp_server = Server(BROWSERMOB_PATH, options={"port": port})
        self.bmp_server.start()
        self.proxy = self.bmp_server.create_proxy()
        # Register cleanup so Ctrl+C etc. won't leave zombies
        atexit.register(self._stop_proxy)
        print(f"[+] Proxy running on port {self.proxy.port}")

    def _stop_proxy(self):
        try:
            if self.proxy:
                self.proxy.close()
        except Exception:
            pass
        try:
            if self.bmp_server:
                self.bmp_server.stop()
        except Exception:
            pass
        # Extra safety: kill Java BMP process if still alive
        self._kill_old_bmp()

    # ── Browser management ───────────────────

    def _create_driver(self) -> tuple:
        """Return (driver, tmp_profile_dir) where tmp_profile_dir may be ''."""
        if self.browser_type == "firefox":
            return self._create_firefox_driver(), ""
        if self.browser_type == "edge":
            return self._create_edge_driver()
        return self._create_chrome_driver()

    def _create_chrome_driver(self) -> webdriver.Chrome:
        options = ChromeOptions()
        if self.browser_binary:
            options.binary_location = self.browser_binary

        tmp_profile = tempfile.mkdtemp(prefix="ciaho_chrome_")
        options.add_argument(f"--user-data-dir={tmp_profile}")
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-setuid-sandbox")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--disable-extensions")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        options.add_argument(
            "--user-agent=Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        options.add_argument(f"--proxy-server={self.proxy.proxy}")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost")

        ver = self._detect_browser_version()
        cached = self._find_cached_chromedriver(ver)
        service = ChromeService(cached) if cached else None
        driver = (webdriver.Chrome(service=service, options=options)
                  if service else webdriver.Chrome(options=options))
        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        return driver, tmp_profile

    def _create_edge_driver(self) -> tuple:
        options = EdgeOptions()
        if self.browser_binary:
            options.binary_location = self.browser_binary
        tmp_profile = tempfile.mkdtemp(prefix="ciaho_edge_")
        options.add_argument(f"--user-data-dir={tmp_profile}")
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument(f"--proxy-server={self.proxy.proxy}")
        options.add_argument("--ignore-certificate-errors")
        if HAS_WDM:
            service = EdgeService(EdgeChromiumDriverManager().install())
            driver = webdriver.Edge(service=service, options=options)
        else:
            driver = webdriver.Edge(options=options)
        return driver, tmp_profile

    def _create_firefox_driver(self) -> webdriver.Firefox:
        options = FirefoxOptions()
        # Only set binary_location when it's a real ELF executable
        # (snap wrapper shell scripts cause "binary is not a Firefox executable")
        if self.browser_binary and not _is_shell_script(self.browser_binary):
            options.binary_location = self.browser_binary
        # else: let geckodriver pick up firefox from PATH (snap wrapper works)
        options.add_argument("--headless")
        options.add_argument("--width=1920")
        options.add_argument("--height=1080")
        options.add_argument("--no-remote")
        # Configure proxy via Firefox preferences
        proxy_host, proxy_port_str = self.proxy.proxy.split(":")
        proxy_port = int(proxy_port_str)
        options.set_preference("network.proxy.type", 1)
        options.set_preference("network.proxy.http", proxy_host)
        options.set_preference("network.proxy.http_port", proxy_port)
        options.set_preference("network.proxy.ssl", proxy_host)
        options.set_preference("network.proxy.ssl_port", proxy_port)
        options.set_preference("network.proxy.no_proxies_on",
                               "localhost,127.0.0.1")
        options.set_preference("accept_untrusted_certs", True)
        options.set_preference("network.stricttransportsecurity.preloadlist", False)
        options.set_preference("security.cert_pinning.enforcement_level", 0)

        # Prefer system geckodriver (avoids WDM version mismatch)
        gecko = subprocess.run(
            ["which", "geckodriver"], capture_output=True, text=True
        ).stdout.strip()
        if not gecko:
            # Try WDM cache
            wdm_gecko = os.path.join(
                os.path.expanduser("~"), ".wdm", "drivers", "geckodriver"
            )
            gecko = self._find_any_binary(wdm_gecko) or ""
        if gecko:
            service = FirefoxService(gecko, service_args=["--log", "fatal"],
                                     timeout=60)
            driver = webdriver.Firefox(service=service, options=options)
        elif HAS_WDM:
            service = FirefoxService(
                GeckoDriverManager().install(),
                service_args=["--log", "fatal"], timeout=60
            )
            driver = webdriver.Firefox(service=service, options=options)
        else:
            driver = webdriver.Firefox(options=options)
        return driver

    def _find_any_binary(self, directory: str) -> str | None:
        """Walk a directory tree and return first executable file found."""
        if not os.path.isdir(directory):
            return None
        for root, _, files in os.walk(directory):
            for f in files:
                full = os.path.join(root, f)
                if os.access(full, os.X_OK):
                    return full
        return None

    def _detect_browser_version(self) -> str:
        """Return version string of the detected browser binary."""
        try:
            binary = self.browser_binary or "google-chrome-stable"
            out = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=5
            ).stdout.strip()
            parts = out.split()
            if parts:
                return parts[-1]  # e.g. "145.0.7632.159"
        except Exception:
            pass
        return ""

    def _find_cached_chromedriver(self, browser_ver: str) -> str | None:
        """Find a chromedriver in selenium-manager cache matching browser version."""
        if not browser_ver:
            return None
        major = browser_ver.split(".")[0]
        cache_root = os.path.join(os.path.expanduser("~"), ".cache", "selenium", "chromedriver")
        if not os.path.isdir(cache_root):
            return None
        best = None
        for arch in os.listdir(cache_root):
            arch_dir = os.path.join(cache_root, arch)
            if not os.path.isdir(arch_dir):
                continue
            for ver_dir in sorted(os.listdir(arch_dir), reverse=True):
                cd = os.path.join(arch_dir, ver_dir, "chromedriver")
                if not os.path.isfile(cd):
                    continue
                if ver_dir.startswith(major + "."):
                    if ver_dir.startswith(browser_ver.rsplit(".", 1)[0]):
                        return cd
                    best = cd
        return best

    # ── Consent detection ────────────────────

    # Popup wrapper selectors – used to detect when the banner appeared
    _CONSENT_WRAPPERS = [
        # OneTrust / CookiePro
        "#onetrust-banner-sdk", "#onetrust-consent-sdk",
        # Cookiebot
        "#CybotCookiebotDialog", ".CybotCookiebotDialog",
        # Didomi
        "#didomi-popup", ".didomi-popup", ".didomi-notice",
        # Sourcepoint
        "#sp_message_container", ".sp_message_container",
        # Quantcast
        ".qc-cmp2-container", ".qc-cmp2-ui",
        # Axeptio
        "#axeptio_overlay", ".axeptio_widget", ".axeptio-widget",
        # Funding Choices (Google FC)
        ".fc-dialog-container", ".fc-consent-root", ".fc-cta-do-not-consent",
        # Borlabs Cookie (WP)
        "#BorlabsCookie", ".borlabs-cookie",
        # TechLab / Polish CMP
        "#tc-privacy-wrapper", ".tc-privacy-wrapper",
        "[id*='tc-consent']", "[class*='tc-consent']",
        # iubenda
        "#iubenda-cs-banner", ".iubenda-cs-banner",
        # CookieYes / GDPR Compliance
        ".cky-consent-container", ".cky-modal",
        ".cli-bar-container", "#cookie-law-info-bar",
        # Klaro
        ".klaro", "#klaro",
        # Real Cookie Banner (WP)
        ".real-cookie-banner", "#real-cookie-banner",
        # Complianz
        "#cmplz-cookiebanner", ".cmplz-cookiebanner", ".cmplz-body",
        # IAB / generic by ID
        "[id*='cookie-banner']", "[id*='cookie_banner']",
        "[id*='cookie-consent']", "[id*='cookieconsent']",
        "[id*='cookie-notice']", "[id*='cookieNotice']",
        "[id*='consent-manager']", "[id*='consentManager']",
        "[id*='cookie-modal']", "[id*='cookieModal']",
        "[id*='gdpr-banner']", "[id*='gdprBanner']",
        "[id*='privacy-banner']",
        # Generic by class
        "[class*='cookie-banner']", "[class*='cookie-consent']",
        "[class*='cookieBanner']", "[class*='cookieConsent']",
        "[class*='cookie-notice']", "[class*='cookie-bar']",
        "[class*='cookieBar']", "[class*='cookie-wall']",
        "[class*='cookie-layer']", "[class*='cookie-popup']",
        "[class*='cookiePopup']", "[class*='cookie-modal']",
        "[class*='consent-banner']", "[class*='consentBanner']",
        "[class*='consent-popup']", "[class*='consent-manager']",
        "[class*='gdpr']", "[class*='privacy-banner']",
        "[class*='cc-window']", "[class*='cc-banner']",
        # Aria-label based
        "[aria-label*='cookie']", "[aria-label*='Cookie']",
        "[aria-label*='consent']", "[aria-label*='Consent']",
        "[aria-label*='privacy']", "[aria-label*='Privacy']",
        # Role-based (modal dialogs)
        '[role="dialog"][aria-label*="cookie"]',
        '[role="dialog"][aria-label*="Cookie"]',
        '[role="dialog"][aria-label*="consent"]',
        '[role="alertdialog"][aria-label*="cookie"]',
        # GDPR Cookie Consent (WP plugins)
        "#gdpr-cookie-message", ".gdpr-cookie-notice",
        "#cookie-notice", ".cookie-notice-container",
    ]

    def _wait_for_consent_banner(self, driver, timeout: float = 12.0) -> bool:
        """Poll until any consent wrapper becomes visible or timeout (sec)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            # 1. Known wrapper selectors
            for wrapper in self._CONSENT_WRAPPERS:
                try:
                    elems = driver.find_elements(By.CSS_SELECTOR, wrapper)
                    if any(e.is_displayed() for e in elems):
                        return True
                except Exception:
                    pass
            # 2. Consent-related iframes (Google FC, TrustArc, SP, etc.)
            try:
                for iframe in driver.find_elements(By.TAG_NAME, "iframe"):
                    src = (iframe.get_attribute("src") or "").lower()
                    name = (iframe.get_attribute("name") or "").lower()
                    if any(kw in src or kw in name for kw in
                           ["consent", "cookie", "privacy", "gdpr",
                            "tcf", "cmp", "sourcepoint", "sp-prod", "fc.yahoo"]):
                        if iframe.is_displayed():
                            return True
            except Exception:
                pass
            # 3. Generic role="dialog" / "alertdialog" with consent text
            try:
                for sel in ('[role="dialog"]', '[role="alertdialog"]'):
                    for dlg in driver.find_elements(By.CSS_SELECTOR, sel):
                        if not dlg.is_displayed():
                            continue
                        combined = " ".join([
                            dlg.get_attribute("aria-label") or "",
                            dlg.get_attribute("aria-describedby") or "",
                            dlg.text or "",
                        ]).lower()
                        if any(kw in combined for kw in
                               ["cookie", "consent", "privacy", "gdpr",
                                "ciasteczka", "zgoda", "prywatność"]):
                            return True
            except Exception:
                pass
            time.sleep(0.4)
        return False  # proceed even if no wrapper found

    def _elem_text(self, driver, elem) -> str:
        """Extract visible text from element using multiple strategies, including deep child text."""
        for getter in [
            lambda e: e.text,
            lambda e: driver.execute_script(
                "return (arguments[0].innerText || arguments[0].textContent || '').trim();", e),
            lambda e: e.get_attribute("value") or "",
            lambda e: e.get_attribute("aria-label") or "",
            lambda e: e.get_attribute("title") or "",
            lambda e: e.get_attribute("placeholder") or "",
            lambda e: e.get_attribute("data-text") or "",
            lambda e: e.get_attribute("data-label") or "",
            # deep child text – join all descendant text nodes
            lambda e: driver.execute_script(
                "return Array.from(arguments[0].querySelectorAll('*'))"
                ".map(n => n.innerText || n.textContent || '')"
                ".join(' ').replace(/\\s+/g, ' ').trim();", e),
        ]:
            try:
                t = (getter(elem) or "").strip()
                if t:
                    return t
            except Exception:
                pass
        return ""

    # ── CAPTCHA detection ─────────────────────────────────────────────────────

    _CAPTCHA_MARKERS = [
        # element IDs / classes
        'id="captcha"', "id='captcha'",
        'class="captcha"', "class='captcha'",
        # Google reCAPTCHA
        'recaptcha', 'grecaptcha', '___grecaptcha_cfg',
        # hCaptcha
        'hcaptcha', 'h-captcha',
        # Cloudflare challenges
        'cf-challenge', 'cf_chl_opt', 'cf-chl-widget',
        # Cloudflare Turnstile
        'cf-turnstile', 'turnstile',
        # Generic
        'data-sitekey',
    ]

    def _detect_captcha(self, driver) -> bool:
        """
        Return True (and print a warning) if the current page appears to
        present a CAPTCHA or bot-challenge wall.
        """
        try:
            src = driver.page_source.lower()
            title = driver.title.lower()
            # Common titles from Cloudflare / generic captcha pages
            captcha_titles = ["just a moment", "attention required", "ddos-guard",
                              "are you human", "bot check", "security check"]
            if any(t in title for t in captcha_titles):
                print(f"    [WARN] CAPTCHA / bot-challenge page detected (title: '{driver.title}').")
                print( "    [WARN] Analysis results for this scenario may be incomplete.")
                return True
            if any(m in src for m in self._CAPTCHA_MARKERS):
                print( "    [WARN] CAPTCHA widget detected in page source.")
                print( "    [WARN] Analysis results for this scenario may be incomplete.")
                return True
        except Exception:
            pass
        return False

    def _remove_overlays(self, driver) -> None:
        """Remove or hide overlay/backdrop elements that block consent button clicks."""
        try:
            driver.execute_script("""
                // Remove fixed/absolute full-viewport overlays that aren't the banner
                const KEEP = ['cookie','consent','gdpr','privacy','cmp','notice','banner'];
                document.querySelectorAll('*').forEach(el => {
                    try {
                        const s = window.getComputedStyle(el);
                        if ((s.position === 'fixed' || s.position === 'absolute')
                             && s.display !== 'none' && s.visibility !== 'hidden'
                             && parseInt(s.zIndex || '0') > 100) {
                            const id  = (el.id  || '').toLowerCase();
                            const cls = (el.className || '').toLowerCase();
                            const isConsent = KEEP.some(k => id.includes(k) || cls.includes(k));
                            if (!isConsent) {
                                const r = el.getBoundingClientRect();
                                // Wide overlay covering most of viewport
                                if (r.width > window.innerWidth * 0.5
                                    && r.height > window.innerHeight * 0.3) {
                                    el.style.pointerEvents = 'none';
                                    el.style.zIndex = '-1';
                                }
                            }
                        }
                    } catch(e) {}
                });
            """)
        except Exception:
            pass

    def _js_deeptext_find(self, driver, text_patterns: list):
        """
        JavaScript-level deep search: walks every text node in the document
        (including shadow roots) and returns the nearest clickable ancestor
        whose text matches any of the given patterns.
        This is the highest-coverage fallback – it finds buttons that have no
        standard class/id convention and are not reachable by Selenium.
        """
        patterns_json = json.dumps(
            [p for p in text_patterns],
        )
        try:
            elem = driver.execute_script(f"""
                const patterns = {patterns_json}.map(p => new RegExp(p, 'i'));
                const CLICKABLE = new Set([
                    'BUTTON','A','INPUT','LABEL','SPAN','DIV','LI','TD','P'
                ]);
                function textOf(el) {{
                    return (el.innerText || el.textContent || '').trim();
                }}
                function isVisible(el) {{
                    try {{
                        const r = el.getBoundingClientRect();
                        if (r.width === 0 || r.height === 0) return false;
                        const s = window.getComputedStyle(el);
                        return s.display !== 'none'
                            && s.visibility !== 'hidden'
                            && parseFloat(s.opacity) > 0.01;
                    }} catch(e) {{ return false; }}
                }}
                function isClickable(el) {{
                    const t = el.tagName;
                    if (t === 'BUTTON') return true;
                    if (t === 'A' && el.href) return true;
                    if (t === 'INPUT' && ['button','submit'].includes(el.type)) return true;
                    const r = el.getAttribute('role');
                    if (r === 'button' || r === 'link') return true;
                    const s = window.getComputedStyle(el);
                    return s.cursor === 'pointer'
                        && CLICKABLE.has(t)
                        && el.onclick !== null;
                }}
                function searchIn(root) {{
                    // Gather all elements
                    let all;
                    try {{ all = Array.from(root.querySelectorAll('*')); }}
                    catch(e) {{ return null; }}
                    for (const el of all) {{
                        if (!isVisible(el)) continue;
                        const txt = textOf(el);
                        if (!txt || txt.length > 120) continue;
                        if (!patterns.some(p => p.test(txt))) continue;
                        // Walk up to find a clickable ancestor within 3 levels
                        let candidate = el;
                        for (let i = 0; i < 4; i++) {{
                            if (isClickable(candidate)) return candidate;
                            if (!candidate.parentElement) break;
                            candidate = candidate.parentElement;
                        }}
                        // Walk down to find button child
                        const btn = el.querySelector('button, [role="button"]');
                        if (btn && isVisible(btn)) return btn;
                        // Return el itself if it has pointer cursor
                        if (isClickable(el)) return el;
                    }}
                    // Recurse into shadow roots
                    for (const el of all) {{
                        if (el.shadowRoot) {{
                            const found = searchIn(el.shadowRoot);
                            if (found) return found;
                        }}
                    }}
                    return null;
                }}
                return searchIn(document.body);
            """)
            return elem if elem else None
        except Exception:
            return None

    def _find_in_shadow_dom(self, driver, text_patterns: list):
        """Search interactive elements inside shadow DOM trees."""
        try:
            elements = driver.execute_script("""
                function collectInteractive(root) {
                    const results = [];
                    const q = 'button, a, [role="button"], input[type="button"],'
                            + 'input[type="submit"], div[role="button"],'
                            + 'span[role="button"], div[class*="cookie"][onclick]';
                    try { results.push(...root.querySelectorAll(q)); } catch(e) {}
                    root.querySelectorAll('*').forEach(el => {
                        if (el.shadowRoot)
                            collectInteractive(el.shadowRoot).forEach(x => results.push(x));
                    });
                    return results;
                }
                const hasShadow = [...document.querySelectorAll('*')].some(e => e.shadowRoot);
                if (!hasShadow) return [];
                return collectInteractive(document.body);
            """)
            if not elements:
                return None
            for elem in elements:
                try:
                    if not elem.is_displayed():
                        continue
                    text = self._elem_text(driver, elem)
                    if not text:
                        continue
                    for pattern in text_patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            return elem
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _text_scan(self, driver, text_patterns: list):
        """Scan all visible interactive elements by text content."""
        try:
            candidates = driver.execute_script("""
                return Array.from(document.querySelectorAll(
                    'button, a, [role="button"], input[type="button"],'
                    + 'input[type="submit"], span[role="button"], div[role="button"]'
                ));
            """) or []
        except Exception:
            candidates = []
        if not candidates:
            try:
                candidates = (
                    driver.find_elements(By.TAG_NAME, "button")
                    + driver.find_elements(By.TAG_NAME, "a")
                    + driver.find_elements(By.CSS_SELECTOR, '[role="button"]')
                    + driver.find_elements(By.CSS_SELECTOR, 'input[type="button"]')
                    + driver.find_elements(By.CSS_SELECTOR, 'input[type="submit"]')
                    + driver.find_elements(By.CSS_SELECTOR, 'div[role="button"]')
                    + driver.find_elements(By.CSS_SELECTOR, 'span[role="button"]')
                )
            except Exception:
                candidates = []
        for elem in candidates:
            try:
                if not elem.is_displayed():
                    continue
                text = self._elem_text(driver, elem)
                if not text:
                    continue
                for pattern in text_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        return elem
            except Exception:
                continue
        return None

    def _find_in_iframes(self, driver, selectors: list, text_patterns: list):
        """Search for consent buttons inside visible iframes.

        When a button is found the driver is left switched to that iframe so
        the caller can click it.  After clicking, call
        driver.switch_to.default_content() to restore context.
        """
        try:
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
        except Exception:
            return None
        for iframe in iframes:
            try:
                if not iframe.is_displayed():
                    continue
                driver.switch_to.frame(iframe)
                # CSS selectors inside iframe
                for selector in selectors:
                    try:
                        for elem in driver.find_elements(By.CSS_SELECTOR, selector):
                            if elem.is_displayed():
                                return elem   # driver left in this frame
                    except Exception:
                        continue
                # Shadow DOM inside iframe
                shadow_btn = self._find_in_shadow_dom(driver, text_patterns)
                if shadow_btn:
                    return shadow_btn
                # Text scan inside iframe
                btn = self._text_scan(driver, text_patterns)
                if btn:
                    return btn
                # Nothing found – switch back before trying next iframe
                driver.switch_to.default_content()
            except Exception:
                try:
                    driver.switch_to.default_content()
                except Exception:
                    pass
        return None

    def _find_consent_button(self, driver, selectors: list, text_patterns: list):
        """Try 5 escalating strategies to find a consent button."""
        # 1. CSS selectors on main document
        for selector in selectors:
            try:
                for elem in driver.find_elements(By.CSS_SELECTOR, selector):
                    if elem.is_displayed():
                        return elem
            except Exception:
                continue

        # 2. Shadow DOM pierce (Usercentrics, Google FC, etc.)
        shadow_btn = self._find_in_shadow_dom(driver, text_patterns)
        if shadow_btn:
            return shadow_btn

        # 3. Broad text-pattern scan in main document
        result = self._text_scan(driver, text_patterns)
        if result:
            return result

        # 4. Search inside iframes (Google consent, TrustArc, Sourcepoint, etc.)
        #    driver may be left inside a frame when button is returned
        iframe_btn = self._find_in_iframes(driver, selectors, text_patterns)
        if iframe_btn:
            return iframe_btn

        # 5. Deep JS walk: visits every visible text node including shadow roots
        #    Highest-coverage fallback for custom / framework-rendered CMPs
        return self._js_deeptext_find(driver, text_patterns)

    def _safe_click(self, driver, element) -> bool:
        """Click element using up to 5 escalating strategies."""
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
            time.sleep(0.3)
        except Exception:
            pass

        # 1. Standard Selenium click
        try:
            element.click()
            return True
        except Exception:
            pass

        # 2. Remove pointer-events blocks, then click
        try:
            driver.execute_script(
                "arguments[0].style.pointerEvents='auto';"
                "arguments[0].style.zIndex='99999';",
                element,
            )
            element.click()
            return True
        except Exception:
            pass

        # 3. JavaScript click()
        try:
            driver.execute_script("arguments[0].click();", element)
            return True
        except Exception:
            pass

        # 4. Dispatch MouseEvent (works on React/Vue synthetic event handlers)
        try:
            driver.execute_script("""
                arguments[0].dispatchEvent(new MouseEvent('click', {
                    bubbles: true, cancelable: true, view: window
                }));
            """, element)
            return True
        except Exception:
            pass

        # 5. ActionChains move-and-click
        try:
            from selenium.webdriver.common.action_chains import ActionChains
            ActionChains(driver).move_to_element(element).click().perform()
            return True
        except Exception:
            pass

        return False

    # ── Page interaction helpers ──────────────

    def _simulate_page_interaction(self, driver, scroll_pause: float = 0.15) -> None:
        """
        Scroll the page gradually to trigger lazy-loaded trackers
        (Intersection Observer, infinite scroll, ad slots), then simulate
        mouse movement to activate hover-based and viewability trackers.
        """
        try:
            total_height = driver.execute_script("return document.body.scrollHeight")
        except Exception:
            total_height = 3000

        step = 350  # px per scroll step
        current = 0
        while current < total_height:
            current = min(current + step, total_height)
            try:
                driver.execute_script(f"window.scrollTo(0, {current});")
            except Exception:
                break
            time.sleep(scroll_pause)

        # Brief pause at bottom, then scroll back (some sites fire scroll-up events)
        time.sleep(0.4)
        try:
            driver.execute_script("window.scrollTo(0, 0);")
        except Exception:
            pass
        time.sleep(0.3)

        # Mouse movement — zigzag across the viewport to trigger hover trackers
        try:
            from selenium.webdriver.common.action_chains import ActionChains
            body = driver.find_element(By.TAG_NAME, "body")
            ac = ActionChains(driver)
            for ox, oy in [(-700, -300), (0, -200), (600, -100),
                           (-500, 100), (300, 200), (-200, 300)]:
                try:
                    ac.move_to_element_with_offset(body, ox, oy).pause(0.08)
                except Exception:
                    pass
            ac.perform()
        except Exception:
            pass

    def _extract_internal_links(self, driver, max_links: int = 3) -> list:
        """Return up to max_links unique same-domain/subdomain hrefs from current page.

        Uses driver.current_url as the reference (handles www. redirects) and
        matches on registered domain via tldextract so that:
          - subdomains like wiadomosci.onet.pl match onet.pl
          - co.uk / com.au / com.pl ccSLDs are handled correctly
        """
        from urllib.parse import urlparse as _up
        try:
            import tldextract as _tld
            def _reg(netloc: str) -> str:
                e = _tld.extract(netloc.split(":")[0])
                return f"{e.domain}.{e.suffix}" if e.suffix else e.domain
        except ImportError:
            # Fallback: last 2 labels (works for simple TLDs)
            def _reg(netloc: str) -> str:  # type: ignore[misc]
                host = netloc.lower().split(":")[0]
                parts = host.split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else host

        # Prefer the actual post-redirect URL over self.url
        try:
            ref_netloc = _up(driver.current_url).netloc or _up(self.url).netloc
        except Exception:
            ref_netloc = _up(self.url).netloc

        base_reg = _reg(ref_netloc)

        seen: set = set()
        links: list = []
        try:
            for a in driver.find_elements(By.TAG_NAME, "a"):
                href = (a.get_attribute("href") or "").strip()
                if not href or href.startswith(("#", "javascript", "mailto", "tel")):
                    continue
                parsed = _up(href)
                if not parsed.netloc:
                    continue
                # Accept exact match OR any subdomain of the registered domain
                if _reg(parsed.netloc) != base_reg:
                    continue
                path = parsed.path.rstrip("/")
                if not path:
                    continue
                norm = f"{parsed.scheme}://{parsed.netloc}{path}"
                current_base = ref_netloc
                if norm.rstrip("/") in (self.url.rstrip("/"),
                                        f"https://{current_base}",
                                        f"http://{current_base}"):
                    continue
                if norm not in seen:
                    seen.add(norm)
                    links.append(norm)
                    if len(links) >= max_links:
                        break
        except Exception:
            pass
        return links

    def _crawl_subpages(self, driver) -> None:
        """Visit (crawl_depth - 1) internal pages to widen HAR coverage."""
        n = self.crawl_depth - 1
        if n < 1:
            return
        links = self._extract_internal_links(driver, max_links=n)
        if not links:
            print("    [~] No internal links found for subpage crawl")
            return
        for link in links:
            print(f"    [~] Crawling subpage: {link}")
            try:
                driver.get(link)
                time.sleep(2)
                self._simulate_page_interaction(driver, scroll_pause=0.1)
            except Exception as exc:
                print(f"    [!] Subpage crawl error: {exc}")

    # ── Scenario capture ─────────────────────

    def _wait_network_idle(self, timeout: float = 20.0, idle_for: float = 2.0,
                           min_wait: float = 10.0) -> None:
        """
        Block until no new HAR entries arrive for *idle_for* seconds, or
        *timeout* seconds have elapsed.

        *min_wait* is a mandatory warm-up period before idle detection begins.
        This prevents a false-idle when the page does a full reload immediately
        after a consent click (e.g. wp.pl): the HAR has 0 entries for the first
        ~1-2 s while the redirect is in flight, which would otherwise trick the
        idle detector into finishing immediately with 0 captured requests.
        """
        # Mandatory warm-up — let any redirect/reload register its first requests
        time.sleep(min_wait)

        deadline = time.time() + max(0.0, timeout - min_wait)
        last_count = -1
        last_change = time.time()
        while time.time() < deadline:
            try:
                entries = self.proxy.har.get("log", {}).get("entries", [])
                count = len(entries)
            except Exception:
                break
            if count != last_count:
                last_count = count
                last_change = time.time()
            elif time.time() - last_change >= idle_for:
                break
            time.sleep(0.4)

    def _capture_scenario(self, label: str, action: str) -> dict:
        """
        Load page, interact with consent dialog (accept/reject/necessary),
        then capture HAR, cookies, and page HTML.
        """
        print(f"\n[*] Scenario: {label.upper()}")

        result: dict = {
            "label": label,
            "har": None,
            "cookies": [],
            "new_cookies": [],   # cookies set AFTER consent click (delta)
            "html": "",
            "consent_found": False,
        }

        def _click(btn) -> bool:
            """Click and always restore default content context."""
            ok = self._safe_click(driver, btn)
            try:
                driver.switch_to.default_content()
            except Exception:
                pass
            return ok

        driver, tmp_profile_dir = self._create_driver()

        _har_opts = {
            "captureHeaders": True,
            "captureContent": False,
            "captureBinaryContent": False,
        }
        try:
            # ── Phase 1: load page + interact with consent dialog ─────────────────
            # We keep an active HAR during page load so the proxy doesn't drop
            # connections, but we will discard its contents after the click.
            self.proxy.new_har(self.url, options=_har_opts)

            print(f"    Loading {self.url} ...")
            driver.get(self.url)
            self._detect_captcha(driver)
            # Dynamic wait for banner (up to 12 s); extra grace if nothing found
            appeared = self._wait_for_consent_banner(driver, timeout=12)
            if not appeared:
                print("    [~] No banner detected in 12 s – waiting 3 s more...")
                time.sleep(3)

            # Remove viewport-covering overlays that could block consent clicks
            self._remove_overlays(driver)

            # Snapshot of cookies that exist BEFORE any consent decision
            pre_consent_cookie_names: set[str] = {
                c["name"] for c in driver.get_cookies()
            }

            if action == "accept":
                btn = self._find_consent_button(
                    driver, ACCEPT_SELECTORS, ACCEPT_TEXT_PATTERNS
                )
                if btn:
                    print("    [+] Found ACCEPT button – clicking...")
                    if _click(btn):
                        result["consent_found"] = True
                        print("    [+] ACCEPT clicked successfully")
                else:
                    print("    [-] No ACCEPT button detected")

            elif action == "reject":
                btn = self._find_consent_button(
                    driver, REJECT_SELECTORS, REJECT_TEXT_PATTERNS
                )
                if btn:
                    print("    [+] Found REJECT button – clicking...")
                    if _click(btn):
                        result["consent_found"] = True
                        print("    [+] REJECT clicked successfully")
                else:
                    print("    [-] No direct REJECT button – trying two-step flow...")
                    mgr = self._find_consent_button(
                        driver, MANAGE_SELECTORS, MANAGE_TEXT_PATTERNS
                    )
                    if mgr:
                        print("    [+] Opened preferences panel – looking for reject...")
                        _click(mgr)
                        time.sleep(2)
                        btn2 = self._find_consent_button(
                            driver, REJECT_SELECTORS, REJECT_TEXT_PATTERNS
                        )
                        if btn2:
                            print("    [+] Found REJECT in panel – clicking...")
                            if _click(btn2):
                                result["consent_found"] = True
                                print("    [+] REJECT clicked (two-step)")
                        else:
                            print("    [-] No reject option in panel")
                    else:
                        # Last resort: necessary-only wording
                        btn = self._find_consent_button(
                            driver, NECESSARY_SELECTORS, NECESSARY_TEXT_PATTERNS
                        )
                        if btn:
                            print("    [+] Found 'necessary only' as reject fallback – clicking...")
                            if _click(btn):
                                result["consent_found"] = True

            elif action == "necessary":
                # 1. Try dedicated "necessary / essential only" selectors
                btn = self._find_consent_button(
                    driver, NECESSARY_SELECTORS, NECESSARY_TEXT_PATTERNS
                )
                if btn:
                    print("    [+] Found NECESSARY ONLY button – clicking...")
                    if _click(btn):
                        result["consent_found"] = True
                        print("    [+] NECESSARY clicked successfully")
                else:
                    print("    [-] No direct necessary-only button – trying two-step...")
                    mgr = self._find_consent_button(
                        driver, MANAGE_SELECTORS, MANAGE_TEXT_PATTERNS
                    )
                    if mgr:
                        print("    [+] Opened preferences panel – looking for necessary...")
                        _click(mgr)
                        time.sleep(2)
                        btn2 = self._find_consent_button(
                            driver, NECESSARY_SELECTORS, NECESSARY_TEXT_PATTERNS
                        )
                        if not btn2:
                            btn2 = self._find_consent_button(
                                driver, REJECT_SELECTORS, REJECT_TEXT_PATTERNS
                            )
                        if btn2:
                            print("    [+] Found necessary/reject in panel – clicking...")
                            if _click(btn2):
                                result["consent_found"] = True
                                print("    [+] NECESSARY clicked (two-step)")
                    else:
                        btn = self._find_consent_button(
                            driver, REJECT_SELECTORS, REJECT_TEXT_PATTERNS
                        )
                        if btn:
                            print("    [+] Using REJECT as necessary-fallback...")
                            if _click(btn):
                                result["consent_found"] = True

            # ── Screenshot when banner was not found (debug aid) ─────────────
            if not result["consent_found"]:
                try:
                    shot_path = os.path.join(
                        self.output_dir, f"screenshot_{label}_no_consent.png"
                    )
                    driver.save_screenshot(shot_path)
                    print(f"    [~] Consent NOT found – screenshot saved: {shot_path}")
                except Exception as _se:
                    print(f"    [~] Could not save screenshot: {_se}")

            # ── Phase 2: reset HAR and capture only post-consent traffic ──────────
            # After the consent decision the site fires (or withholds) trackers.
            # Resetting ensures we measure ONLY that differential traffic and not
            # the page's initial load or the consent-panel's own asset requests.
            self.proxy.new_har(self.url + "#post-consent", options=_har_opts)
            print(f"    [~] HAR reset – scrolling page (lazy-load trigger) + mouse simulation...")
            self._simulate_page_interaction(driver)
            if self.crawl_depth > 1:
                print(f"    [~] Crawl depth {self.crawl_depth}: visiting subpages...")
                self._crawl_subpages(driver)
            print(f"    [~] Waiting for network idle (max 20 s)...")
            # min_wait reduced to 5 s — scroll itself already takes ~3 s
            self._wait_network_idle(timeout=20.0, idle_for=2.0, min_wait=5.0)

            result["html"] = driver.page_source
            all_cookies = driver.get_cookies()
            result["cookies"] = all_cookies
            # Delta: only cookies that did NOT exist before the consent click
            result["new_cookies"] = [
                c for c in all_cookies
                if c["name"] not in pre_consent_cookie_names
            ]
            result["har"] = self.proxy.har

            entries = len(result["har"]["log"]["entries"])
            print(
                f"    Captured {entries} HAR entries | "
                f"{len(all_cookies)} cookies total | "
                f"{len(result['new_cookies'])} new after consent"
            )

        except Exception as exc:
            print(f"    [!] Error during scenario '{label}': {exc}")
        finally:
            try:
                driver.quit()
            except Exception:
                pass
            # Remove temporary Chrome/Edge profile directory
            if tmp_profile_dir and os.path.isdir(tmp_profile_dir):
                import shutil
                try:
                    shutil.rmtree(tmp_profile_dir, ignore_errors=True)
                except Exception:
                    pass

        return result

    # ── HAR / Cookie extraction ───────────────

    # Patterns that identify TCF consent-distribution / vendor-sync requests.
    # These are fired by the CMP AFTER reject to notify IAB vendors of the
    # refusal – they are NOT tracking the user, just propagating the signal.
    # We count them separately so they don't inflate the reject domain stats.
    _TCF_FLOOD_PATTERNS = re.compile(
        r"(gdpr_consent|euconsent|consent_string|tcf_string"
        r"|gdpr=1&gdpr_consent"
        r"|/rtd/\?gdpr"
        r"|/usync\?"
        r"|/cm\?.*gdpr"
        r"|/ms\?.*gdpr"
        r"|/match\?.*gdpr"
        r"|/cksync\.php"
        r"|/cookie-sync|/cookiesync"
        r"|/sync\?.*gdpr"
        r"|adtrafficquality\.google)",
        re.IGNORECASE,
    )

    def _domains_from_har(self, har: dict, filter_tcf: bool = False) -> Counter:
        domains: Counter = Counter()
        if not har:
            return domains
        for entry in har.get("log", {}).get("entries", []):
            try:
                url = entry["request"]["url"]
                if filter_tcf and self._TCF_FLOOD_PATTERNS.search(url):
                    continue
                netloc = urlparse(url).netloc.lower()
                if ":" in netloc:
                    netloc = netloc.rsplit(":", 1)[0]
                if netloc:
                    domains[netloc] += 1
            except Exception:
                continue
        return domains

    def _tcf_flood_count(self, har: dict) -> int:
        """Return number of HAR entries that look like TCF consent distribution."""
        if not har:
            return 0
        return sum(
            1 for e in har.get("log", {}).get("entries", [])
            if self._TCF_FLOOD_PATTERNS.search(e.get("request", {}).get("url", ""))
        )

    def _cookies_from_har(self, har: dict) -> list:
        cookies = []
        if not har:
            return cookies
        for entry in har.get("log", {}).get("entries", []):
            try:
                domain = urlparse(entry["request"]["url"]).netloc
                for hdr in entry.get("response", {}).get("headers", []):
                    if hdr.get("name", "").lower() == "set-cookie":
                        cookies.append({"domain": domain, "raw": hdr["value"]})
            except Exception:
                continue
        return cookies

    # ── HTML analysis ─────────────────────────

    def _analyze_html(self, accept_html: str, reject_html: str,
                       necessary_html: str = "") -> dict:
        diff: dict = {
            "accept_scripts": 0, "reject_scripts": 0, "necessary_scripts": 0,
            "accept_iframes": 0, "reject_iframes": 0, "necessary_iframes": 0,
            "accept_tracking_pixels": 0, "reject_tracking_pixels": 0,
            "necessary_tracking_pixels": 0,
            "accept_external_scripts": [], "reject_external_scripts": [],
            "necessary_external_scripts": [],
        }
        if not accept_html or not reject_html:
            return diff

        def parse(html: str):
            soup = BeautifulSoup(html, "lxml")
            scripts = soup.find_all("script", src=True)
            iframes = soup.find_all("iframe")
            pixels = [
                img for img in soup.find_all("img")
                if img.get("width") in ("0", "1") or img.get("height") in ("0", "1")
            ]
            external = [
                s["src"] for s in scripts
                if s.get("src", "").startswith("http")
            ]
            return len(scripts), len(iframes), len(pixels), external[:25]

        try:
            a_s, a_i, a_p, a_e = parse(accept_html)
            r_s, r_i, r_p, r_e = parse(reject_html)
            diff.update({
                "accept_scripts": a_s, "reject_scripts": r_s,
                "accept_iframes": a_i, "reject_iframes": r_i,
                "accept_tracking_pixels": a_p, "reject_tracking_pixels": r_p,
                "accept_external_scripts": a_e, "reject_external_scripts": r_e,
            })
            if necessary_html:
                n_s, n_i, n_p, n_e = parse(necessary_html)
                diff.update({
                    "necessary_scripts": n_s,
                    "necessary_iframes": n_i,
                    "necessary_tracking_pixels": n_p,
                    "necessary_external_scripts": n_e,
                })
        except Exception as exc:
            print(f"    [!] HTML analysis error: {exc}")

        return diff

    # ── Comparison & reporting ────────────────

    def _compare_scenarios(self, accept: dict, reject: dict, necessary: dict) -> dict:
        print("\n[*] Comparing scenarios...")

        accept_doms    = self._domains_from_har(accept["har"],    filter_tcf=True)
        reject_doms    = self._domains_from_har(reject["har"],    filter_tcf=True)
        necessary_doms = self._domains_from_har(necessary["har"], filter_tcf=True)

        accept_tcf_flood    = self._tcf_flood_count(accept["har"])
        reject_tcf_flood    = self._tcf_flood_count(reject["har"])
        necessary_tcf_flood = self._tcf_flood_count(necessary["har"])

        accept_cats:    dict[str, set] = defaultdict(set)
        reject_cats:    dict[str, set] = defaultdict(set)
        necessary_cats: dict[str, set] = defaultdict(set)

        for d in accept_doms:    accept_cats[self._categorize_domain(d)].add(d)
        for d in reject_doms:    reject_cats[self._categorize_domain(d)].add(d)
        for d in necessary_doms: necessary_cats[self._categorize_domain(d)].add(d)

        tracking_cats = {"advertising", "analytics", "social_media"}
        accept_tracking    = {d for d in accept_doms    if self._categorize_domain(d) in tracking_cats}
        reject_tracking    = {d for d in reject_doms    if self._categorize_domain(d) in tracking_cats}
        necessary_tracking = {d for d in necessary_doms if self._categorize_domain(d) in tracking_cats}

        # Domains that fire tracking requests despite reject/necessary-only consent.
        # These suggest potential GDPR non-compliance by the site.
        non_compliant_in_reject    = sorted(reject_tracking    - accept_tracking)
        non_compliant_in_necessary = sorted(necessary_tracking - accept_tracking)

        only_accept_doms    = sorted(set(accept_doms)    - set(reject_doms))
        only_reject_doms    = sorted(set(reject_doms)    - set(accept_doms))
        only_necessary_doms = sorted(set(necessary_doms) - set(reject_doms))

        accept_cookie_names    = {c["name"] for c in accept["cookies"]}
        reject_cookie_names    = {c["name"] for c in reject["cookies"]}
        necessary_cookie_names = {c["name"] for c in necessary["cookies"]}

        # "new" = cookies set only AFTER the consent click (delta captured per-scenario)
        accept_new_names    = {c["name"] for c in accept.get("new_cookies", [])}
        reject_new_names    = {c["name"] for c in reject.get("new_cookies", [])}
        necessary_new_names = {c["name"] for c in necessary.get("new_cookies", [])}

        accept_har_cook    = self._cookies_from_har(accept["har"])
        reject_har_cook    = self._cookies_from_har(reject["har"])
        necessary_har_cook = self._cookies_from_har(necessary["har"])

        html_diff = self._analyze_html(accept["html"], reject["html"], necessary["html"])

        accept_reqs    = len(accept["har"]["log"]["entries"])    if accept["har"]    else 0
        reject_reqs    = len(reject["har"]["log"]["entries"])    if reject["har"]    else 0
        necessary_reqs = len(necessary["har"]["log"]["entries"]) if necessary["har"] else 0

        return {
            "url": self.url,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "consent": {
                "accept_found":    accept["consent_found"],
                "reject_found":    reject["consent_found"],
                "necessary_found": necessary["consent_found"],
            },
            "requests": {
                "accept_total":              accept_reqs,
                "reject_total":              reject_reqs,
                "necessary_total":           necessary_reqs,
                "difference":                accept_reqs - reject_reqs,
                # TCF consent-distribution requests (vendor sync after reject/accept).
                # These inflate reject counts but don't represent user tracking.
                "accept_tcf_flood":          accept_tcf_flood,
                "reject_tcf_flood":          reject_tcf_flood,
                "necessary_tcf_flood":       necessary_tcf_flood,
                "reject_net_of_tcf":         reject_reqs - reject_tcf_flood,
            },
            "domains": {
                "accept_total":       len(accept_doms),
                "reject_total":       len(reject_doms),
                "necessary_total":    len(necessary_doms),
                "accept_tracking":    len(accept_tracking),
                "reject_tracking":    len(reject_tracking),
                "necessary_tracking": len(necessary_tracking),
                "only_in_accept":     only_accept_doms,
                "only_in_reject":     only_reject_doms,
                "only_in_necessary":  only_necessary_doms,
                # Tracking domains active despite reject/necessary: potential non-compliance
                "non_compliant_in_reject":    non_compliant_in_reject,
                "non_compliant_in_necessary": non_compliant_in_necessary,
                "accept_list":        sorted(accept_doms.keys()),
                "reject_list":        sorted(reject_doms.keys()),
                "necessary_list":     sorted(necessary_doms.keys()),
                "accept_categories":    {k: sorted(v) for k, v in accept_cats.items()},
                "reject_categories":    {k: sorted(v) for k, v in reject_cats.items()},
                "necessary_categories": {k: sorted(v) for k, v in necessary_cats.items()},
            },
            "cookies": {
                "accept_browser_count":    len(accept["cookies"]),
                "reject_browser_count":    len(reject["cookies"]),
                "necessary_browser_count": len(necessary["cookies"]),
                "accept_new_count":        len(accept_new_names),
                "reject_new_count":        len(reject_new_names),
                "necessary_new_count":     len(necessary_new_names),
                "accept_har_count":        len(accept_har_cook),
                "reject_har_count":        len(reject_har_cook),
                "necessary_har_count":     len(necessary_har_cook),
                "only_in_accept":    sorted(accept_cookie_names    - reject_cookie_names),
                "only_in_reject":    sorted(reject_cookie_names    - accept_cookie_names),
                "only_in_necessary": sorted(necessary_cookie_names - reject_cookie_names),
                "only_new_in_accept":    sorted(accept_new_names    - reject_new_names),
                "only_new_in_reject":    sorted(reject_new_names    - accept_new_names),
                "only_new_in_necessary": sorted(necessary_new_names - reject_new_names),
                "accept_cookie_list": [
                    {k: v for k, v in c.items() if k != "value"}
                    for c in accept["cookies"]
                ],
                "reject_cookie_list": [
                    {k: v for k, v in c.items() if k != "value"}
                    for c in reject["cookies"]
                ],
                "necessary_cookie_list": [
                    {k: v for k, v in c.items() if k != "value"}
                    for c in necessary["cookies"]
                ],
                "accept_cookie_details":    self._format_cookie_details(accept["cookies"]),
                "reject_cookie_details":    self._format_cookie_details(reject["cookies"]),
                "necessary_cookie_details": self._format_cookie_details(necessary["cookies"]),
            },
            "html": html_diff,
        }

    # ── Charts ────────────────────────────────

    _CAT_COLORS = {
        "advertising": "#FF6B6B",
        "analytics": "#4ECDC4",
        "social_media": "#45B7D1",
        "cdn_infrastructure": "#96CEB4",
        "other": "#FFD93D",
    }

    def _generate_charts(self, analysis: dict):
        # ── Chart 1: domain category pie charts ──
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        fig.suptitle(
            f"Cookie Impact Analysis\n{self.url}",
            fontsize=14, fontweight="bold",
        )

        def make_pie(ax, categories: dict, title: str):
            labels, sizes, colors = [], [], []
            for cat, domains in sorted(categories.items()):
                if not domains:
                    continue
                labels.append(f"{cat.replace('_', ' ').title()}\n({len(domains)})")
                sizes.append(len(domains))
                colors.append(self._CAT_COLORS.get(cat, "#CCCCCC"))

            if not sizes:
                ax.text(0.5, 0.5, "No data", ha="center", va="center",
                        transform=ax.transAxes, fontsize=12)
                ax.set_title(title)
                return

            wedges, texts, autotexts = ax.pie(
                sizes, labels=labels, colors=colors,
                autopct="%1.1f%%", startangle=90, pctdistance=0.82,
            )
            for t in texts:
                t.set_fontsize(9)
            for at in autotexts:
                at.set_fontsize(8)
                at.set_fontweight("bold")
            ax.set_title(title, fontsize=12, fontweight="bold", pad=14)

        dom = analysis["domains"]
        make_pie(
            axes[0], dom["accept_categories"],
            f"After ACCEPTING cookies\n({dom['accept_total']} unique domains)",
        )
        make_pie(
            axes[1], dom["reject_categories"],
            f"After REJECTING cookies\n({dom['reject_total']} unique domains)",
        )

        plt.tight_layout()
        pie_path = os.path.join(self.output_dir, "domain_categories.png")
        plt.savefig(pie_path, dpi=100, bbox_inches="tight")
        plt.close()
        print(f"\n[+] Chart saved: {pie_path}")

        # ── Chart 2: comparison bar chart ──
        fig, ax = plt.subplots(figsize=(9, 5))

        metrics = ["Total\nRequests", "Unique\nDomains", "Tracking\nDomains",
                   "Browser\nCookies", "HAR\nCookies"]
        req = analysis["requests"]
        cook = analysis["cookies"]
        accept_vals = [
            req["accept_total"], dom["accept_total"],
            dom["accept_tracking"], cook["accept_browser_count"],
            cook["accept_har_count"],
        ]
        reject_vals = [
            req["reject_total"], dom["reject_total"],
            dom["reject_tracking"], cook["reject_browser_count"],
            cook["reject_har_count"],
        ]

        x = range(len(metrics))
        w = 0.36
        bars1 = ax.bar(
            [i - w / 2 for i in x], accept_vals, w,
            label="Accept Cookies", color="#FF6B6B", alpha=0.85,
        )
        bars2 = ax.bar(
            [i + w / 2 for i in x], reject_vals, w,
            label="Reject Cookies", color="#4ECDC4", alpha=0.85,
        )

        for bar in list(bars1) + list(bars2):
            h = bar.get_height()
            ax.annotate(
                str(h),
                xy=(bar.get_x() + bar.get_width() / 2, h),
                xytext=(0, 3), textcoords="offset points",
                ha="center", va="bottom", fontsize=9,
            )

        ax.set_xlabel("Metric")
        ax.set_ylabel("Count")
        ax.set_title(f"Cookie Acceptance Impact – {self.url}")
        ax.set_xticks(list(x))
        ax.set_xticklabels(metrics)
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        plt.tight_layout()

        bar_path = os.path.join(self.output_dir, "comparison.png")
        plt.savefig(bar_path, dpi=100, bbox_inches="tight")
        plt.close()
        print(f"[+] Chart saved: {bar_path}")

    # ── Terminal report ───────────────────────

    def _print_report(self, a: dict):
        sep = "─" * 62
        print(f"\n{'═' * 62}")
        print(f"  ANALYSIS REPORT")
        print(f"  URL : {a['url']}")
        print(f"  Time: {a['timestamp']}")
        print(f"{'═' * 62}")

        # ── Privacy score ─────────────────────────────────────────────────
        ps = a.get("privacy_score", {})
        if ps:
            score  = ps.get("score", 0)
            grade  = ps.get("grade", "?")
            filled = score // 5
            bar    = "█" * filled + "░" * (20 - filled)
            if score >= 90:
                grade_tag = "A ✅"
            elif score >= 75:
                grade_tag = "B 🟢"
            elif score >= 60:
                grade_tag = "C 🟡"
            elif score >= 45:
                grade_tag = "D 🟠"
            else:
                grade_tag = "F 🔴"
            print(f"\n  PRIVACY SCORE")
            print(sep)
            print(f"  Score : {score:>3}/100  [{bar}]  Grade: {grade_tag}")
            if ps.get("reasons"):
                print(f"  Deductions:")
                for reason in ps["reasons"]:
                    print(f"    – {reason}")

        c = a["consent"]
        print(f"\n  CONSENT DETECTION")
        print(sep)
        print(f"  Accept button found : {'YES ✓' if c['accept_found'] else 'NO  ✗'}")
        print(f"  Reject button found : {'YES ✓' if c['reject_found'] else 'NO  ✗'}")

        req = a["requests"]
        diff = req["difference"]
        direction = (
            f"+{diff} more when accepting" if diff > 0
            else f"{abs(diff)} fewer when accepting" if diff < 0
            else "identical"
        )
        print(f"\n  NETWORK REQUESTS")
        print(sep)
        print(f"  After accepting : {req['accept_total']:>6}")
        print(f"  After rejecting : {req['reject_total']:>6}")
        print(f"  Difference      : {direction}")

        dom = a["domains"]
        print(f"\n  DOMAIN ANALYSIS")
        print(sep)
        print(f"  Unique domains   (accept / reject) : "
              f"{dom['accept_total']} / {dom['reject_total']}")
        print(f"  Tracking domains (accept / reject) : "
              f"{dom['accept_tracking']} / {dom['reject_tracking']}")

        for scenario_label, cats in (
            ("ACCEPT", dom["accept_categories"]),
            ("REJECT", dom["reject_categories"]),
        ):
            print(f"\n  Domain categories after {scenario_label}:")
            for cat, domains in sorted(cats.items()):
                if not domains:
                    continue
                print(f"    {cat.replace('_', ' ').title():<22} {len(domains):>4} domain(s)")
                for d in sorted(domains)[:6]:
                    print(f"      · {d}")
                if len(domains) > 6:
                    print(f"      … and {len(domains) - 6} more")

        if dom["only_in_accept"]:
            print(f"\n  Domains ONLY after accepting ({len(dom['only_in_accept'])}):")
            for d in sorted(dom["only_in_accept"])[:15]:
                cat     = self._categorize_domain(d)
                company = self._company_of(d)
                co_str  = f"  ↪ {company}" if company else ""
                print(f"    · {d}  [{cat}]{co_str}")
            if len(dom["only_in_accept"]) > 15:
                print(f"    … and {len(dom['only_in_accept']) - 15} more")

        cook = a["cookies"]
        print(f"\n  COOKIES")
        print(sep)
        print(f"  Browser cookies  (accept / reject) : "
              f"{cook['accept_browser_count']} / {cook['reject_browser_count']}")
        print(f"  HAR Set-Cookie   (accept / reject) : "
              f"{cook['accept_har_count']} / {cook['reject_har_count']}")

        if cook["only_in_accept"]:
            print(f"\n  Cookies ONLY set after accepting ({len(cook['only_in_accept'])}):")
            for name in cook["only_in_accept"][:20]:
                print(f"    · {name}")
            if len(cook["only_in_accept"]) > 20:
                print(f"    … and {len(cook['only_in_accept']) - 20} more")

        if cook["only_in_reject"]:
            print(f"\n  Cookies ONLY set after rejecting ({len(cook['only_in_reject'])}):")
            for name in cook["only_in_reject"][:10]:
                print(f"    · {name}")

        # ── Detailed cookie attributes ────────────────────────────────────
        details = cook.get("accept_cookie_details", [])
        if details:
            print(f"\n  COOKIE DETAILS – after ACCEPTING ({len(details)}):")
            print(f"  {'Name':<26} {'Domain':<24} {'Expires':<22} Sec  HTTP")
            print(f"  {'─'*26} {'─'*24} {'─'*22} ─── ────")
            for d in details[:25]:
                name_c    = (d.get('name',       '') or '?')[:25]
                domain_c  = (d.get('domain',     '') or '?')[:23]
                expiry_c  = (d.get('expiry_str', '') or '?')[:21]
                company_c = (d.get('company',    '') or '')[:40]
                sec_c     = '✓' if d.get('secure')   else '✗'
                http_c    = '✓' if d.get('httpOnly') else '✗'
                print(f"  {name_c:<26} {domain_c:<24} {expiry_c:<22} {sec_c:<4} {http_c}")
                if company_c:
                    print(f"  {'':26} └─ {company_c}")
            if len(details) > 25:
                print(f"  … and {len(details)-25} more (see analysis.json)")

        html = a["html"]
        print(f"\n  HTML CONTENT DIFF  (accept / reject)")
        print(sep)
        print(f"  <script> tags     : {html['accept_scripts']} / {html['reject_scripts']}")
        print(f"  <iframe> tags     : {html['accept_iframes']} / {html['reject_iframes']}")
        print(f"  Tracking pixels   : {html['accept_tracking_pixels']} / {html['reject_tracking_pixels']}")

        # ── GDPR / RODO violations ────────────────────────────────────────────
        gdpr = a.get("gdpr", {})
        if gdpr:
            overall = gdpr.get("overall_risk", "NONE")
            counts  = gdpr.get("severity_counts", {})
            risk_label = {
                "HIGH":   "🔴  HIGH",
                "MEDIUM": "🟡  MEDIUM",
                "LOW":    "🟢  LOW",
                "NONE":   "✅  NONE",
            }.get(overall, overall)
            print(f"\n  DETECTED GDPR VIOLATIONS")
            print(sep)
            print(f"  Overall risk level   : {risk_label}")
            print(f"  HIGH violations      : {counts.get('HIGH',   0)}")
            print(f"  MEDIUM violations    : {counts.get('MEDIUM', 0)}")
            print(f"  LOW violations       : {counts.get('LOW',    0)}")
            for v in gdpr.get("violations", []):
                sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                    v["severity"], "•"
                )
                print(f"\n  {sev_icon} [{v['severity']}] {v['title']}")
                print(f"     Legal basis : {v['article']}")
                # Word-wrap description at 58 chars
                desc = v["description"]
                while len(desc) > 58:
                    cut = desc.rfind(" ", 0, 58)
                    if cut < 0:
                        cut = 58
                    print(f"     {desc[:cut]}")
                    desc = desc[cut:].lstrip()
                if desc:
                    print(f"     {desc}")
                for ev in v.get("evidence", [])[:5]:
                    print(f"       · {ev}")
                if len(v.get("evidence", [])) > 5:
                    print(f"       … and {len(v['evidence'])-5} more (see JSON)")

        print(f"\n{'═' * 62}")
        print(f"  RESULTS SAVED TO:")
        print(f"  {self.output_dir}/")
        print(f"  ├── report_card.pdf         (A4 report card)")
        print(f"  ├── analysis.json          (full JSON report)")
        print(f"  ├── domain_categories.png  (domain pie charts)")
        print(f"  └── comparison.png         (comparison bar chart)")
        print(f"{'═' * 62}\n")

        # ── Fingerprinting ────────────────────────────────────────────────────
        fp = a.get("fingerprinting", {})
        if fp:
            fp_risk = fp.get("risk", "NONE")
            fp_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "✅"}.get(fp_risk, "•")
            sep = "─" * 62
            print(sep)
            print(f"  BROWSER FINGERPRINTING  –  risk: {fp_icon} {fp_risk}")
            print(sep)
            for line in fp.get("details", []):
                print(f"  {line}")
            print()

    # ── Cookie detail enrichment ──────────────────────────────────────────────

    def _format_cookie_details(self, cookies: list) -> list:
        """Return enriched cookie metadata dicts (no cookie values)."""
        result = []
        for c in cookies:
            expiry_ts = c.get("expiry")
            if expiry_ts:
                try:
                    expiry_dt = datetime.fromtimestamp(float(expiry_ts))
                    days_left = int((expiry_dt - datetime.now()).days)
                    expiry_str = expiry_dt.strftime("%Y-%m-%d %H:%M")
                    if days_left < 0:
                        expiry_str += " (expired)"
                    elif days_left == 0:
                        expiry_str += " (today)"
                    elif days_left > 365 * 2:
                        years = round(days_left / 365, 1)
                        expiry_str += f" (+{years}y)"
                    else:
                        expiry_str += f" (+{days_left}d)"
                except Exception:
                    expiry_str = str(expiry_ts)
                    days_left = None
            else:
                expiry_str = "Session"
                days_left = None

            result.append({
                "name":       c.get("name",     "?"),
                "domain":     c.get("domain",   "?"),
                "company":    self._company_of(c.get("domain", "")),
                "path":       c.get("path",     "/"),
                "secure":     bool(c.get("secure",   False)),
                "httpOnly":   bool(c.get("httpOnly", False)),
                "sameSite":   c.get("sameSite", "?"),
                "expiry_ts":  expiry_ts,
                "expiry_str": expiry_str,
                "days_left":  days_left,
            })
        result.sort(key=lambda x: (x["name"] or "").lower())
        return result

    # ── Privacy score ─────────────────────────────────────────────────────────

    def _compute_privacy_score(self, analysis: dict) -> dict:
        """Compute a 0–100 privacy score with grade and deduction reasons."""
        score = 100
        reasons: list[str] = []

        cons = analysis.get("consent", {})
        dom  = analysis.get("domains", {})
        cook = analysis.get("cookies", {})
        gdpr = analysis.get("gdpr",    {})

        # ── Consent banner ───────────────────────────────────────────────────
        if not cons.get("accept_found") and not cons.get("reject_found"):
            if dom.get("accept_tracking", 0) > 0:
                score -= 15
                reasons.append("No consent banner with active trackers (-15)")
        else:
            if not cons.get("reject_found"):
                score -= 20
                reasons.append("No reject button found (-20)")
            if not cons.get("necessary_found"):
                score -= 10
                reasons.append("No 'necessary only' option found (-10)")

        # ── Non-compliant tracking after reject ──────────────────────────────
        nc = dom.get("non_compliant_in_reject", [])
        if nc:
            deduct = min(25, len(nc) * 5)
            score -= deduct
            reasons.append(
                f"Tracking domains active after rejecting consent: {len(nc)} (-{deduct})"
            )

        # ── Excessive trackers on accept ─────────────────────────────────────
        acc_track = dom.get("accept_tracking", 0)
        if acc_track >= 10:
            deduct = min(20, (acc_track // 5) * 5)
            score -= deduct
            reasons.append(
                f"Excessive trackers after accepting: {acc_track} (-{deduct})"
            )

        # ── Cookie security flags ─────────────────────────────────────────────
        details = cook.get("accept_cookie_details", [])
        insecure  = [d["name"] for d in details if not d.get("secure")]
        no_http   = [d["name"] for d in details if not d.get("httpOnly")]
        long_exp  = [
            d["name"] for d in details
            if d.get("days_left") is not None and d["days_left"] > 365
        ]

        if insecure:
            deduct = min(10, len(insecure))
            score -= deduct
            reasons.append(
                f"Cookies missing Secure flag: {len(insecure)} (-{deduct})"
            )
        if no_http:
            deduct = min(10, len(no_http))
            score -= deduct
            reasons.append(
                f"Cookies missing HttpOnly flag: {len(no_http)} (-{deduct})"
            )
        if long_exp:
            deduct = min(10, len(long_exp))
            score -= deduct
            reasons.append(
                f"Cookies with expiry >1 year: {len(long_exp)} (-{deduct})"
            )

        # ── GDPR overall risk ─────────────────────────────────────────────────
        overall = gdpr.get("overall_risk", "NONE")
        if overall == "HIGH":
            score -= 20
            reasons.append("GDPR violations detected – HIGH risk (-20)")
        elif overall == "MEDIUM":
            score -= 10
            reasons.append("GDPR violations detected – MEDIUM risk (-10)")
        elif overall == "LOW":
            score -= 5
            reasons.append("GDPR violations detected – LOW risk (-5)")

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 45:
            grade = "D"
        else:
            grade = "F"

        return {"score": score, "grade": grade, "reasons": reasons}

    # ── Browser fingerprinting detection ─────────────────────────────────────

    # Known fingerprinting domains / services
    _FP_DOMAINS: set[str] = {
        # Canvas / font / WebGL fingerprinters
        "fingerprintjs.com", "fingerprint.com", "fpjs.io", "fpcdn.io",
        "clientjs.com",
        # Device / behaviour analytics that heavily use fingerprinting
        "threatmetrix.com", "iovation.com", "iovation.net",
        "deviceatlas.com", "scientiamobile.com",
        # Session-replay / heatmap tools known for FP
        "sessioncam.com", "smartlook.com", "hotjar.com",
        "clarity.ms", "mouseflow.com", "fullstory.com",
        "logrocket.com", "inspectlet.com",
        # Ad-fraud / bot-detection that collect FP signals
        "perimeterx.com", "px-cdn.net", "px-cloud.net",
        "datadome.co", "kasada.io", "anura.io",
        "fraudscore.com", "ipqualityscore.com",
        # Cross-site tracking with strong FP component
        "tapad.com", "id5-sync.com", "netid.de",
        "adnxs.com", "adkernel.com",
    }

    # Known advertising / header-bidding script name fragments.
    # Checked against reject_external_scripts to catch ad libraries loaded
    # despite consent being rejected.
    _AD_SCRIPT_PATTERNS: tuple[str, ...] = (
        "pbjs", "prebid",                        # Prebid.js (header bidding)
        "googletag", "gpt.js", "adsbygoogle",   # Google Publisher Tags
        "apstag.js", "amazon-apstag",            # Amazon Advertising
        "criteo", "taboola", "outbrain",        # demand/content networks
        "gemius", "gemhit",                      # Gemius (PL measurement)
        "/adv/", "/ads/", "/ad.",               # generic ad paths
        "doubleclick", "adsrvr",                 # DoubleClick / TTD
        "smartadserver", "teads",               # other ad servers
    )

    # JS APIs exploited by fingerprinting scripts
    _FP_JS_PATTERNS: list[str] = [
        "canvas.toblob", "canvas.todataurl",          # canvas FP
        "getimagedata",                                 # canvas pixel read
        "webglrenderingcontext",                        # WebGL FP
        "webgl2renderingcontext",
        "getextension",                                 # WebGL extension enum
        "audiocontext", "oscillatornode",               # AudioContext FP
        "navigator.plugins",                           # plugin enum
        "navigator.mimetypes",
        "screen.colordepth", "screen.pixeldepth",     # screen FP
        "devicepixelratio",
        "navigator.hardwareconcurrency",               # hardware FP
        "navigator.devicememory",
        "navigator.languages",                         # locale FP
        "intl.datetimeformat",                         # timezone FP
        "navigator.connection",                        # network FP
        "window.performance.memory",                   # memory FP
        "speechsynthesis.getvoices",                  # TTS voice enum
        "document.fonts",                              # font enum
        "fontsloadingevent",
        "css.supports",                                # CSS feature detection
        "__fp_", "_fingerprint", "fingerprintjs",      # JS variable names
        "fpjs", "fpagent", "visitorid",               # FP library artifacts
    ]

    def _detect_fingerprinting(self, analysis: dict, accept_html: str = "",
                                reject_html: str = "") -> dict:
        """
        Heuristically detect browser fingerprinting attempts.

        Three signal sources are combined:
          1. HAR domains matched against known fingerprinting services.
          2. Inline / external JS source scanned for fingerprinting API calls.
          3. Number of distinct signal sources detected.

        Returns a dict with:
          domains  – list of FP-linked domains contacted
          signals  – list of JS API patterns found in page source
          risk     – "HIGH" | "MEDIUM" | "LOW" | "NONE"
          details  – human-readable list of findings
        """
        findings_domains: list[str] = []
        findings_signals: list[str] = []

        # ── 1. Domain check (from HAR) ────────────────────────────────────────
        dom = analysis.get("domains", {})
        all_contacted = set(dom.get("accept_list", []) + dom.get("reject_list", []) +
                            dom.get("necessary_list", []))
        for d in all_contacted:
            d_lower = d.lower().lstrip(".")
            for fp_d in self._FP_DOMAINS:
                if d_lower == fp_d or d_lower.endswith("." + fp_d):
                    if d_lower not in findings_domains:
                        findings_domains.append(d_lower)

        # ── 2. JS / HTML source scan ──────────────────────────────────────────
        combined_src = (accept_html + " " + reject_html).lower()
        for pat in self._FP_JS_PATTERNS:
            if pat in combined_src:
                findings_signals.append(pat)

        # ── 3. Risk level ─────────────────────────────────────────────────────
        total = len(findings_domains) + len(findings_signals)
        if total == 0:
            risk = "NONE"
        elif len(findings_domains) >= 2 or total >= 8:
            risk = "HIGH"
        elif len(findings_domains) >= 1 or total >= 4:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        details: list[str] = []
        if findings_domains:
            details.append(f"Known fingerprinting services contacted: {', '.join(findings_domains[:10])}")
        if findings_signals:
            details.append(f"Fingerprinting JS APIs detected ({len(findings_signals)}): "
                           f"{', '.join(findings_signals[:8])}")
        if not details:
            details.append("No fingerprinting indicators detected.")

        return {
            "domains":  findings_domains,
            "signals":  findings_signals,
            "risk":     risk,
            "details":  details,
        }

    # ── GDPR / RODO violation detection ──────────────────────────────────────

    def _detect_gdpr_violations(self, analysis: dict) -> dict:
        """
        Analyse the comparison result and flag potential GDPR (RODO) violations.

        Returns a dict with:
          violations      – list of {severity, article, title, description, evidence}
          severity_counts – {HIGH, MEDIUM, LOW}
          overall_risk    – "HIGH" | "MEDIUM" | "LOW" | "NONE"
          compliant       – bool (True only when no violations detected)
        """
        violations: list[dict] = []
        dom  = analysis.get("domains",  {})
        cook = analysis.get("cookies",  {})
        req  = analysis.get("requests", {})
        cons = analysis.get("consent",  {})

        def add(severity: str, article: str, title: str,
                description: str, evidence: list | None = None):
            violations.append({
                "severity":    severity,
                "article":     article,
                "title":       title,
                "description": description,
                "evidence":    evidence or [],
            })

        # ── HIGH: Tracking domains active after reject ───────────────────────
        nc_reject = dom.get("non_compliant_in_reject", [])
        if nc_reject:
            add(
                "HIGH",
                "Art. 6 & 7 GDPR",
                "Tracking domains active after rejecting consent",
                (
                    f"Detected {len(nc_reject)} tracking domains sending "
                    "network requests after cookies are rejected. This may violate "
                    "Art. 6 GDPR (no legal basis for processing) and "
                    "Art. 7(3) GDPR (withdrawal of consent not respected)."
                ),
                nc_reject[:20],
            )

        # ── HIGH: Tracking cookies set by browser after reject ───────────────
        tracking_cookie_names_reject: list[str] = []
        tracking_cats = {"advertising", "analytics", "social_media"}
        for c in cook.get("reject_cookie_list", []):
            domain = c.get("domain", "").lstrip(".")
            if domain and self._categorize_domain(domain) in tracking_cats:
                tracking_cookie_names_reject.append(
                    f"{c.get('name', '?')} @ {domain}"
                )
        if tracking_cookie_names_reject:
            add(
                "HIGH",
                "Art. 6 GDPR",
                "Tracking cookies set after rejecting consent",
                (
                    f"The browser accepted {len(tracking_cookie_names_reject)} "
                    "tracking cookies despite consent being rejected. Setting "
                    "such cookies without a valid legal basis violates "
                    "Art. 6 GDPR."
                ),
                tracking_cookie_names_reject[:20],
            )

        # ── HIGH: Accept found but reject missing ────────────────────────────
        if cons.get("accept_found") and not cons.get("reject_found"):
            add(
                "HIGH",
                "Art. 7(3) GDPR",
                "No reject button found",
                (
                    "A consent accept button was found, but no reject button was detected. "
                    "The ability to withdraw consent must be as easy as giving it "
                    "(Art. 7(3) GDPR)."
                ),
            )

        # ── MEDIUM: No consent banner at all ─────────────────────────────────
        if not cons.get("accept_found") and not cons.get("reject_found"):
            acc_track = dom.get("accept_tracking", 0)
            if acc_track > 0:
                add(
                    "MEDIUM",
                    "Art. 7 GDPR / ePrivacy Directive",
                    "No consent banner detected despite tracker activity",
                    (
                        f"No consent buttons were found, yet the site "
                        f"contacts {acc_track} tracking domains. "
                        "If no other consent mechanism exists, "
                        "this may violate Art. 7 GDPR."
                    ),
                )

        # ── MEDIUM: Tracking domains active on necessary-only ─────────────────
        nc_necessary = dom.get("non_compliant_in_necessary", [])
        if nc_necessary:
            add(
                "MEDIUM",
                "Art. 6 GDPR",
                "Tracking domains active on 'necessary only' selection",
                (
                    f"When choosing 'necessary cookies only', "
                    f"{len(nc_necessary)} tracking domains were still active. "
                    "Possible processing of data without a legal basis "
                    "under Art. 6 GDPR."
                ),
                nc_necessary[:20],
            )

        # ── MEDIUM: No necessary-only option ─────────────────────────────────
        if cons.get("accept_found") and not cons.get("necessary_found"):
            add(
                "MEDIUM",
                "Art. 7 GDPR / ePrivacy",
                "No 'necessary cookies only' option available",
                (
                    "No option to restrict consent to necessary cookies was found. "
                    "Users should be able to use the service "
                    "without consenting to non-essential cookies."
                ),
            )

        # ── LOW: Disproportionate number of trackers (data minimisation) ──────
        acc_track = dom.get("accept_tracking", 0)
        rej_track = dom.get("reject_tracking", 0)
        if acc_track >= 10 and acc_track > rej_track * 5:
            add(
                "LOW",
                "Art. 5(1)(c) GDPR",
                "Excessive number of tracking domains after accepting",
                (
                    f"After accepting, the site engages {acc_track} tracking domains "
                    f"({acc_track - rej_track} more than after rejecting). "
                    "The data minimisation principle (Art. 5(1)(c) GDPR) "
                    "may be violated when consent covers disproportionate processing."
                ),
                [
                    f"Tracking domains after accepting:  {acc_track}",
                    f"Tracking domains after rejecting: {rej_track}",
                ],
            )

        # ── LOW: Elevated network activity after reject ───────────────────────
        rej_reqs = req.get("reject_total", 0)
        rej_tcf  = req.get("reject_tcf_flood", 0)
        rej_net  = max(0, rej_reqs - rej_tcf)
        acc_reqs = req.get("accept_total", 0)
        if rej_net >= 20 and acc_reqs > 0 and rej_net > acc_reqs * 0.35:
            add(
                "LOW",
                "Art. 6 GDPR",
                "Elevated network activity after rejecting consent",
                (
                    f"After rejecting consent, {rej_net} net network requests were recorded "
                    f"(after subtracting {rej_tcf} TCF requests). "
                    "High activity may suggest data processing "
                    "without an adequate legal basis."
                ),
                [
                    f"Requests after rejecting (net): {rej_net}",
                    f"TCF requests (consent sync):    {rej_tcf}",
                    f"Requests after accepting:       {acc_reqs}",
                ],
            )

        # ── HIGH: Tracking pixels active after reject ──────────────────────
        html = analysis.get("html", {})
        reject_pixels = html.get("reject_tracking_pixels", 0)
        if reject_pixels > 0:
            add(
                "HIGH",
                "Art. 6 GDPR",
                "Tracking pixels active after rejecting consent",
                (
                    f"Detected {reject_pixels} tracking pixel(s) (1×1 or 0×0 px "
                    "images) present in the page after consent was rejected. "
                    "Tracking pixels typically transmit user identifiers to third-"
                    "party servers without a valid legal basis, violating Art. 6 GDPR."
                ),
                [f"Tracking pixels counted in reject scenario: {reject_pixels}"],
            )

        # ── MEDIUM: Tracking pixels active on necessary-only ─────────────────
        necessary_pixels = html.get("necessary_tracking_pixels", 0)
        if necessary_pixels > 0:
            add(
                "MEDIUM",
                "Art. 6 GDPR / Art. 5(1)(c) GDPR",
                "Tracking pixels active on 'necessary-only' selection",
                (
                    f"Detected {necessary_pixels} tracking pixel(s) even when the "
                    "user selected 'necessary cookies only'. Processing user data "
                    "via tracking pixels without consent may violate Art. 6 GDPR."
                ),
                [f"Tracking pixels counted in necessary-only scenario: {necessary_pixels}"],
            )

        # ── HIGH: Known advertising scripts loaded after reject ───────────────
        reject_scripts = html.get("reject_external_scripts", [])
        ad_scripts_in_reject = [
            s for s in reject_scripts
            if any(pat in s.lower() for pat in self._AD_SCRIPT_PATTERNS)
        ]
        if ad_scripts_in_reject:
            add(
                "HIGH",
                "Art. 6 & 7(3) GDPR",
                "Known advertising/tracking scripts loaded after rejecting consent",
                (
                    f"Detected {len(ad_scripts_in_reject)} recognisable advertising "
                    "or tracking script(s) still loaded after consent was rejected. "
                    "Loading such scripts implies continued user tracking without a "
                    "valid legal basis (Art. 6 GDPR) and disregard for withdrawal of "
                    "consent (Art. 7(3) GDPR)."
                ),
                [s.split("?")[0][:120] for s in ad_scripts_in_reject[:10]],
            )

        counts = Counter(v["severity"] for v in violations)
        if counts["HIGH"]:
            overall = "HIGH"
        elif counts["MEDIUM"]:
            overall = "MEDIUM"
        elif counts["LOW"]:
            overall = "LOW"
        else:
            overall = "NONE"

        return {
            "violations": violations,
            "severity_counts": {
                "HIGH":   counts["HIGH"],
                "MEDIUM": counts["MEDIUM"],
                "LOW":    counts["LOW"],
            },
            "overall_risk": overall,
            "compliant":    overall == "NONE",
        }

    # ── A4 Report Card ────────────────────────────────────────────────────────

    def _generate_report_card(self, analysis: dict) -> str:
        """
        Generate a one-page A4 PDF 'report card' that visually summarises the
        entire analysis.  Returns the path to the created file.
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm, cm
        from reportlab.lib import colors
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether, Image as RLImage,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


        # ── palette (Catppuccin Mocha-ish) ────────────────────────────────────
        BG       = HexColor("#1e1e2e")
        SURFACE  = HexColor("#313244")
        OVERLAY  = HexColor("#45475a")
        TEXT     = HexColor("#cdd6f4")
        GREEN    = HexColor("#a6e3a1")
        YELLOW   = HexColor("#f9e2af")
        BLUE     = HexColor("#89b4fa")
        RED      = HexColor("#f38ba8")
        CYAN     = HexColor("#89dceb")
        MAUVE    = HexColor("#cba6f7")
        PINK     = HexColor("#f5c2e7")
        ROSEWATER= HexColor("#f5e0dc")

        W, H = A4          # 595.27 x 841.89 pts
        MARGIN = 18 * mm

        pdf_path = os.path.join(self.output_dir, "report_card.pdf")

        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=MARGIN, bottomMargin=MARGIN,
        )

        styles = getSampleStyleSheet()

        def S(name, **kw) -> ParagraphStyle:
            base = styles["Normal"]
            return ParagraphStyle(name, parent=base, **kw)

        story = []

        # ─────────────────────────────────────────────────────────────────────
        # helpers
        # ─────────────────────────────────────────────────────────────────────

        def hr(color=OVERLAY, thickness=0.5, space_before=4, space_after=4):
            story.append(HRFlowable(
                width="100%", thickness=thickness,
                color=color, spaceAfter=space_after, spaceBefore=space_before,
            ))

        def stat_cell(label, value, color=BLUE):
            """Create a 2-row table cell: large coloured number + small label."""
            return Table(
                [
                    [Paragraph(f'<font size="22" color="#{color.hexval()}">'
                               f'<b>{value}</b></font>',
                               ParagraphStyle("sv", alignment=TA_CENTER, leading=24))],
                    [Paragraph(f'<font size="7.5" color="#{OVERLAY.hexval()}">{label}</font>',
                               ParagraphStyle("sl", alignment=TA_CENTER, leading=10))],
                ],
                colWidths=["100%"],
                style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
                    ("ROWPADDINGS", (0, 0), (-1, -1), 4),
                    ("TOPPADDING",  (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING",(0,-1),(-1,-1), 8),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]),
            )

        # ─────────────────────────────────────────────────────────────────────
        # pull data
        # ─────────────────────────────────────────────────────────────────────
        url   = analysis.get("url", "")
        ts    = analysis.get("timestamp", "")[:19]
        dom   = analysis.get("domains",  {})
        cook  = analysis.get("cookies",  {})
        req   = analysis.get("requests", {})
        cons  = analysis.get("consent",  {})
        gdpr  = analysis.get("gdpr",     {})
        ps    = analysis.get("privacy_score", {})
        html  = analysis.get("html",     {})

        score = ps.get("score", 0)
        grade = ps.get("grade", "?")
        ps_reasons = ps.get("reasons", [])
        overall_risk = gdpr.get("overall_risk", "NONE")
        violations   = gdpr.get("violations",  [])

        GRADE_COLORS = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": YELLOW, "F": RED}
        RISK_COLORS  = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN, "NONE": GREEN}
        RISK_LABELS  = {"HIGH": "HIGH ▲", "MEDIUM": "MEDIUM !", "LOW": "LOW ▼", "NONE": "NONE ✓"}
        grade_color  = GRADE_COLORS.get(grade, BLUE)
        risk_color   = RISK_COLORS.get(overall_risk, BLUE)

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 1 – Header
        # ─────────────────────────────────────────────────────────────────────
        content_w = W - 2 * MARGIN

        # top bar table: [URL + timestamp | grade badge | GDPR badge]
        grade_text = f"{score}/100  {grade}"
        risk_text  = RISK_LABELS.get(overall_risk, overall_risk)

        header_data = [[
            Table(
                [
                    [Paragraph(f'<font name="Helvetica-Bold" size="14" color="#{MAUVE.hexval()}">'
                               f'🍪 CIAhO</font>',
                               ParagraphStyle("ht", leading=18))],
                    [Paragraph(f'<font size="10" color="#{TEXT.hexval()}">{url}</font>',
                               ParagraphStyle("hu", leading=13))],
                    [Paragraph(f'<font size="7.5" color="#{OVERLAY.hexval()}">Analysis: {ts}</font>',
                               ParagraphStyle("hts", leading=10))],
                ],
                colWidths=["100%"],
                style=TableStyle([("LEFTPADDING",(0,0),(-1,-1),0),
                                  ("RIGHTPADDING",(0,0),(-1,-1),0),
                                  ("TOPPADDING",(0,0),(-1,-1),1),
                                  ("BOTTOMPADDING",(0,0),(-1,-1),1)]),
            ),
            # Privacy Score badge
            Table(
                [
                    [Paragraph(f'<font name="Helvetica-Bold" size="28" color="#{grade_color.hexval()}">'
                               f'{score}</font>',
                               ParagraphStyle("gs", alignment=TA_CENTER, leading=32))],
                    [Paragraph(f'<font size="7" color="#{OVERLAY.hexval()}">/100 – Privacy Score</font>',
                               ParagraphStyle("gl", alignment=TA_CENTER, leading=9))],
                    [Paragraph(f'<font name="Helvetica-Bold" size="18" color="#{grade_color.hexval()}">'
                               f'{grade}</font>',
                               ParagraphStyle("gg", alignment=TA_CENTER, leading=22))],
                ],
                colWidths=["100%"],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                    ("ALIGN",(0,0),(-1,-1),"CENTER"),
                    ("TOPPADDING",(0,0),(-1,-1),4),
                    ("BOTTOMPADDING",(0,0),(-1,-1),4),
                    ("ROUNDEDCORNERS",[4,4,4,4]),
                ]),
            ),
            # GDPR badge
            Table(
                [
                    [Paragraph(f'<font size="7.5" color="#{OVERLAY.hexval()}">GDPR Risk</font>',
                               ParagraphStyle("rl", alignment=TA_CENTER, leading=10))],
                    [Paragraph(f'<font name="Helvetica-Bold" size="13" color="#{risk_color.hexval()}">'
                               f'{risk_text}</font>',
                               ParagraphStyle("rv", alignment=TA_CENTER, leading=16))],
                    [Paragraph(f'<font size="7.5" color="#{OVERLAY.hexval()}">'
                               f'{gdpr.get("severity_counts",{}).get("HIGH",0)} high / '
                               f'{gdpr.get("severity_counts",{}).get("MEDIUM",0)} med. / '
                               f'{gdpr.get("severity_counts",{}).get("LOW",0)} low</font>',
                               ParagraphStyle("rc", alignment=TA_CENTER, leading=10))],
                ],
                colWidths=["100%"],
                style=TableStyle([
                    ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                    ("ALIGN",(0,0),(-1,-1),"CENTER"),
                    ("TOPPADDING",(0,0),(-1,-1),4),
                    ("BOTTOMPADDING",(0,0),(-1,-1),4),
                ]),
            ),
        ]]

        col_w = [content_w * 0.52, content_w * 0.24, content_w * 0.24]
        header_tbl = Table(header_data, colWidths=col_w,
                           style=TableStyle([
                               ("BACKGROUND",(0,0),(-1,-1),BG),
                               ("LEFTPADDING",(0,0),(-1,-1),0),
                               ("RIGHTPADDING",(0,0),(-1,-1),6),
                               ("TOPPADDING",(0,0),(-1,-1),0),
                               ("BOTTOMPADDING",(0,0),(-1,-1),0),
                               ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                           ]))
        story.append(header_tbl)
        story.append(Spacer(1, 5))
        hr(MAUVE, thickness=1.5, space_before=2, space_after=6)

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 2 – Stat cards (3 + 3)
        # ─────────────────────────────────────────────────────────────────────
        story.append(Paragraph("Comparative statistics (Accept / Reject)",
                               S("SH", fontSize=9, textColor=MAUVE, fontName="Helvetica-Bold",
                                 spaceBefore=2, spaceAfter=4)))

        stat_w = content_w / 6

        acc_req = req.get("accept_total",    0)
        rej_req = req.get("reject_total",    0)
        acc_trk = dom.get("accept_tracking", 0)
        rej_trk = dom.get("reject_tracking", 0)
        acc_ck  = cook.get("accept_browser_count", 0)
        rej_ck  = cook.get("reject_browser_count", 0)

        def delta_color(a, b):
            return RED if a > b else GREEN if a < b else BLUE

        stats_row = [[
            stat_cell("Net requests\n(accept)",  acc_req, delta_color(acc_req, rej_req)),
            stat_cell("Net requests\n(reject)",  rej_req, delta_color(rej_req, acc_req)),
            stat_cell("Trackers\n(accept)",      acc_trk, delta_color(acc_trk, rej_trk)),
            stat_cell("Trackers\n(reject)",      rej_trk, delta_color(rej_trk, acc_trk)),
            stat_cell("Cookies\n(accept)",       acc_ck,  delta_color(acc_ck,  rej_ck)),
            stat_cell("Cookies\n(reject)",       rej_ck,  delta_color(rej_ck,  acc_ck)),
        ]]
        stats_tbl = Table(stats_row,
                          colWidths=[stat_w] * 6,
                          style=TableStyle([
                              ("LEFTPADDING", (0,0),(-1,-1), 3),
                              ("RIGHTPADDING",(0,0),(-1,-1), 3),
                              ("TOPPADDING",  (0,0),(-1,-1), 0),
                              ("BOTTOMPADDING",(0,0),(-1,-1),0),
                              ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                          ]))
        story.append(stats_tbl)
        story.append(Spacer(1, 6))
        hr(space_before=2, space_after=4)

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 3 – Consent banner status + Pie chart side by side
        # ─────────────────────────────────────────────────────────────────────
        story.append(Paragraph("Consent banner & Domain categories",
                               S("SH2", fontSize=9, textColor=MAUVE, fontName="Helvetica-Bold",
                                 spaceBefore=2, spaceAfter=4)))

        # Consent column
        def yes_no(val):
            col = GREEN if val else RED
            txt = "YES ✓" if val else "NO ✗"
            return Paragraph(
                f'<font name="Helvetica-Bold" size="8.5" color="#{col.hexval()}">{txt}</font>',
                ParagraphStyle("yn", alignment=TA_LEFT))

        consent_data = [
            [Paragraph('<font size="8" color="#45475a">ACCEPT button</font>',
                       ParagraphStyle("cl")), yes_no(cons.get("accept_found"))],
            [Paragraph('<font size="8" color="#45475a">REJECT button</font>',
                       ParagraphStyle("cl")), yes_no(cons.get("reject_found"))],
            [Paragraph('<font size="8" color="#45475a">NECESSARY option</font>',
                       ParagraphStyle("cl")), yes_no(cons.get("necessary_found"))],
        ]
        consent_tbl = Table(consent_data,
                            colWidths=[content_w * 0.18, content_w * 0.10],
                            style=TableStyle([
                                ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                                ("LEFTPADDING",(0,0),(-1,-1),6),
                                ("RIGHTPADDING",(0,0),(-1,-1),6),
                                ("TOPPADDING",(0,0),(-1,-1),4),
                                ("BOTTOMPADDING",(0,0),(-1,-1),4),
                                ("ROWBACKGROUNDS",(0,0),(-1,-1),[SURFACE, BG]),
                            ]))

        # HTML diff column
        html_data = [
            [Paragraph('<font size="8" color="#45475a">Scripts &lt;script&gt;</font>',
                       ParagraphStyle("hd")),
             Paragraph(f'<font size="8.5" color="#{TEXT.hexval()}">'
                       f'{html.get("accept_scripts",0)} / {html.get("reject_scripts",0)}</font>',
                       ParagraphStyle("hv"))],
            [Paragraph('<font size="8" color="#45475a">Frames &lt;iframe&gt;</font>',
                       ParagraphStyle("hd")),
             Paragraph(f'<font size="8.5" color="#{TEXT.hexval()}">'
                       f'{html.get("accept_iframes",0)} / {html.get("reject_iframes",0)}</font>',
                       ParagraphStyle("hv"))],
            [Paragraph('<font size="8" color="#45475a">Tracking pixels</font>',
                       ParagraphStyle("hd")),
             Paragraph(f'<font size="8.5" color="#{RED.hexval()}">'
                       f'{html.get("accept_tracking_pixels",0)} / '
                       f'{html.get("reject_tracking_pixels",0)}</font>',
                       ParagraphStyle("hv"))],
        ]
        html_tbl = Table(html_data,
                         colWidths=[content_w * 0.17, content_w * 0.10],
                         style=TableStyle([
                             ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                             ("LEFTPADDING",(0,0),(-1,-1),6),
                             ("RIGHTPADDING",(0,0),(-1,-1),6),
                             ("TOPPADDING",(0,0),(-1,-1),4),
                             ("BOTTOMPADDING",(0,0),(-1,-1),4),
                             ("ROWBACKGROUNDS",(0,0),(-1,-1),[SURFACE, BG]),
                         ]))

        # Pie chart PNG (right column)
        pie_path = os.path.join(self.output_dir, "domain_categories.png")
        mid_col_w = content_w * 0.45

        left_cell = Table(
            [[consent_tbl], [Spacer(1, 6)], [html_tbl]],
            colWidths=[content_w * 0.30],
            style=TableStyle([
                ("LEFTPADDING",(0,0),(-1,-1),0),
                ("RIGHTPADDING",(0,0),(-1,-1),0),
                ("TOPPADDING",(0,0),(-1,-1),0),
                ("BOTTOMPADDING",(0,0),(-1,-1),0),
            ]),
        )

        if os.path.isfile(pie_path):
            chart_img = RLImage(pie_path, width=mid_col_w, height=mid_col_w * 0.42)
            mid_row = Table([[left_cell, chart_img]],
                            colWidths=[content_w * 0.32, mid_col_w],
                            style=TableStyle([
                                ("LEFTPADDING",(0,0),(-1,-1),0),
                                ("RIGHTPADDING",(0,0),(-1,-1),6),
                                ("TOPPADDING",(0,0),(-1,-1),0),
                                ("BOTTOMPADDING",(0,0),(-1,-1),0),
                                ("VALIGN",(0,0),(-1,-1),"TOP"),
                            ]))
        else:
            mid_row = left_cell

        story.append(mid_row)
        story.append(Spacer(1, 6))
        hr(space_before=2, space_after=4)

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 4 – Cookie Details table (accept scenario, top 18)
        # ─────────────────────────────────────────────────────────────────────
        story.append(Paragraph("Cookie details – after ACCEPTING",
                               S("SH3", fontSize=9, textColor=MAUVE, fontName="Helvetica-Bold",
                                 spaceBefore=2, spaceAfter=4)))

        details = cook.get("accept_cookie_details", [])
        if details:
            cw = [content_w * r for r in [0.21, 0.19, 0.18, 0.20, 0.08, 0.07, 0.07]]
            hdr_row = [
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">Name</font>',
                          ParagraphStyle("ch", alignment=TA_LEFT)),
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">Domain</font>',
                          ParagraphStyle("ch")),
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">Company</font>',
                          ParagraphStyle("ch")),
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">Expires</font>',
                          ParagraphStyle("ch")),
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">Sec</font>',
                          ParagraphStyle("ch", alignment=TA_CENTER)),
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">HTTP</font>',
                          ParagraphStyle("ch", alignment=TA_CENTER)),
                Paragraph('<font name="Helvetica-Bold" size="7.5" color="#cba6f7">SameSite</font>',
                          ParagraphStyle("ch")),
            ]
            ck_rows = [hdr_row]
            for d in details[:18]:
                def ck_cell(txt, color=TEXT):
                    return Paragraph(
                        f'<font size="7" color="#{color.hexval()}">{txt}</font>',
                        ParagraphStyle("ck", leading=9))

                sec_col  = GREEN if d.get("secure")   else RED
                http_col = GREEN if d.get("httpOnly") else RED
                sec_sym  = "✓" if d.get("secure")   else "✗"
                http_sym = "✓" if d.get("httpOnly") else "✗"
                company  = (d.get("company", "") or "–")[:22]
                name     = (d.get("name",    "") or "?")[:26]
                domain   = (d.get("domain",  "") or "?")[:24]
                expiry   = (d.get("expiry_str","") or "?")[:22]
                samesite = (d.get("sameSite","") or "?")[:10]

                ck_rows.append([
                    ck_cell(name),
                    ck_cell(domain, CYAN),
                    ck_cell(company, PINK),
                    ck_cell(expiry, YELLOW),
                    Paragraph(f'<font name="Helvetica-Bold" size="8" color="#{sec_col.hexval()}">'
                              f'{sec_sym}</font>',
                              ParagraphStyle("sc", alignment=TA_CENTER)),
                    Paragraph(f'<font name="Helvetica-Bold" size="8" color="#{http_col.hexval()}">'
                              f'{http_sym}</font>',
                              ParagraphStyle("hc", alignment=TA_CENTER)),
                    ck_cell(samesite, BLUE),
                ])

            ck_style = [
                ("BACKGROUND",(0,0),(-1,0),BG),
                ("BACKGROUND",(0,1),(-1,-1),SURFACE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[SURFACE, BG]),
                ("LEFTPADDING",(0,0),(-1,-1),4),
                ("RIGHTPADDING",(0,0),(-1,-1),4),
                ("TOPPADDING",(0,0),(-1,-1),2),
                ("BOTTOMPADDING",(0,0),(-1,-1),2),
                ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                ("LINEBELOW",(0,0),(-1,0),0.5,OVERLAY),
            ]
            ck_tbl = Table(ck_rows, colWidths=cw,
                           style=TableStyle(ck_style))
            story.append(ck_tbl)
            if len(details) > 18:
                story.append(Paragraph(
                    f'<font size="7" color="#{OVERLAY.hexval()}">'
                    f'… and {len(details)-18} more cookies – see analysis.json</font>',
                    ParagraphStyle("more", spaceBefore=2)))
        else:
            story.append(Paragraph(
                '<font size="8" color="#45475a">No cookie data available.</font>',
                ParagraphStyle("nc", spaceBefore=4)))

        story.append(Spacer(1, 6))
        hr(space_before=2, space_after=4)

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 5 – GDPR violations
        # ─────────────────────────────────────────────────────────────────────
        story.append(Paragraph("Detected GDPR violations",
                               S("SH4", fontSize=9, textColor=MAUVE, fontName="Helvetica-Bold",
                                 spaceBefore=2, spaceAfter=4)))

        if not violations:
            story.append(Paragraph(
                '<font name="Helvetica-Bold" size="9" color="#a6e3a1">'
                '✓ No GDPR violations detected based on network traffic analysis.</font>',
                ParagraphStyle("ok", spaceBefore=2)))
        else:
            SEV_COL = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}
            viol_rows = []
            for v in violations[:8]:
                sev   = v.get("severity", "LOW")
                col   = SEV_COL.get(sev, BLUE)
                title = v.get("title", "")[:70]
                art   = v.get("article", "")
                desc  = v.get("description", "")[:130]
                evid  = "; ".join(str(e) for e in v.get("evidence", [])[:3])[:90]

                sev_cell = Paragraph(
                    f'<font name="Helvetica-Bold" size="7.5" color="#{col.hexval()}">{sev}</font>',
                    ParagraphStyle("vc", alignment=TA_CENTER))
                title_cell = Paragraph(
                    f'<font name="Helvetica-Bold" size="7.5" color="#{TEXT.hexval()}">{title}</font>'
                    f'<br/><font size="6.5" color="#{MAUVE.hexval()}">{art}</font>'
                    f'<br/><font size="6.5" color="#{OVERLAY.hexval()}">{desc[:120]}</font>'
                    + (f'<br/><font size="6" color="#{CYAN.hexval()}">↪ {evid}</font>' if evid else ""),
                    ParagraphStyle("vd", leading=9))
                viol_rows.append([sev_cell, title_cell])

            viol_tbl = Table(viol_rows,
                             colWidths=[content_w * 0.10, content_w * 0.90],
                             style=TableStyle([
                                 ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                                 ("ROWBACKGROUNDS",(0,0),(-1,-1),[SURFACE, BG]),
                                 ("LEFTPADDING",(0,0),(-1,-1),5),
                                 ("RIGHTPADDING",(0,0),(-1,-1),5),
                                 ("TOPPADDING",(0,0),(-1,-1),4),
                                 ("BOTTOMPADDING",(0,0),(-1,-1),4),
                                 ("VALIGN",(0,0),(0,-1),"MIDDLE"),
                                 ("VALIGN",(1,0),(1,-1),"TOP"),
                             ]))
            story.append(viol_tbl)

        story.append(Spacer(1, 6))
        hr(space_before=2, space_after=4)

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 6 – Privacy Score breakdown + top tracking domains
        # ─────────────────────────────────────────────────────────────────────
        # Two columns: score reasons | tracking domains
        score_lines = []
        for r_txt in (ps_reasons or ["No deductions – full score"]):
            score_lines.append(
                Paragraph(f'<font size="7.5" color="#{TEXT.hexval()}">– {r_txt}</font>',
                          ParagraphStyle("sl2", leading=11, spaceBefore=1))
            )

        only_accept = dom.get("only_in_accept", [])[:10]
        track_lines = []
        for d in only_accept:
            company = self._company_of(d)
            co_str  = f" [{company}]" if company else ""
            cat     = self._categorize_domain(d)
            track_lines.append(
                Paragraph(
                    f'<font size="7" color="#{CYAN.hexval()}">{d}</font>'
                    f'<font size="6.5" color="#{PINK.hexval()}">{co_str}</font>'
                    f' <font size="6" color="#{OVERLAY.hexval()}">[{cat}]</font>',
                    ParagraphStyle("tl", leading=10, spaceBefore=1))
            )

        col_a_content = [
            Paragraph(f'<font name="Helvetica-Bold" size="8.5" color="#{MAUVE.hexval()}">'
                      f'Privacy Score – deductions</font>',
                      ParagraphStyle("psh", leading=12, spaceAfter=4)),
        ] + score_lines

        col_b_content = [
            Paragraph(f'<font name="Helvetica-Bold" size="8.5" color="#{MAUVE.hexval()}">'
                      f'Domains ONLY after accepting (top {len(only_accept)})</font>',
                      ParagraphStyle("tth", leading=12, spaceAfter=4)),
        ] + (track_lines if track_lines else [
            Paragraph('<font size="7.5" color="#45475a">No additional domains.</font>',
                      ParagraphStyle("td"))
        ])

        bottom_cols = Table(
            [[
                Table([[p] for p in col_a_content],
                      colWidths=[content_w * 0.47],
                      style=TableStyle([
                          ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                          ("LEFTPADDING",(0,0),(-1,-1),8),
                          ("RIGHTPADDING",(0,0),(-1,-1),8),
                          ("TOPPADDING",(0,0),(-1,-1),6),
                          ("BOTTOMPADDING",(0,0),(-1,-1),2),
                      ])),
                Spacer(content_w * 0.03, 1),
                Table([[p] for p in col_b_content],
                      colWidths=[content_w * 0.47],
                      style=TableStyle([
                          ("BACKGROUND",(0,0),(-1,-1),SURFACE),
                          ("LEFTPADDING",(0,0),(-1,-1),8),
                          ("RIGHTPADDING",(0,0),(-1,-1),8),
                          ("TOPPADDING",(0,0),(-1,-1),6),
                          ("BOTTOMPADDING",(0,0),(-1,-1),2),
                      ])),
            ]],
            colWidths=[content_w * 0.48, content_w * 0.04, content_w * 0.48],
            style=TableStyle([
                ("LEFTPADDING",(0,0),(-1,-1),0),
                ("RIGHTPADDING",(0,0),(-1,-1),0),
                ("TOPPADDING",(0,0),(-1,-1),0),
                ("BOTTOMPADDING",(0,0),(-1,-1),0),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
            ])
        )
        story.append(bottom_cols)
        story.append(Spacer(1, 8))

        # ─────────────────────────────────────────────────────────────────────
        # SECTION 7 – Footer
        # ─────────────────────────────────────────────────────────────────────
        hr(MAUVE, thickness=0.8, space_before=2, space_after=3)
        footer_txt = (
            f'<font size="6.5" color="#{OVERLAY.hexval()}">'
            f'Generated by CIAhO • {ts} • {url} • '
            f'Results are for informational purposes only and do not constitute legal advice.'
            f'</font>'
        )
        story.append(Paragraph(footer_txt, ParagraphStyle("ft", alignment=TA_CENTER, leading=9)))

        # ─────────────────────────────────────────────────────────────────────
        # Build PDF with dark background via canvas callback
        # ─────────────────────────────────────────────────────────────────────
        def _on_page(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(BG)
            canvas.rect(0, 0, W, H, fill=1, stroke=0)
            canvas.restoreState()

        doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
        print(f"[+] Report card saved: {pdf_path}")
        return pdf_path

    # ── JSON export ───────────────────────────

    def _save_json(self, analysis: dict):
        path = os.path.join(self.output_dir, "analysis.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(analysis, fh, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved: {path}")

    # ── Public entry point ────────────────────

    def analyze(self) -> dict:
        print(f"\n{'═' * 62}")
        print(f"  CIAhO")
        print(f"  URL: {self.url}")
        print(f"{'═' * 62}")

        self._start_proxy()
        try:
            accept_result    = self._capture_scenario("accept",    "accept")
            time.sleep(2)
            reject_result    = self._capture_scenario("reject",    "reject")
            time.sleep(2)
            necessary_result = self._capture_scenario("necessary", "necessary")
        finally:
            self._stop_proxy()

        analysis = self._compare_scenarios(accept_result, reject_result, necessary_result)
        analysis["gdpr"] = self._detect_gdpr_violations(analysis)
        analysis["privacy_score"] = self._compute_privacy_score(analysis)
        analysis["fingerprinting"] = self._detect_fingerprinting(
            analysis,
            accept_html=accept_result.get("html", ""),
            reject_html=reject_result.get("html", ""),
        )
        self._generate_charts(analysis)
        self._print_report(analysis)
        self._save_json(analysis)
        self._generate_report_card(analysis)
        _save_to_db(analysis)
        return analysis


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

def _print_ranking(results: list[dict]) -> None:
    """Print a summary ranking table for a multi-URL batch run."""
    if not results:
        return
    sep = "═" * 68
    print(f"\n{sep}")
    print(f"  RANKING  –  {len(results)} site(s) analysed")
    print(sep)
    # Sort by privacy score descending, failed ones at the bottom
    ok   = [r for r in results if r.get("score") is not None]
    fail = [r for r in results if r.get("score") is None]
    ok.sort(key=lambda r: r["score"], reverse=True)
    ranked = ok + fail

    GRADE_ICON = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟡", "F": "🔴"}
    RISK_ICON  = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "✅"}
    FP_ICON    = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "✅"}

    print(f"  {'#':<3} {'Site':<32} {'Score':<7} {'Grade':<7} {'GDPR':<8} {'FP':<6}")
    print(f"  {'─'*3} {'─'*32} {'─'*7} {'─'*7} {'─'*8} {'─'*6}")
    for i, r in enumerate(ranked, 1):
        url   = r.get("url", "?")[:31]
        score = r.get("score")
        grade = r.get("grade", "?")
        gdpr  = r.get("gdpr_risk", "?")
        fp    = r.get("fp_risk",   "?")
        if score is None:
            print(f"  {i:<3} {url:<32} {'ERROR':<7} {'–':<7} {'–':<8} {'–':<6}")
        else:
            gi = GRADE_ICON.get(grade, "•")
            ri = RISK_ICON.get(gdpr, "•")
            fi = FP_ICON.get(fp, "•")
            print(f"  {i:<3} {url:<32} {score:<7} {gi} {grade:<5} {ri} {gdpr:<6} {fi} {fp}")
    print(sep)
    if ok:
        best  = ok[0]
        worst = ok[-1]
        print(f"  🏆 Best  : {best['url']}  (score {best['score']}, grade {best['grade']})")
        if len(ok) > 1:
            print(f"  ⚠️  Worst : {worst['url']}  (score {worst['score']}, grade {worst['grade']})")
    print(f"{sep}\n")


def main():
    banner = r"""
  ╔═══════════════════════════════════════════╗
  ║              CIAhO  v1.0                  ║
  ║  Compares traffic after accept/reject     ║
  ╚═══════════════════════════════════════════╝"""
    print(banner)

    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("url", nargs="?", default=None,
                        help="URL or comma-separated URLs to analyse")
    parser.add_argument("--browser", choices=["chrome", "firefox", "edge"], default=None)
    parser.add_argument("--binary", default=None)
    parser.add_argument("--list", metavar="FILE",
                        help="Path to a .txt file with one URL per line")
    parser.add_argument("--report", action="store_true",
                        help="Show cross-site company tracker ranking from database and exit")
    parser.add_argument("--crawl-depth", type=int, default=1, metavar="N",
                        help="Pages to crawl per scenario: 1=homepage only, 2-3=follow internal links")
    args, _unknown = parser.parse_known_args()

    # ── Cross-site report mode ────────────────────────────────────────────────
    if args.report:
        _print_company_ranking()
        sys.exit(0)

    # ── Build URL list ────────────────────────────────────────────────────────
    urls: list[str] = []

    if args.list:
        txt_path = args.list
        if not os.path.isfile(txt_path):
            print(f"[ERROR] File not found: {txt_path}")
            sys.exit(1)
        with open(txt_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        if not urls:
            print(f"[ERROR] No URLs found in {txt_path}")
            sys.exit(1)
        print(f"[*] Loaded {len(urls)} URL(s) from {txt_path}")

    elif args.url:
        # Support comma-separated URLs on the command line
        urls = [u.strip() for u in args.url.split(",") if u.strip()]

    if not urls:
        raw = input("  Enter website address(es) (comma-separated, e.g. bbc.com, cnn.com): ").strip()
        if not raw:
            print("  No address provided. Exiting.")
            sys.exit(1)
        urls = [u.strip() for u in raw.split(",") if u.strip()]

    _check_java()
    _ensure_bmp()

    if args.browser:
        btype = args.browser
        if args.binary:
            binary = args.binary
        elif btype == "firefox":
            binary = _resolve_real_firefox() or _resolve_binary(_FALLBACK_FIREFOX)
        elif btype == "edge":
            binary = _resolve_binary(_FALLBACK_EDGE)
        else:
            binary = _resolve_binary(_FALLBACK_CHROME)
        if not binary:
            print(f"[ERROR] Binary not found for {btype}.")
            sys.exit(1)
        print(f"[+] Forced {btype.upper()}: {binary}")
        browser_type, browser_binary = btype, binary
    else:
        browser_type, browser_binary = _detect_default_browser()

    # ── Analyse each URL ──────────────────────────────────────────────────────
    batch_results: list[dict] = []
    timestamp_batch = datetime.now().strftime("%Y%m%d_%H%M%S")

    for idx, website in enumerate(urls, 1):
        if len(urls) > 1:
            print(f"\n[*] ({idx}/{len(urls)}) Analysing: {website}")

        normalized = website if "://" in website else "https://" + website
        netloc = urlparse(normalized).netloc or website
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", netloc)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.abspath(f"output_{safe}_{timestamp}")
        print(f"  Results will be saved to: {output_dir}/\n")

        entry: dict = {"url": netloc or website, "score": None, "grade": None,
                       "gdpr_risk": None, "fp_risk": None, "output_dir": output_dir}
        try:
            analyzer = CookieAnalyzer(website, output_dir=output_dir,
                                       browser_type=browser_type,
                                       browser_binary=browser_binary,
                                       crawl_depth=args.crawl_depth)
            result = analyzer.analyze()
            ps = result.get("privacy_score", {})
            entry["score"]     = ps.get("score")
            entry["grade"]     = ps.get("grade")
            entry["gdpr_risk"] = result.get("gdpr", {}).get("overall_risk", "NONE")
            entry["fp_risk"]   = result.get("fingerprinting", {}).get("risk", "NONE")
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user.")
            break
        except Exception as exc:
            print(f"\n[ERROR] {exc}")
            import traceback
            traceback.print_exc()

        batch_results.append(entry)

    if len(urls) > 1:
        _print_ranking(batch_results)
        # Save ranking JSON next to the first output dir
        ranking_path = os.path.abspath(f"ranking_{timestamp_batch}.json")
        with open(ranking_path, "w", encoding="utf-8") as fh:
            json.dump(batch_results, fh, indent=2, ensure_ascii=False)
        print(f"[+] Ranking saved: {ranking_path}")

    # ── Always show cross-site company summary if DB has >=2 sites ───────────
    _print_company_ranking()


if __name__ == "__main__":
    main()
