# feeds.py
"""
Feed fetchers for the Mini Threat-Intelligence Platform.

- URLhaus (recent): tries CSV first, then falls back to the text feed.
- Spamhaus: DROP, EDROP, and DROPv6 (CIDR lists).

Each fetch_* function returns a list of normalized "indicator" dicts:
{
  "type": "url" | "ip" | "domain" | "cidr",
  "value": "...",
  "source": "urlhaus" | "spamhaus-drop" | "spamhaus-edrop" | "spamhaus-dropv6",
  "first_seen": "YYYY-MM-DDTHH:MM:SSZ",
  "last_seen":  "YYYY-MM-DDTHH:MM:SSZ",
  "tags": "comma,separated",
  "confidence": int (0-100),
  "status": "active" | "inactive",
}
"""

from datetime import datetime, timezone
import csv
import io
import requests

# ---- URLhaus ----
# CSV (recent) and plain-text (recent) endpoints
URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_RECENT_TXT = "https://urlhaus.abuse.ch/downloads/text_recent/"

# ---- Spamhaus ----
SPAMHAUS_DROP   = "https://www.spamhaus.org/drop/drop.txt"     # IPv4 CIDRs
SPAMHAUS_EDROP  = "https://www.spamhaus.org/drop/edrop.txt"    # IPv4 (extended) CIDRs
SPAMHAUS_DROPV6 = "https://www.spamhaus.org/drop/dropv6.txt"   # IPv6 CIDRs

REQUEST_TIMEOUT = 25  # seconds
UA = "mini-tip/0.1 (+https://github.com/alexv199/mini-tip; educational)"  # change if you like


def _utc_now_iso() -> str:
    """UTC timestamp in ISO 8601 with 'Z' suffix."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# -----------------------------
# URLhaus helpers / main fetcher
# -----------------------------
def _parse_urlhaus_csv(text: str) -> list[dict]:
    """
    Parse URLhaus CSV content.
    Skips comment lines beginning with '#', normalizes headers to lowercase.
    """
    # Keep only non-comment lines; header appears after the banner comments.
    rows = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not rows:
        return []

    reader = csv.DictReader(io.StringIO("\n".join(rows)))
    out: list[dict] = []

    for row in reader:
        # Some columns may vary in case; normalize keys
        low = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }

        url = low.get("url") or ""
        if not url:
            continue

        dateadded = low.get("dateadded") or low.get("firstseen") or _utc_now_iso()
        status_field = (low.get("url_status") or low.get("status") or "").lower()
        status = "inactive" if status_field == "offline" else "active"

        out.append({
            "type": "url",
            "value": url,
            "source": "urlhaus",
            "first_seen": dateadded,
            "last_seen": dateadded,
            "tags": low.get("tags", ""),
            "confidence": 80,
            "status": status,
        })
    return out


def _parse_urlhaus_text(text: str) -> list[dict]:
    """
    Parse URLhaus text feed: one URL per line, '#' lines are comments.
    """
    out: list[dict] = []
    now = _utc_now_iso()
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("http://") or s.startswith("https://"):
            out.append({
                "type": "url",
                "value": s,
                "source": "urlhaus",
                "first_seen": now,
                "last_seen": now,
                "tags": "",
                "confidence": 80,
                "status": "active",
            })
    return out


def fetch_urlhaus_recent() -> list[dict]:
    """
    Try URLhaus CSV first; if we parse 0 rows, fall back to the text feed.
    Raises for HTTP errors; returns [] if no indicators parsed.
    """
    headers = {
        "User-Agent": UA,
        "Accept": "text/csv, text/plain;q=0.9, */*;q=0.8",
    }

    # Attempt CSV
    r = requests.get(URLHAUS_RECENT_CSV, headers=headers, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()

    # If a block page (HTML) ever appears, bail clearly rather than silently returning 0.
    first = r.text.lstrip().lower()
    if first.startswith("<!doctype") or first.startswith("<html"):
        raise RuntimeError("URLhaus returned HTML (possible block page).")

    indicators = _parse_urlhaus_csv(r.text)
    if indicators:
        return indicators

    # Fallback: plain-text feed
    r2 = requests.get(URLHAUS_RECENT_TXT, headers=headers, timeout=REQUEST_TIMEOUT)
    r2.raise_for_status()
    return _parse_urlhaus_text(r2.text)


# -----------------------------
# Spamhaus helpers / main fetch
# -----------------------------
def _parse_spamhaus_text(text: str, source_name: str) -> list[dict]:
    """
    Parse Spamhaus DROP/EDROP/DROPv6 lists.
    Lines look like: "203.0.113.0/24 ; SBL123456 Description"
    Lines starting with ';' are comments.
    """
    indicators: list[dict] = []
    now = _utc_now_iso()
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith(";"):
            continue
        # First token on the line is the CIDR
        cidr = raw.split()[0]
        if "/" not in cidr:
            continue
        indicators.append({
            "type": "cidr",
            "value": cidr,
            "source": source_name,
            "first_seen": now,
            "last_seen": now,
            "tags": "drop-list",
            "confidence": 70,
            "status": "active",
        })
    return indicators


def fetch_spamhaus_all() -> list[dict]:
    """
    Fetch Spamhaus DROP, EDROP, and DROPv6 lists and return CIDR indicators.
    """
    headers = {"User-Agent": UA, "Accept": "text/plain"}
    indicators: list[dict] = []

    for url, name in [
        (SPAMHAUS_DROP,   "spamhaus-drop"),
        (SPAMHAUS_EDROP,  "spamhaus-edrop"),
        (SPAMHAUS_DROPV6, "spamhaus-dropv6"),
    ]:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        indicators.extend(_parse_spamhaus_text(resp.text, name))

    return indicators
