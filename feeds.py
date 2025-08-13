# feeds.py
import csv
import io
import re
import requests
from datetime import datetime, timezone

# --- URLhaus ---
# We'll use the "recent CSV" which lists recent malicious URLs.
URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# --- Spamhaus ---
# DROP (IPv4), EDROP (IPv4), and DROPv6 (IPv6) CIDR lists.
SPAMHAUS_DROP = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP = "https://www.spamhaus.org/drop/edrop.txt"
SPAMHAUS_DROPV6 = "https://www.spamhaus.org/drop/dropv6.txt"

REQUEST_TIMEOUT = 25  # seconds

def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def fetch_urlhaus_recent():
    """
    Downloads the recent CSV and yields normalized indicator dicts for 'url'.
    CSV has many '#' commented lines at the top. We skip them.
    """
    resp = requests.get(URLHAUS_RECENT_CSV, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    # The CSV contains a header after the comment block.
    # We'll find the first non-comment line to feed into csv.DictReader.
    text = resp.text
    # Remove the leading commented lines:
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    if not lines:
        return []

    csv_text = "\n".join(lines)
    reader = csv.DictReader(io.StringIO(csv_text))
    indicators = []
    for row in reader:
        # Common fields: dateadded,url,threat,host,url_status,rtir_id,tags,...
        url = row.get("url") or row.get("URL") or ""
        if not url:
            continue
        dateadded = row.get("dateadded") or _utc_now_iso()
        tags = row.get("tags", "")
        status = "active" if (row.get("url_status","").lower() != "offline") else "inactive"

        indicators.append({
            "type": "url",
            "value": url.strip(),
            "source": "urlhaus",
            "first_seen": dateadded,
            "last_seen": dateadded,
            "tags": tags,
            "confidence": 80,  # arbitrary default higher than 50
            "status": status
        })
    return indicators

def _parse_spamhaus_text(text: str, source_name: str):
    """
    Parses Spamhaus DROP style lists.
    Lines look like:
      203.0.113.0/24 ; SBL123456 Example
    Lines starting with ';' are comments.
    We return 'cidr' indicators.
    """
    indicators = []
    now = _utc_now_iso()
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith(";"):
            continue
        # The CIDR is the first token on the line
        cidr = raw.split()[0]
        # Basic validation: CIDR pattern (IPv4 or IPv6)
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
            "status": "active"
        })
    return indicators

def fetch_spamhaus_all():
    """
    Fetches DROP, EDROP, and DROPv6.
    Note: Spamhaus terms restrict redistribution; personal research use is OK.
    """
    indicators = []
    for url, name in [
        (SPAMHAUS_DROP, "spamhaus-drop"),
        (SPAMHAUS_EDROP, "spamhaus-edrop"),
        (SPAMHAUS_DROPV6, "spamhaus-dropv6"),
    ]:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        indicators.extend(_parse_spamhaus_text(resp.text, name))
    return indicators
