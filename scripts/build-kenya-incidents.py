#!/usr/bin/env python3
"""Build a daily Kenya OSINT incident snapshot from GDELT Events 2.0."""
import concurrent.futures
import io
import json
import os
import time
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
OUT_JSON = os.path.join(DATA_DIR, "kenya_incidents.json")
OUT_JS = os.path.join(DATA_DIR, "kenya_incidents.js")
BASE = "https://data.gdeltproject.org/gdeltv2/"
MANIFEST = BASE + "lastupdate.txt"
UA = "BulwarkKenyaOSINT/1.0 (+https://bulwark.co.ke)"
WINDOW_FILES = 96
MAX_EVENTS = 180
ACLED_URL = "https://api.acleddata.com/acled/read"

CATEGORY_LABELS = {
    "theft": "Theft / property",
    "cyber": "Cyber",
    "protest": "Protest",
    "conflict": "Armed conflict",
    "assault": "Assault",
    "coercion": "Coercion",
    "incident": "Conflict incident",
}

EVENT_LABELS = {
    "171": "Seize or damage property",
    "1711": "Confiscate property",
    "1712": "Destroy property",
    "173": "Arrest, detain, or charge",
    "175": "Violent repression",
    "176": "Cyber attack",
    "18": "Assault",
    "182": "Physical assault",
    "1821": "Sexual assault",
    "1822": "Torture",
    "1823": "Kill by physical assault",
    "183": "Bombing",
    "185": "Attempt to assassinate",
    "186": "Assassinate",
    "19": "Fight",
    "190": "Fight",
    "191": "Unconventional mass violence",
    "192": "Conventional military force",
    "193": "Small arms or light weapons",
    "194": "Artillery or heavy weapons",
    "195": "Explosion or remote violence",
    "20": "Mass violence",
}


def display_name(value):
    text = str(value or "").strip()
    if text and text.isupper():
        return text.title()
    return text or "unidentified actor"



def fetch_bytes(url):
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=90) as resp:
                return resp.read()
        except Exception as ex:
            last = ex
            time.sleep(attempt + 1)
    raise last


def fetch_text(url):
    return fetch_bytes(url).decode("utf-8", errors="replace")


def latest_export_url():
    text = fetch_text(MANIFEST)
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].endswith(".export.CSV.zip"):
            return parts[2]
    raise RuntimeError("no GDELT export file in lastupdate.txt")


def export_urls(latest_url):
    name = os.path.basename(latest_url).split(".")[0]
    latest = datetime.strptime(name, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    urls = []
    for offset in range(WINDOW_FILES):
        stamp = (latest - timedelta(minutes=15 * offset)).strftime("%Y%m%d%H%M%S")
        urls.append(BASE + stamp + ".export.CSV.zip")
    return urls


def load_previous():
    try:
        with open(OUT_JSON, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalise_code(value):
    code = str(value or "").strip().lstrip("0")
    return code or "0"


def iso_date(value):
    try:
        return datetime.strptime(value, "%Y%m%d").strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return ""


def iso_timestamp(value):
    try:
        return datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return ""


def source_host(value):
    try:
        return urllib.parse.urlsplit(value).netloc.replace("www.", "")
    except Exception:
        return "GDELT"


def classify(event_code, root_code, quad_class):
    code = normalise_code(event_code)
    root = normalise_code(root_code)
    if code.startswith("171"):
        return "theft"
    if code.startswith("176"):
        return "cyber"
    if root == "14":
        return "protest"
    if root in ("19", "20"):
        return "conflict"
    if root == "18":
        return "assault"
    if root == "17":
        return "coercion"
    if quad_class >= 4:
        return "incident"
    return "incident"


def severity_for(category, quad_class, goldstein):
    if category == "conflict" or (category == "assault" and quad_class >= 4):
        return 4
    if goldstein is not None and goldstein <= -7:
        return 4
    if category in ("assault", "cyber", "coercion"):
        return 3
    if goldstein is not None and goldstein <= -4:
        return 3
    return 2


def make_event(cols, source_url):
    event_id = "gdelt-" + cols[0]
    code = cols[26].strip()
    base_code = cols[27].strip()
    root_code = cols[28].strip()
    quad = safe_int(cols[29])
    goldstein = safe_float(cols[30])
    category = classify(base_code or code, root_code, quad)
    label = EVENT_LABELS.get(normalise_code(base_code) or normalise_code(code), CATEGORY_LABELS[category])
    lat = safe_float(cols[56])
    lon = safe_float(cols[57])
    if lat is None or lon is None:
        return None
    country = cols[53].strip().upper()
    if country != "KE" and not (33.5 <= lon <= 42.0 and -4.9 <= lat <= 5.5):
        return None
    physical_root = normalise_code(root_code) in ("14", "17", "18", "19", "20")
    if quad < 4 and not physical_root:
        return None

    actor1 = display_name(cols[6].strip() or cols[5].strip() or "Unidentified actor")
    actor2 = display_name(cols[17].strip() or cols[16].strip() or "target")
    place = cols[52].strip() or "Kenya"
    url = cols[60].strip()
    if actor1.lower() == actor2.lower():
        title = label + " reported in " + place
    else:
        title = label + ": " + actor1 + " / " + actor2 + " in " + place

    return {
        "id": event_id,
        "date": iso_date(cols[1]),
        "updatedUtc": iso_timestamp(cols[59]),
        "title": title,
        "summary": label + " reported in " + place + ".",
        "category": category,
        "categoryLabel": CATEGORY_LABELS[category],
        "place": place,
        "county": cols[54].strip() or "",
        "lat": lat,
        "lon": lon,
        "severity": severity_for(category, quad, goldstein),
        "code": base_code or code,
        "rootCode": root_code,
        "quadClass": quad,
        "goldstein": goldstein,
        "mentions": safe_int(cols[31]),
        "sources": safe_int(cols[32]),
        "articles": safe_int(cols[33]),
        "source": source_host(url) or "GDELT",
        "url": url,
        "confidence": "open-source report; not verified by Bulwark",
        "locationPrecision": safe_int(cols[51]),
        "sourceFeed": source_url,
    }


def read_export(url):
    raw = fetch_bytes(url).decode("latin-1", errors="replace")
    with zipfile.ZipFile(io.BytesIO(raw.encode("latin-1", errors="replace"))) as archive:
        names = [n for n in archive.namelist() if n.endswith(".export.CSV")]
        if not names:
            return [], 0
        text = archive.read(names[0]).decode("latin-1", errors="replace")

    events = []
    rows = 0
    for line in text.splitlines():
        if not line or line.startswith("GDELT VERSION") or line.startswith("GLOBALEVENTID"):
            continue
        cols = line.split("\t")
        if len(cols) < 61:
            continue
        rows += 1
        event = make_event(cols, url)
        if event:
            events.append(event)
    return events, rows


def acled_category(row):
    event_type = str(row.get("event_type") or "").lower()
    sub_type = str(row.get("sub_event_type") or "").lower()
    if "loot" in sub_type or "robber" in sub_type or "property" in sub_type:
        return "theft"
    if "protest" in event_type or "riot" in event_type:
        return "protest"
    if "explosion" in event_type or "battle" in event_type:
        return "conflict"
    if "violence against civilians" in event_type:
        return "assault"
    if "strategic" in event_type:
        return "coercion"
    return "incident"


def make_acled_event(row, source_url):
    lat = safe_float(row.get("latitude"))
    lon = safe_float(row.get("longitude"))
    if lat is None or lon is None:
        return None
    category = acled_category(row)
    fatalities = safe_int(row.get("fatalities"))
    severity = 4 if fatalities >= 10 else 3 if fatalities > 0 else 3 if category in ("conflict", "assault") else 2
    actor1 = display_name(row.get("actor1") or "Unidentified actor")
    actor2 = display_name(row.get("actor2") or "target")
    place = str(row.get("location") or row.get("admin1") or "Kenya").strip()
    label = str(row.get("sub_event_type") or row.get("event_type") or "Reported incident").strip()
    source_text = str(row.get("source") or "ACLED").split(";")[0].strip() or "ACLED"
    return {
        "id": "acled-" + str(row.get("event_id_cnty") or ""),
        "date": str(row.get("event_date") or ""),
        "updatedUtc": "",
        "title": label + ": " + actor1 + " / " + actor2 + " in " + place,
        "summary": str(row.get("notes") or label).strip(),
        "category": category,
        "categoryLabel": CATEGORY_LABELS[category],
        "place": place,
        "county": str(row.get("admin1") or "").strip(),
        "lat": lat,
        "lon": lon,
        "severity": severity,
        "code": str(row.get("sub_event_type") or ""),
        "rootCode": str(row.get("event_type") or ""),
        "quadClass": 4 if category in ("conflict", "assault", "theft") else 3,
        "goldstein": None,
        "mentions": 1,
        "sources": 1,
        "articles": 1,
        "source": source_text,
        "url": safe_url_for_python(row.get("source_url")),
        "confidence": "ACLED-coded open-source event; not verified by Bulwark",
        "locationPrecision": safe_int(row.get("geo_precision")),
        "fatalities": fatalities,
        "sourceFeed": source_url,
    }


def safe_url_for_python(value):
    text = str(value or "").strip()
    return text if text.lower().startswith(("http://", "https://")) else ""


def fetch_acled_events():
    key = os.environ.get("ACLED_KEY", "").strip()
    email = os.environ.get("ACLED_EMAIL", "").strip()
    source = {
        "name": "acled_kenya",
        "label": "ACLED Kenya",
        "category": "coded Kenya conflict events",
        "license": "ACLED terms; non-commercial by default",
        "url": "https://acleddata.com/country/kenya",
        "error": None,
    }
    if not key or not email:
        source["error"] = "ACLED_KEY/ACLED_EMAIL not configured; GDELT Kenya only"
        return [], source
    since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")
    params = {
        "key": key,
        "email": email,
        "country": "Kenya",
        "event_date": since,
        "event_date_where": ">=",
        "fields": "event_id_cnty|event_date|event_type|sub_event_type|actor1|actor2|location|admin1|latitude|longitude|geo_precision|fatalities|source|notes|source_url",
        "limit": "500",
    }
    url = ACLED_URL + "?" + urllib.parse.urlencode(params)
    try:
        payload = json.loads(fetch_text(url))
        if not payload.get("success"):
            raise RuntimeError("ACLED API returned success=false")
        events = []
        for row in payload.get("data", []):
            event = make_acled_event(row, url)
            if event:
                events.append(event)
        return events, source
    except Exception as ex:
        source["error"] = str(ex)
        return [], source


def main():
    previous = load_previous()
    acled_events, acled_source = fetch_acled_events()
    errors = []
    events = {}
    rows = 0
    files_ok = 0
    files_failed = 0
    fresh_from = ""
    fresh_to = ""

    try:
        latest_url = latest_export_url()
        targets = export_urls(latest_url)
    except Exception as ex:
        latest_url = ""
        targets = []
        errors.append(str(ex))

    if targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(read_export, url): url for url in targets}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    batch, batch_rows = future.result()
                    files_ok += 1
                    rows += batch_rows
                    stamp = os.path.basename(url).split(".")[0]
                    if not fresh_to or stamp > fresh_to:
                        fresh_to = stamp
                    if not fresh_from or stamp < fresh_from:
                        fresh_from = stamp
                    for event in batch:
                        events[event["id"]] = event
                except Exception as ex:
                    files_failed += 1
                    errors.append(os.path.basename(url) + ": " + str(ex))

    for event in acled_events:
        events[event["id"]] = event

    if not events:
        for event in previous.get("events", []):
            if event.get("id") and event.get("lat") is not None and event.get("lon") is not None:
                events[event["id"]] = event
        if events and not errors:
            errors.append("upstream returned no Kenya incidents; using previous snapshot")

    ordered = sorted(
        events.values(),
        key=lambda e: (e.get("updatedUtc") or "", e.get("mentions") or 0),
        reverse=True,
    )[:MAX_EVENTS]

    payload = {
        "generatedUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window": "last 24 hours of GDELT Events 2.0 15-minute exports",
        "latestFile": latest_url,
        "freshFrom": fresh_from,
        "freshTo": fresh_to,
        "sources": [
            {
                "name": "gdelt_events_2",
                "label": "GDELT Events 2.0",
                "category": "open-source news events",
                "license": "Free with attribution",
                "url": "https://data.gdeltproject.org/",
                "codebook": "https://data.gdeltproject.org/documentation/CAMEO.Manual.1.1b3.pdf",
                "error": "; ".join(errors[:5]) if errors else None,
            },
            acled_source,
        ],
        "summary": {
            "incidents": len(ordered),
            "rowsScanned": rows,
            "filesOk": files_ok,
            "filesFailed": files_failed,
            "gdeltEvents": sum(1 for e in ordered if str(e["id"]).startswith("gdelt-")),
            "acledEvents": sum(1 for e in ordered if str(e["id"]).startswith("acled-")),
            "categories": dict(Counter(e["categoryLabel"] for e in ordered)),
        },
        "disclaimer": "Geolocated open-source reports, not Bulwark agent telemetry. Locations are place-level and reports are not independently verified.",
        "events": ordered,
    }

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)

    with open(OUT_JS, "w", encoding="utf-8") as fh:
        fh.write("window.BULWARK_KENYA_INCIDENTS = ")
        json.dump(payload, fh, separators=(",", ":"), ensure_ascii=False)
        fh.write(";\n")

    print("Kenya OSINT incidents: {0} from {1} rows, {2} ok, {3} failed".format(
        len(ordered), rows, files_ok, files_failed))
    if errors:
        print("  " + "; ".join(errors[:3]))


if __name__ == "__main__":
    main()
