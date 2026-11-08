#!/usr/bin/env python3
"""Bastion feed helper: fetch and normalize FortiGuard Labs RSS feeds.

Usage:
  bastion.py fetch     Download the feeds, update the cache, print JSON.
  bastion.py cached    Print the last cached result (no network).
  bastion.py ack [id...]  Mark cached items read (all, or just these), print JSON.

Network access is limited to the three fixed HTTPS feed URLs below, with a
timeout and a hard size cap. Everything taken from a feed is treated as
untrusted: HTML is stripped, strings are length-bounded, links must stay on
fortinet.com over HTTPS, and item counts are capped. Output is plain JSON on
stdout; the QML side renders it with Text.PlainText only.

Not affiliated with or endorsed by Fortinet, Inc.
"""

import email.utils
import html
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

FEEDS = {
    "psirt": "https://www.fortiguard.com/rss/ir.xml",
    "outbreak": "https://www.fortiguard.com/rss/outbreakalert.xml",
    "threat": "https://www.fortiguard.com/rss/threatsignal.xml",
}
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 15
MAX_ITEMS = {"psirt": 15, "outbreak": 8, "threat": 8}
MAX_TITLE = 160
MAX_SUMMARY = 280
MAX_CVES = 8
MAX_KNOWN = 2000
MAX_FRESH = 20
MAX_PRODUCTS = 4
MAX_ACK_IDS = 100
USER_AGENT = "Bastion-Omarchy-Plugin/1.0 (+FortiGuard RSS reader)"
ALLOWED_HOST_SUFFIX = ".fortinet.com"
ALLOWED_HOSTS = {"fortinet.com", "fortiguard.com", "www.fortiguard.com"}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
CVSS_RE = re.compile(r"CVSSv3\s*Score:\s*([0-9]{1,2}(?:\.[0-9])?)", re.I)
# Fortinet product names as they appear in advisory text ("in FortiOS, FortiProxy
# and FortiSwitch"). PSIRT titles don't name the product, so this is the only
# place to learn what an advisory affects. FortiGuard is the source, not a product.
PRODUCT_RE = re.compile(r"\bForti(?!Guard\b)[A-Z][A-Za-z0-9]{0,24}(?:-[A-Z0-9][A-Za-z0-9]{0,5})?\b")
TAG_RE = re.compile(r"<[^>]*>")
SPACE_RE = re.compile(r"\s+")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")


def _xdg(var, fallback):
    base = os.environ.get(var) or os.path.join(os.path.expanduser("~"), fallback)
    return os.path.join(base, "omarchy-bastion")


CACHE_FILE = os.path.join(_xdg("XDG_CACHE_HOME", ".cache"), "feeds.json")
STATE_FILE = os.path.join(_xdg("XDG_STATE_HOME", ".local/state"), "state.json")


def clean_text(raw, limit):
    """Strip markup and control characters, collapse whitespace, bound length."""
    if not raw:
        return ""
    text = TAG_RE.sub(" ", str(raw))
    text = html.unescape(text)
    # Unescaping can produce new tag-shaped text (&lt;img&gt;); strip again.
    text = TAG_RE.sub(" ", text)
    text = CTRL_RE.sub("", text)
    text = SPACE_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def safe_link(raw):
    """Return the link only if it is HTTPS on a Fortinet-owned host."""
    link = (raw or "").strip()
    if len(link) > 300 or CTRL_RE.search(link) or " " in link:
        return ""
    try:
        parts = urlsplit(link)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or parts.password or parts.port:
        return ""
    if host in ALLOWED_HOSTS or host.endswith(ALLOWED_HOST_SUFFIX):
        return link
    return ""


def parse_date(raw):
    try:
        parsed = email.utils.parsedate_to_datetime((raw or "").strip())
        ts = int(parsed.timestamp())
    except (TypeError, ValueError, IndexError, OverflowError):
        return 0
    # Reject timestamps before 2000 or more than two days in the future.
    if ts < 946684800 or ts > time.time() + 172800:
        return 0
    return ts


def severity_for(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def products_in(text):
    products = []
    for name in PRODUCT_RE.findall(text or ""):
        if name not in products:
            products.append(name)
        if len(products) >= MAX_PRODUCTS:
            break
    return products


def parse_feed(kind, data):
    root = ET.fromstring(data)
    items = []
    for node in root.findall("./channel/item"):
        title = clean_text(node.findtext("title"), MAX_TITLE)
        link = safe_link(node.findtext("link"))
        guid = clean_text(node.findtext("guid") or link or title, 300)
        if not title or not guid:
            continue
        raw_desc = node.findtext("description") or ""
        item = {
            "id": guid,
            "title": title,
            "link": link,
            "published": parse_date(node.findtext("pubDate")),
        }
        if kind == "psirt":
            plain = clean_text(raw_desc, 20000)
            match = CVSS_RE.search(plain)
            score = None
            if match:
                try:
                    value = float(match.group(1))
                    score = value if 0.0 <= value <= 10.0 else None
                except ValueError:
                    score = None
            cves = []
            for cve in CVE_RE.findall(plain):
                if cve not in cves:
                    cves.append(cve)
                if len(cves) >= MAX_CVES:
                    break
            advisory = ""
            m = re.search(r"FG-IR-\d{2}-\d{1,5}", link or guid)
            if m:
                advisory = m.group(0)
            item.update({
                "advisory": advisory,
                "cvss": score,
                "severity": severity_for(score),
                "cves": cves,
                "products": products_in(plain),
            })
        else:
            item["summary"] = clean_text(raw_desc, MAX_SUMMARY)
        items.append(item)
    items.sort(key=lambda i: i["published"], reverse=True)
    return items[: MAX_ITEMS[kind]]


class FortinetOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to HTTPS on a Fortinet host (the feeds 302 to
    filestore.fortinet.com); refuse anything else before connecting to it.

    The redirect response's body is never read: the stock handler calls an
    unbounded fp.read() before following, which would bypass MAX_BYTES, so
    the response is closed here first and that read returns nothing."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if fp is not None:
            fp.close()
        if not safe_link(newurl):
            raise urllib.error.HTTPError(req.full_url, code, "redirect off Fortinet HTTPS refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(FortinetOnlyRedirects)


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml"})
    with OPENER.open(request, timeout=TIMEOUT) as response:
        if not safe_link(response.geturl()):
            raise ValueError("ended up off Fortinet HTTPS")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("feed too large")
    return data


def read_json(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else fallback
    except (OSError, ValueError):
        return fallback


def write_json(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_state():
    state = read_json(STATE_FILE, {})
    known = state.get("known") if isinstance(state.get("known"), list) else None
    acked = state.get("acked") if isinstance(state.get("acked"), list) else []
    seeded = state.get("seeded")
    if isinstance(seeded, list):
        seeded = [k for k in FEEDS if k in seeded]
    else:
        # State written before per-feed seeding: if it knows any items, the
        # feeds had been fetched; an empty list means the first run was offline.
        seeded = list(FEEDS) if known else []
    return {
        "known": [str(k) for k in known][-MAX_KNOWN:] if known is not None else None,
        "acked": [str(k) for k in acked][-MAX_KNOWN:],
        "seeded": seeded,
    }


def save_state(known, acked, seeded):
    write_json(STATE_FILE, {
        "known": list(known)[-MAX_KNOWN:],
        "acked": list(acked)[-MAX_KNOWN:],
        "seeded": [k for k in FEEDS if k in seeded],
    })


def decorate(result, state):
    """Mark unread items; first ever run treats everything as already read."""
    acked = set(state["acked"])
    known = state["known"]
    for kind in FEEDS:
        for item in result.get(kind, []):
            item["unread"] = known is not None and item["id"] not in acked
    psirt = result.get("psirt", [])
    result["unreadCritical"] = sum(1 for i in psirt if i.get("unread") and i.get("severity") == "critical")
    result["unreadTotal"] = sum(1 for kind in FEEDS for i in result.get(kind, []) if i.get("unread"))
    return result


def all_ids(result):
    return [item["id"] for kind in FEEDS for item in result.get(kind, [])]


def cmd_fetch():
    previous = read_json(CACHE_FILE, {})
    result = {"fetchedAt": int(time.time()), "errors": {}}
    for kind, url in FEEDS.items():
        try:
            result[kind] = parse_feed(kind, download(url))
        except Exception as exc:  # noqa: BLE001 - report per-feed, keep others
            result["errors"][kind] = clean_text(type(exc).__name__ + ": " + str(exc), 160)
            result[kind] = previous.get(kind, []) if isinstance(previous.get(kind), list) else []
    write_json(CACHE_FILE, {k: v for k, v in result.items()})

    state = load_state()
    known = list(state["known"] or [])
    known_set = set(known)
    acked = list(state["acked"])
    acked_set = set(acked)
    seeded = set(state["seeded"])
    fresh = set()
    for kind in FEEDS:
        for item in result.get(kind, []):
            ident = item["id"]
            if ident in known_set:
                continue
            known.append(ident)
            known_set.add(ident)
            if kind in seeded:
                fresh.add(ident)
            elif ident not in acked_set:
                # A feed's first successful fetch is its baseline, not news:
                # otherwise a first run while offline (or with one feed down)
                # would announce the whole backlog on the next good fetch.
                acked.append(ident)
                acked_set.add(ident)
        if kind not in result["errors"]:
            seeded.add(kind)
    save_state(known, acked, seeded)

    decorate(result, {"known": known[-MAX_KNOWN:], "acked": acked[-MAX_KNOWN:]})
    result["fresh"] = fresh_items(result, fresh)
    return result


def fresh_items(result, fresh_set):
    """Items that appeared since the last fetch, for notifications."""
    out = []
    for kind in FEEDS:
        for i in result.get(kind, []):
            if i["id"] not in fresh_set:
                continue
            out.append({
                "kind": kind,
                "title": i["title"],
                "link": i.get("link", ""),
                "severity": i.get("severity", ""),
                "cvss": i.get("cvss"),
                "advisory": i.get("advisory", ""),
                "products": i.get("products", []),
                "published": i.get("published", 0),
            })
    return out[:MAX_FRESH]


def cmd_cached():
    result = read_json(CACHE_FILE, {})
    if not result:
        return {"fetchedAt": 0, "errors": {}, "psirt": [], "outbreak": [], "threat": [], "unreadCritical": 0, "unreadTotal": 0}
    result.setdefault("errors", {})
    return decorate(result, load_state())


def cmd_ack(only=None):
    """Mark cached items read. With ids, only those (the rows the panel was
    showing), so an item fetched while the panel closed stays unread."""
    result = read_json(CACHE_FILE, {})
    state = load_state()
    cached = all_ids(result) if result else []
    wanted = set(only or [])
    targets = [i for i in cached if i in wanted] if only else cached
    acked_set = set(state["acked"])
    acked = state["acked"] + [i for i in targets if i not in acked_set]
    known = state["known"] if state["known"] is not None else list(cached)
    save_state(known, acked, state["seeded"])
    return cmd_cached()


def main(argv):
    command = argv[1] if len(argv) > 1 else "cached"
    handlers = {"fetch": cmd_fetch, "cached": cmd_cached, "ack": cmd_ack}
    if command not in handlers:
        print("usage: bastion.py fetch|cached|ack [id...]", file=sys.stderr)
        return 2
    try:
        if command == "ack" and len(argv) > 2:
            ids = [i for i in argv[2:2 + MAX_ACK_IDS] if 0 < len(i) <= 300]
            output = cmd_ack(ids)
        else:
            output = handlers[command]()
    except Exception as exc:  # noqa: BLE001
        print(clean_text(str(exc), 200), file=sys.stderr)
        return 1
    print(json.dumps(output, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
