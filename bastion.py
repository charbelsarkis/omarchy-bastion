#!/usr/bin/env python3
"""Bastion feed helper: fetch and normalize FortiGuard Labs RSS feeds.

Usage:
  bastion.py fetch     Download the feeds, update the cache, print JSON.
  bastion.py cached    Print the last cached result (no network).
  bastion.py ack [id...]  Mark cached items read (all, or just these), print JSON.

Network access is limited to the three fixed HTTPS feed URLs below and the
HTTPS Fortinet hosts they redirect to. The feeds are fetched in parallel, with
a per-operation timeout, an overall deadline and a hard size cap, and with
conditional requests so an unchanged feed costs a 304. Everything taken from
a feed is treated as untrusted: HTML is stripped, strings are length-bounded,
links must stay on fortinet.com over HTTPS, and item counts are capped. Output
is plain JSON on stdout; the QML side renders it with Text.PlainText only.

Every monitor's bar runs its own copy of the widget, so several helpers can
run at once: state changes are serialized with a lock file, and a fetch that
lands right after another one reuses its result instead of downloading again.

Not affiliated with or endorsed by Fortinet, Inc.
"""

import contextlib
import email.utils
import fcntl
import html
import io
import json
import os
import re
import sys
import tempfile
import threading
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
TIMEOUT = 15          # seconds, per socket operation
FETCH_DEADLINE = 45   # seconds, for the whole fetch (all feeds, in parallel)
COALESCE_SEC = 60     # a fetch this soon after a clean one reuses its result
CACHE_FORMAT = 2      # bump when parse_feed's output changes: old items are then never reused on a 304
# Everything held is listed in the panel, so closing it acks only what was shown.
# PSIRT keeps 15: Fortinet publishes its advisories in monthly batches.
MAX_ITEMS = {"psirt": 15, "outbreak": 5, "threat": 5}
MAX_TITLE = 160
MAX_SUMMARY = 280
MAX_CVES = 8
MAX_KNOWN = 2000
MAX_FRESH = 20
MAX_PRODUCTS = 4
MAX_ACK_IDS = 100
ALLOWED_HOST_SUFFIX = ".fortinet.com"
ALLOWED_HOSTS = {"fortinet.com", "fortiguard.com", "www.fortiguard.com"}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
CVSS_RE = re.compile(r"CVSSv3\s*Score:\s*([0-9]{1,2}(?:\.[0-9])?)", re.I)
# Fortinet product names as they appear in advisory text ("in FortiOS, FortiProxy
# and FortiSwitch"). PSIRT titles don't name the product, so this is the only
# place to learn what an advisory affects. FortiGuard is the source, not a product.
PRODUCT_RE = re.compile(r"\bForti(?!Guard\b)[A-Z][A-Za-z0-9]{0,24}(?:-[A-Z0-9][A-Za-z0-9]{0,5})?\b")
# "<" is excluded inside the tag so a failed match stops at the next "<":
# with "<[^>]*>" a long run of unclosed "<" rescans the rest of the field from
# every "<" (quadratic, and the regex holds the GIL so join() deadlines stall).
TAG_RE = re.compile(r"<[^<>]*>")
SPACE_RE = re.compile(r"\s+")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")
# ETag / Last-Modified values we store and send back: printable ASCII only.
HEADER_VALUE_RE = re.compile(r"[\x20-\x7e]{1,200}")


def _plugin_version():
    """The manifest's version, so the User-Agent can't drift from it."""
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json")
        with open(path, "r", encoding="utf-8") as handle:
            version = json.load(handle).get("version")
    except (OSError, ValueError, AttributeError):
        return "unknown"
    if isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.+-]{1,32}", version):
        return version
    return "unknown"


USER_AGENT = "Bastion-Omarchy-Plugin/%s (+FortiGuard RSS reader)" % _plugin_version()


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
        host = (parts.hostname or "").lower()
        # .port raises ValueError for a non-numeric or out-of-range port; one
        # malformed <link> must not take the whole feed down with it.
        port = parts.port
    except ValueError:
        return ""
    if parts.scheme != "https" or parts.username or parts.password or port is not None:
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

    A redirect response's body is never read. The stock handler reads it with
    an unbounded fp.read() (which would bypass MAX_BYTES), and some redirects
    never reach redirect_request at all (a non-web Location, or none), so
    every 30x handler closes the response on entry and hands the stock code an
    empty stand-in. Nothing here depends on when, or whether, the stock
    handler reads its fp."""

    def http_error_302(self, req, fp, code, msg, headers):
        if fp is not None:
            fp.close()
        return super().http_error_302(req, io.BytesIO(), code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not safe_link(newurl):
            raise urllib.error.HTTPError(req.full_url, code, "redirect off Fortinet HTTPS refused", headers, None)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(FortinetOnlyRedirects)


def header_value(value):
    """A response validator we're willing to store and send back, or ""."""
    value = value.strip() if isinstance(value, str) else ""
    return value if HEADER_VALUE_RE.fullmatch(value) else ""


def download(url, validators=None):
    """GET url. Returns (data, info), where info holds the final URL and the
    response's validators, or (None, {}) when validators were sent and the
    server answered 304 Not Modified."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml"}
    headers.update(validators or {})
    request = urllib.request.Request(url, headers=headers)
    try:
        response = OPENER.open(request, timeout=TIMEOUT)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 304 and validators:
            return None, {}
        raise
    with response:
        final = safe_link(response.geturl())
        if not final:
            raise ValueError("ended up off Fortinet HTTPS")
        data = response.read(MAX_BYTES + 1)
        info = {
            "url": final,
            "etag": header_value(response.headers.get("ETag")),
            "lastModified": header_value(response.headers.get("Last-Modified")),
        }
    if len(data) > MAX_BYTES:
        raise ValueError("feed too large")
    return data, info


def validators_for(meta):
    out = {}
    if header_value(meta.get("etag")):
        out["If-None-Match"] = header_value(meta.get("etag"))
    if header_value(meta.get("lastModified")):
        out["If-Modified-Since"] = header_value(meta.get("lastModified"))
    return out


def fetch_feed(kind, meta, cached):
    """Download and parse one feed. Returns (items, meta) for the cache.

    Goes straight to the Fortinet host the feed last redirected to (saving the
    redirect), falling back to the canonical URL if that fails. Sends the last
    response's validators only while the cached items a 304 would reuse are
    there, so an unchanged feed costs a 304 and no parsing."""
    meta = meta if isinstance(meta, dict) else {}
    canonical = FEEDS[kind]
    learned = safe_link(meta.get("url")) if isinstance(meta.get("url"), str) else ""
    validators = validators_for(meta) if cached else {}
    attempts = [learned, canonical] if learned and learned != canonical else [canonical]
    error = None
    for url in attempts:
        try:
            data, info = download(url, validators)
            if data is None:
                kept = {"url": learned, "etag": header_value(meta.get("etag")),
                        "lastModified": header_value(meta.get("lastModified"))}
                return cached[: MAX_ITEMS[kind]], kept
            return parse_feed(kind, data), info
        except Exception as exc:  # noqa: BLE001 - try the canonical URL next
            error = exc
    raise error


def cached_items(previous, kind):
    """The cached items for a feed, skipping anything malformed."""
    items = previous.get(kind)
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict) and isinstance(i.get("id"), str) and isinstance(i.get("title"), str)]


def fetch_all(previous):
    """Fetch every feed in parallel. Returns {kind: (items, meta) or exception};
    a feed still running at FETCH_DEADLINE counts as failed (its daemon thread
    is abandoned and dies with the process)."""
    same_format = previous.get("format") == CACHE_FORMAT
    meta = previous.get("http") if same_format and isinstance(previous.get("http"), dict) else {}
    done = {}

    def work(kind):
        try:
            done[kind] = fetch_feed(kind, meta.get(kind), cached_items(previous, kind) if same_format else [])
        except Exception as exc:  # noqa: BLE001 - reported per feed
            done[kind] = exc

    deadline = time.monotonic() + FETCH_DEADLINE
    threads = [threading.Thread(target=work, args=(kind,), name="bastion-" + kind, daemon=True) for kind in FEEDS]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    return {kind: done.get(kind, TimeoutError("no answer within %ss" % FETCH_DEADLINE)) for kind in FEEDS}


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


@contextlib.contextmanager
def state_lock():
    """Serialize fetches and acks across helper runs (one widget per monitor).
    The lock goes with the process, so a killed helper never leaves it held."""
    directory = os.path.dirname(STATE_FILE)
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, ".lock"), "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


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
    return [item["id"] for kind in FEEDS for item in cached_items(result, kind)]


def recently_fetched(previous, now):
    at = previous.get("fetchedAt")
    return isinstance(at, int) and not previous.get("errors") and 0 <= now - at < COALESCE_SEC


def cmd_fetch():
    with state_lock():
        previous = read_json(CACHE_FILE, {})
        now = int(time.time())
        if recently_fetched(previous, now):
            # Another copy of the widget just fetched: reuse it. Its run
            # already reported (and notified) whatever was new.
            result = cmd_cached()
            result["fresh"] = []
            return result

        outcomes = fetch_all(previous)
        old_meta = previous.get("http") if isinstance(previous.get("http"), dict) else {}
        result = {"format": CACHE_FORMAT, "fetchedAt": 0, "errors": {}, "http": {}}
        for kind in FEEDS:
            outcome = outcomes[kind]
            if isinstance(outcome, Exception):
                result["errors"][kind] = clean_text(type(outcome).__name__ + ": " + str(outcome), 160)
                result[kind] = cached_items(previous, kind)
                # Keep the validators that belong to the items kept.
                if isinstance(old_meta.get(kind), dict):
                    result["http"][kind] = old_meta[kind]
            else:
                result[kind], result["http"][kind] = outcome
        # Only a feed that answered makes the cache newer. A fetch that failed
        # everywhere keeps the old time, so the panel shows the data as stale
        # and the next check retries instead of waiting a whole interval.
        old_at = previous.get("fetchedAt")
        if len(result["errors"]) < len(FEEDS):
            result["fetchedAt"] = now
        elif isinstance(old_at, int) and old_at > 0:
            result["fetchedAt"] = old_at
        write_json(CACHE_FILE, result)

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
    for kind in FEEDS:
        result[kind] = cached_items(result, kind)
    return decorate(result, load_state())


def cmd_ack(only=None):
    """Mark cached items read. With ids, only those (the rows the panel was
    showing), so an item fetched while the panel closed stays unread. An empty
    list acks nothing."""
    with state_lock():
        result = read_json(CACHE_FILE, {})
        state = load_state()
        cached = all_ids(result) if result else []
        if only is None:
            targets = cached
        else:
            wanted = set(only)
            targets = [i for i in cached if i in wanted]
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
