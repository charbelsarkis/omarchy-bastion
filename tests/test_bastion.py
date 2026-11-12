"""Regression tests for bastion.py. Run: python3 -I -m unittest discover -s tests"""
import importlib.util
import json
import os
import sys
import threading
import time
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("bastion", os.path.join(HERE, "..", "bastion.py"))
bastion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bastion)

PSIRT = b"""<?xml version='1.0'?><rss version="2.0"><channel>
<item><title>&lt;img src="https://example.invalid/tracker"&gt;Evil &lt;b&gt;title&lt;/b&gt;</title>
<link>https://fortiguard.fortinet.com/psirt/FG-IR-26-001</link>
<description><![CDATA[<p><strong>CVSSv3 Score:</strong> 9.8</p><p>CVE-2026-0001 - (critical) <script>x</script></p>]]></description>
<guid>https://fortiguard.fortinet.com/psirt/FG-IR-26-001</guid><pubDate>Mon, 26 Oct 2026 00:00:00 -0700</pubDate></item>
<item><title>Off-site link</title><link>javascript:alert(1)</link><description>CVSSv3 Score: 99</description>
<guid>x2</guid><pubDate>garbage</pubDate></item>
<item><title>Lookalike host</title><link>https://fortinet.com.evil.example/a</link><description>CVSSv3 Score: 5.0</description>
<guid>x3</guid><pubDate>Tue, 27 Oct 2026 00:00:00 -0700</pubDate></item>
<item><title>Bad port</title><link>https://fortiguard.fortinet.com:abc/psirt/FG-IR-26-004</link>
<guid>x4</guid></item>
</channel></rss>"""


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.items = {i["id"]: i for i in bastion.parse_feed("psirt", PSIRT)}

    def test_markup_is_stripped_from_titles(self):
        title = self.items["https://fortiguard.fortinet.com/psirt/FG-IR-26-001"]["title"]
        self.assertNotIn("<", title)
        self.assertNotIn(">", title)
        self.assertEqual(title, "Evil title")

    def test_cvss_and_severity(self):
        item = self.items["https://fortiguard.fortinet.com/psirt/FG-IR-26-001"]
        self.assertEqual(item["cvss"], 9.8)
        self.assertEqual(item["severity"], "critical")
        self.assertEqual(item["cves"], ["CVE-2026-0001"])
        self.assertEqual(item["advisory"], "FG-IR-26-001")

    def test_out_of_range_cvss_rejected(self):
        self.assertIsNone(self.items["x2"]["cvss"])
        self.assertEqual(self.items["x2"]["severity"], "")

    def test_non_fortinet_links_dropped(self):
        self.assertEqual(self.items["x2"]["link"], "")
        self.assertEqual(self.items["x3"]["link"], "")

    def test_malformed_port_drops_the_link_not_the_feed(self):
        self.assertEqual(self.items["x4"]["link"], "")
        self.assertEqual(len(self.items), 4)

    def test_bad_dates_become_zero(self):
        self.assertEqual(self.items["x2"]["published"], 0)

    def test_sorted_newest_first(self):
        dates = [i["published"] for i in bastion.parse_feed("psirt", PSIRT)]
        self.assertEqual(dates, sorted(dates, reverse=True))

    def test_lengths_bounded(self):
        long = b"<rss><channel><item><title>" + b"A" * 5000 + b"</title><guid>g</guid><description>" + b"B" * 5000 + b"</description></item></channel></rss>"
        item = bastion.parse_feed("outbreak", long)[0]
        self.assertLessEqual(len(item["title"]), bastion.MAX_TITLE)
        self.assertLessEqual(len(item["summary"]), bastion.MAX_SUMMARY)

    def test_entity_encoded_markup_cannot_survive(self):
        self.assertEqual(bastion.clean_text("&lt;img src=x&gt;hi", 100), "hi")
        double = bastion.clean_text("&amp;lt;img src=x&amp;gt;hi", 100)
        self.assertNotIn("<", double)
        self.assertNotIn(">", double)

    def test_bidi_and_control_chars_removed(self):
        self.assertEqual(bastion.clean_text("a‮b\x07c", 10), "abc")

    def test_safe_link(self):
        self.assertEqual(bastion.safe_link("https://www.fortiguard.com/psirt/X"), "https://www.fortiguard.com/psirt/X")
        self.assertEqual(bastion.safe_link("http://fortiguard.fortinet.com/x"), "")
        self.assertEqual(bastion.safe_link("https://user@fortiguard.fortinet.com/x"), "")
        self.assertEqual(bastion.safe_link("https://evilfortinet.com/x"), "")

    def test_safe_link_ports(self):
        for link in ("https://www.fortinet.com:abc/x", "https://www.fortinet.com:99999/x",
                     "https://www.fortinet.com:8443/x", "https://www.fortinet.com:0/x"):
            self.assertEqual(bastion.safe_link(link), "", link)

    def test_clean_text_unclosed_tags_are_linear(self):
        # A long run of "<" with no ">" made "<[^>]*>" rescan from every "<":
        # quadratic (200k chars took ~11s, a 2 MiB title ~12 min) while holding
        # the GIL, so fetch_all's join() deadline couldn't fire.
        n = 200_000
        for raw in ("<" * n, "&lt;" * n, "<a " * n, "<" * bastion.MAX_BYTES):
            start = time.monotonic()
            bastion.clean_text(raw, bastion.MAX_TITLE)
            self.assertLess(time.monotonic() - start, 1.0)

    def test_clean_text_still_strips_markup(self):
        self.assertEqual(bastion.clean_text("<p>a <b>b</b></p> &lt;i&gt;c&lt;/i&gt;", 100), "a b c")
        self.assertEqual(bastion.clean_text("x <<b>y", 100), "x < y")


class VersionTests(unittest.TestCase):
    def test_user_agent_carries_manifest_version(self):
        with open(os.path.join(HERE, "..", "manifest.json"), encoding="utf-8") as handle:
            version = json.load(handle)["version"]
        self.assertIn("/%s " % version, bastion.USER_AGENT)


class FreshTests(unittest.TestCase):
    def test_fresh_items_only_new_and_capped(self):
        result = {"psirt": [{"id": "a", "title": "A", "link": "", "severity": "critical", "cvss": 9.8, "advisory": "FG-IR-26-001", "published": 1}],
                  "outbreak": [{"id": "b", "title": "B", "link": "", "published": 2}],
                  "threat": [{"id": "t%d" % n, "title": "T", "link": "", "published": n} for n in range(30)]}
        fresh = bastion.fresh_items(result, {"a"} | {"t%d" % n for n in range(30)})
        self.assertEqual(fresh[0]["kind"], "psirt")
        self.assertNotIn("b", [f.get("id") for f in fresh])
        self.assertEqual(len(fresh), bastion.MAX_FRESH)
        self.assertTrue(all(f["kind"] in ("psirt", "threat") for f in fresh))


class ProductTests(unittest.TestCase):
    def test_products_from_description(self):
        text = ("A Double Free vulnerability [CWE-415] in FortiOS, FortiProxy and FortiSwitch may allow ... "
                "see FortiGuard; FortiOS again; FortiOS-6K7K, FortiClientEMS, FortiWeb.")
        self.assertEqual(bastion.products_in(text), ["FortiOS", "FortiProxy", "FortiSwitch", "FortiOS-6K7K"])
        self.assertEqual(bastion.products_in("Linux kernel RCE, Fortinet says"), [])

    def test_products_on_parsed_psirt(self):
        feed = b"""<rss><channel><item><title>Broken authorization</title>
<link>https://fortiguard.fortinet.com/psirt/FG-IR-26-183</link><guid>g</guid>
<description><![CDATA[<p><strong>CVSSv3 Score:</strong> 3.4</p><p>A missing authorization vulnerability in FortiSIEM GUI</p>]]></description>
</item></channel></rss>"""
        self.assertEqual(bastion.parse_feed("psirt", feed)[0]["products"], ["FortiSIEM"])


def rss(*ids):
    items = "".join("<item><title>T %s</title><guid>%s</guid></item>" % (i, i) for i in ids)
    return ("<rss><channel>%s</channel></rss>" % items).encode()


FILESTORE = "https://filestore.fortinet.com/fortiguard/rss/%s.xml"


class StateTests(unittest.TestCase):
    """cmd_fetch / cmd_ack against a fake network and a temporary state dir.

    The fake serves each feed from its canonical URL and from FILESTORE (where
    the real feeds redirect to), with an ETag derived from the content, and
    answers 304 when sent the current one."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (bastion.CACHE_FILE, bastion.STATE_FILE, bastion.download, bastion.COALESCE_SEC, bastion.FETCH_DEADLINE)
        bastion.CACHE_FILE = os.path.join(self.tmp.name, "c", "feeds.json")
        bastion.STATE_FILE = os.path.join(self.tmp.name, "s", "state.json")
        bastion.COALESCE_SEC = 0  # tests fetch back to back on purpose
        self.feeds = {}    # kind -> bytes, or missing for "offline"
        self.broken = set()  # URLs that fail even when the feed is up
        self.stall = {}    # kind -> callable run inside that feed's download
        self.release = threading.Event()  # set in tearDown: frees stalled downloads
        self.calls = []    # (url, validators)
        lock = threading.Lock()

        def fake_download(url, validators=None):
            with lock:
                self.calls.append((url, dict(validators or {})))
            kind = next(k for k, u in bastion.FEEDS.items() if url in (u, FILESTORE % k))
            if kind in self.stall:
                self.stall[kind]()
            if kind not in self.feeds or url in self.broken:
                raise OSError("offline")
            data = self.feeds[kind]
            etag = '"%08x"' % zlib.crc32(data)
            if validators and validators.get("If-None-Match") == etag:
                return None, {}
            return data, {"url": FILESTORE % kind, "etag": etag, "lastModified": ""}
        bastion.download = fake_download

    def tearDown(self):
        self.release.set()
        bastion.CACHE_FILE, bastion.STATE_FILE, bastion.download, bastion.COALESCE_SEC, bastion.FETCH_DEADLINE = self.saved
        self.tmp.cleanup()

    def fetch(self):
        return bastion.cmd_fetch()

    def all_up(self):
        self.feeds = {"psirt": rss("p1", "p2"), "outbreak": rss("o1"), "threat": rss("t1")}

    def test_offline_first_run_does_not_flood_later(self):
        self.assertEqual(self.fetch()["fresh"], [])                     # all three feeds down
        self.all_up()
        result = self.fetch()
        self.assertEqual(result["fresh"], [])                            # backlog is baseline
        self.assertEqual(result["unreadTotal"], 0)
        self.feeds["outbreak"] = rss("o2", "o1")
        result = self.fetch()
        self.assertEqual([f["title"] for f in result["fresh"]], ["T o2"])  # real news still announced
        self.assertEqual(result["unreadTotal"], 1)

    def test_feed_down_on_first_run_is_seeded_when_it_returns(self):
        self.feeds = {"psirt": rss("p1"), "outbreak": rss("o1")}       # threat down
        self.fetch()
        self.feeds["threat"] = rss("t1", "t2")
        self.feeds["psirt"] = rss("p2", "p1")
        result = self.fetch()
        self.assertEqual(sorted(f["title"] for f in result["fresh"]), ["T p2"])

    def test_legacy_state_keeps_announcing(self):
        os.makedirs(os.path.dirname(bastion.STATE_FILE))
        with open(bastion.STATE_FILE, "w") as handle:
            json.dump({"known": ["p1"], "acked": ["p1"]}, handle)       # written before "seeded"
        self.feeds = {"psirt": rss("p2", "p1"), "outbreak": rss(), "threat": rss()}
        self.assertEqual([f["title"] for f in self.fetch()["fresh"]], ["T p2"])

    def test_ack_only_given_ids(self):
        self.feeds = {"psirt": rss("p1"), "outbreak": rss(), "threat": rss()}
        self.fetch()
        self.feeds["psirt"] = rss("p3", "p2", "p1")
        self.fetch()
        result = bastion.cmd_ack(["p2", "not-cached"])
        unread = [i["id"] for i in result["psirt"] if i["unread"]]
        self.assertEqual(unread, ["p3"])
        self.assertEqual(bastion.cmd_ack()["unreadTotal"], 0)

    def test_ack_with_empty_list_acks_nothing(self):
        self.feeds = {"psirt": rss("p1"), "outbreak": rss(), "threat": rss()}
        self.fetch()
        self.feeds["psirt"] = rss("p2", "p1")
        self.fetch()
        self.assertEqual(bastion.cmd_ack([])["unreadTotal"], 1)

    def test_failed_fetch_keeps_old_time(self):
        self.all_up()
        first = self.fetch()["fetchedAt"]
        self.assertGreater(first, 0)
        self.feeds = {}
        result = self.fetch()
        self.assertEqual(result["fetchedAt"], first)                     # nothing answered: not "fresh"
        self.assertEqual(sorted(result["errors"]), ["outbreak", "psirt", "threat"])
        self.assertEqual([i["id"] for i in result["psirt"]], ["p1", "p2"])  # last copy still shown

    def test_partial_failure_moves_time_forward(self):
        self.all_up()
        self.fetch()
        del self.feeds["threat"]
        result = self.fetch()
        self.assertEqual(list(result["errors"]), ["threat"])
        self.assertEqual([i["id"] for i in result["threat"]], ["t1"])

    def test_unchanged_feed_costs_a_304(self):
        self.all_up()
        self.fetch()
        self.calls.clear()
        result = self.fetch()
        self.assertEqual(result["errors"], {})
        self.assertEqual([i["id"] for i in result["psirt"]], ["p1", "p2"])
        # Straight to the learned host, with the stored validator.
        for url, validators in self.calls:
            self.assertTrue(url.startswith("https://filestore.fortinet.com/"), url)
            self.assertIn("If-None-Match", validators)

    def test_no_validators_without_cached_items(self):
        self.all_up()
        self.fetch()
        with open(bastion.CACHE_FILE) as handle:
            cache = json.load(handle)
        cache["psirt"] = []
        with open(bastion.CACHE_FILE, "w") as handle:
            json.dump(cache, handle)
        self.calls.clear()
        result = self.fetch()
        self.assertEqual([i["id"] for i in result["psirt"]], ["p1", "p2"])  # full download, not a 304 into nothing
        psirt_calls = [v for u, v in self.calls if u in (bastion.FEEDS["psirt"], FILESTORE % "psirt")]
        self.assertEqual(psirt_calls, [{}])

    def test_old_cache_format_is_not_reused(self):
        self.all_up()
        self.fetch()
        with open(bastion.CACHE_FILE) as handle:
            cache = json.load(handle)
        cache["format"] = 1
        with open(bastion.CACHE_FILE, "w") as handle:
            json.dump(cache, handle)
        self.calls.clear()
        self.fetch()
        self.assertTrue(all(v == {} for _, v in self.calls))
        self.assertTrue(all(u in bastion.FEEDS.values() for u, _ in self.calls))

    def test_learned_url_falls_back_to_canonical(self):
        self.all_up()
        self.fetch()
        self.broken = {FILESTORE % "psirt"}
        self.feeds["psirt"] = rss("p3", "p1", "p2")
        self.calls.clear()
        result = self.fetch()
        self.assertEqual(result["errors"], {})
        self.assertEqual([i["id"] for i in result["psirt"]], ["p3", "p1", "p2"])
        self.assertEqual([u for u, _ in self.calls if u in (bastion.FEEDS["psirt"], FILESTORE % "psirt")], [FILESTORE % "psirt", bastion.FEEDS["psirt"]])

    def test_feeds_are_fetched_in_parallel_with_a_deadline(self):
        # No tight wall-clock margins to race: a hung feed blocks until
        # tearDown (or 20 s), and parallelism is proven by a rendezvous rather
        # than by elapsed time.
        self.all_up()
        bastion.FETCH_DEADLINE = 1
        self.stall = {"threat": lambda: self.release.wait(20)}   # hangs well past the deadline
        started = time.monotonic()
        result = self.fetch()
        self.assertLess(time.monotonic() - started, 10)   # gave up; didn't wait for the hung feed
        self.assertEqual(list(result["errors"]), ["threat"])
        self.assertIn("TimeoutError", result["errors"]["threat"])
        self.assertEqual([i["id"] for i in result["psirt"]], ["p1", "p2"])

        # Each feed's first download waits until all three are in flight at
        # once. Fetched one after another, the first wait times out and that
        # feed errors. One-shot, so a fallback second download passes through.
        arrived, everyone, count = set(), threading.Event(), threading.Lock()

        def meet(kind):
            with count:
                arrived.add(kind)
                if len(arrived) == len(bastion.FEEDS):
                    everyone.set()
            if not everyone.wait(5):
                raise OSError("feeds were not fetched in parallel")

        self.stall = {kind: (lambda k=kind: meet(k)) for kind in bastion.FEEDS}
        bastion.FETCH_DEADLINE = 10
        self.assertEqual(self.fetch()["errors"], {})

    def test_back_to_back_fetches_coalesce(self):
        self.all_up()
        self.fetch()
        bastion.COALESCE_SEC = 60
        self.feeds["outbreak"] = rss("o2", "o1")
        self.calls.clear()
        result = self.fetch()
        self.assertEqual(self.calls, [])                    # reused: no network
        self.assertEqual(result["fresh"], [])
        self.assertEqual([i["id"] for i in result["outbreak"]], ["o1"])

    def test_no_coalescing_after_errors(self):
        self.feeds = {"psirt": rss("p1")}
        self.fetch()
        bastion.COALESCE_SEC = 60
        self.all_up()
        self.calls.clear()
        self.assertEqual(self.fetch()["errors"], {})
        self.assertNotEqual(self.calls, [])

    def test_malformed_cached_items_are_skipped(self):
        os.makedirs(os.path.dirname(bastion.CACHE_FILE))
        with open(bastion.CACHE_FILE, "w") as handle:
            json.dump({"fetchedAt": 1, "psirt": [{"title": "no id"}, 7, {"id": "p1", "title": "ok"}]}, handle)
        self.assertEqual([i["id"] for i in bastion.cmd_cached()["psirt"]], ["p1"])
        self.assertEqual([i["id"] for i in self.fetch()["psirt"]], ["p1"])  # feeds down: kept, minus junk


class RedirectTests(unittest.TestCase):
    CODES = (301, 302, 303, 307, 308)

    def test_every_redirect_code_uses_the_override(self):
        cls = bastion.FortinetOnlyRedirects
        for code in self.CODES:
            self.assertIs(getattr(cls, "http_error_%d" % code), cls.http_error_302, code)

    def test_off_site_redirect_refused(self):
        import urllib.error
        import urllib.request
        handler = bastion.FortinetOnlyRedirects()
        req = urllib.request.Request(bastion.FEEDS["psirt"])
        for target in ("https://evil.example/ir.xml", "http://filestore.fortinet.com/fortiguard/rss/ir.xml"):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                handler.redirect_request(req, None, 302, "Found", {}, target)
            caught.exception.close()
        ok = handler.redirect_request(req, None, 302, "Found", {}, "https://filestore.fortinet.com/fortiguard/rss/ir.xml")
        self.assertEqual(ok.full_url, "https://filestore.fortinet.com/fortiguard/rss/ir.xml")

    def _redirect_response(self, code, location, body_size):
        """A real http.client response to a redirect whose body is body_size
        bytes, served lazily; returns (response, function giving bytes consumed).
        Draining the body past MAX_BYTES fails at once instead of crawling
        through (and buffering) all of it."""
        import http.client
        import io

        lines = ["HTTP/1.1 %d Redirect" % code, "Content-Length: %d" % body_size]
        if location is not None:
            lines.append("Location: %s" % location)
        head = ("\r\n".join(lines) + "\r\n\r\n").encode()

        class Body(io.RawIOBase):
            def __init__(self):
                self.pos = 0

            def readable(self):
                return True

            def readinto(self, buf):
                if self.pos - len(head) > bastion.MAX_BYTES:
                    raise AssertionError("redirect body is being drained")
                n = min(len(buf), len(head) + body_size - self.pos, 64 * 1024)
                part = head[self.pos:self.pos + n]
                buf[:n] = part + b"A" * (n - len(part))
                self.pos += n
                return n

        raw = Body()

        class Sock:
            def makefile(self, mode):
                return io.BufferedReader(raw)

        resp = http.client.HTTPResponse(Sock())
        resp.begin()
        return resp, lambda: raw.pos - len(head)

    def _handle(self, code, target):
        import urllib.request
        handler = bastion.FortinetOnlyRedirects()
        followed = []

        class Parent:
            def open(self, new, timeout=None):
                followed.append(new.full_url)
                return "followed"

        handler.parent = Parent()
        req = urllib.request.Request(bastion.FEEDS["psirt"])
        req.timeout = bastion.TIMEOUT  # set by OpenerDirector.open in real use
        resp, consumed = self._redirect_response(code, target, 64 * bastion.MAX_BYTES)
        method = getattr(handler, "http_error_%d" % code)
        return (lambda: method(req, resp, code, "Redirect", resp.msg)), resp, consumed, followed

    def test_redirect_body_is_not_buffered(self):
        import urllib.error
        for code in self.CODES:
            call, resp, consumed, followed = self._handle(code, "https://filestore.fortinet.com/fortiguard/rss/ir.xml")
            self.assertEqual(call(), "followed", code)
            self.assertEqual(followed, ["https://filestore.fortinet.com/fortiguard/rss/ir.xml"])
            # Only header parsing's buffered read-ahead may be consumed, never the body.
            self.assertLess(consumed(), bastion.MAX_BYTES, code)
            self.assertTrue(resp.isclosed())

            call, resp, consumed, followed = self._handle(code, "https://evil.example/ir.xml")
            with self.assertRaises(urllib.error.HTTPError) as caught:
                call()
            caught.exception.close()
            self.assertEqual(followed, [])
            self.assertLess(consumed(), bastion.MAX_BYTES, code)

    def test_redirects_that_skip_redirect_request_are_closed_too(self):
        import urllib.error
        # A non-web Location: the stock handler raises before redirect_request.
        call, resp, consumed, followed = self._handle(302, "data:text/plain,x")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            call()
        caught.exception.close()
        self.assertTrue(resp.isclosed())
        self.assertLess(consumed(), bastion.MAX_BYTES)
        # No Location at all: the stock handler returns None.
        call, resp, consumed, followed = self._handle(302, None)
        self.assertIsNone(call())
        self.assertTrue(resp.isclosed())
        self.assertLess(consumed(), bastion.MAX_BYTES)


if __name__ == "__main__":
    unittest.main()
