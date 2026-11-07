"""Regression tests for bastion.py. Run: python3 -I -m unittest discover -s tests"""
import importlib.util
import json
import os
import sys
import unittest

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


class StateTests(unittest.TestCase):
    """cmd_fetch / cmd_ack against a fake network and a temporary state dir."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.saved = (bastion.CACHE_FILE, bastion.STATE_FILE, bastion.download)
        bastion.CACHE_FILE = os.path.join(self.tmp.name, "c", "feeds.json")
        bastion.STATE_FILE = os.path.join(self.tmp.name, "s", "state.json")
        self.feeds = {}  # kind -> bytes, or missing for "offline"

        def fake_download(url):
            kind = next(k for k, u in bastion.FEEDS.items() if u == url)
            if kind not in self.feeds:
                raise OSError("offline")
            return self.feeds[kind]
        bastion.download = fake_download

    def tearDown(self):
        bastion.CACHE_FILE, bastion.STATE_FILE, bastion.download = self.saved
        self.tmp.cleanup()

    def fetch(self):
        return bastion.cmd_fetch()

    def test_offline_first_run_does_not_flood_later(self):
        self.assertEqual(self.fetch()["fresh"], [])                     # all three feeds down
        self.feeds = {"psirt": rss("p1", "p2"), "outbreak": rss("o1"), "threat": rss("t1")}
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


class RedirectTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
