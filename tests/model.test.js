// Regression tests for Model.js. Run: node tests/model.test.js
const fs = require("fs")
const path = require("path")
const assert = require("assert")
const src = fs.readFileSync(path.join(__dirname, "..", "Model.js"), "utf8").replace(/^\.pragma library\s*/, "")
const module_ = { exports: {} }
new Function("module", src)(module_)
const M = module_.exports

const BASE = "https://www.fortiguard.com"
const cases = [
  ["CVE-2024-21762", "cve", BASE + "/search?q=CVE-2024-21762"],
  ["cve-2024-21762", "cve", BASE + "/search?q=CVE-2024-21762"],
  ["FG-IR-26-187", "psirt", BASE + "/psirt/FG-IR-26-187"],
  ["8.8.8.8", "ip", BASE + "/search?q=8.8.8.8"],
  ["2001:db8::1", "ip", BASE + "/search?q=2001%3Adb8%3A%3A1"],
  ["d41d8cd98f00b204e9800998ecf8427e", "hash", BASE + "/search?q=d41d8cd98f00b204e9800998ecf8427e"],
  ["example.com", "url", BASE + "/search?q=example.com"],
  ["https://evil.example/a?b=c&d", "url", BASE + "/search?q=https%3A%2F%2Fevil.example%2Fa%3Fb%3Dc%26d"],
  ["Log4j2 Vulnerability", "keyword", BASE + "/search?q=Log4j2%20Vulnerability"],
]
for (const [q, kind, url] of cases) {
  assert.strictEqual(M.classify(q).kind, kind, q)
  assert.strictEqual(M.lookupUrl(q), url, q)
}

for (const [q] of cases) assert.ok(!M.lookupUrl(q).includes("/webfilter"), "dead /webfilter endpoint used for " + q)

// Injection-shaped input stays inside the query string of the fixed origin.
for (const evil of ["x/../../evil", "a#frag", "\"; rm -rf ~", "<img src=https://example.invalid/t>", "?q=1&next=//evil.example"]) {
  const u = M.lookupUrl(evil)
  assert.ok(u.startsWith(BASE + "/"), evil)
  const rest = u.slice(BASE.length)
  assert.ok(!/[<>"#\s]/.test(rest), "unencoded char in " + u)
}
assert.strictEqual(M.lookupUrl(""), "")
assert.strictEqual(M.lookupUrl("a‮b"), "")
assert.strictEqual(M.lookupUrl("x".repeat(300)), "")

// Feed links: only https on Fortinet hosts.
assert.strictEqual(M.safeFeedLink("https://fortiguard.fortinet.com/psirt/FG-IR-1"), "https://fortiguard.fortinet.com/psirt/FG-IR-1")
assert.strictEqual(M.safeFeedLink("javascript:alert(1)"), "")
assert.strictEqual(M.safeFeedLink("https://fortinet.com.evil.example/"), "")
assert.strictEqual(M.safeFeedLink("http://fortiguard.fortinet.com/x"), "")

// Sanitizing a corrupted/hostile cache.
const r = M.sanitizeResult({ unreadCritical: 1e9, psirt: [{ title: "t‮<b>", cvss: 42, severity: "pwn", link: "file:///etc/passwd", cves: ["CVE-1-1", "CVE-2026-0001"], advisory: "x" }], outbreak: "nope" })
assert.strictEqual(r.unreadCritical, 99)
assert.strictEqual(r.psirt[0].cvss, -1)
assert.strictEqual(r.psirt[0].severity, "")
assert.strictEqual(r.psirt[0].link, "")
assert.deepStrictEqual(r.psirt[0].cves, ["CVE-2026-0001"])
assert.strictEqual(r.psirt[0].advisory, "")
assert.ok(!r.psirt[0].title.includes("‮"))
assert.deepStrictEqual(r.outbreak, [])

// Notification bodies: markup-shaped input is neutralized, no leading dashes.
const n = M.notificationText("--help <img src=https://example.invalid/t> & co")
assert.ok(!/[<>&]/.test(n), n)
assert.ok(!n.startsWith("-"), n)

// Ages.
assert.deepStrictEqual(M.ageParts(1000, 1000 + 30), { unit: "minutes", value: 1 })
assert.deepStrictEqual(M.ageParts(1000, 1000 + 7200), { unit: "hours", value: 2 })
assert.deepStrictEqual(M.ageParts(1000, 1000 + 3 * 86400), { unit: "days", value: 3 })
assert.strictEqual(M.ageParts(0, 5), null)

// Notification rules.
const fresh = [
  { kind: "psirt", title: "Low thing", severity: "low", cvss: 2.1, advisory: "FG-IR-26-001", link: "https://fortiguard.fortinet.com/psirt/FG-IR-26-001", published: 5 },
  { kind: "threat", title: "Signal", link: "https://fortiguard.fortinet.com/threat-signal-report/1", published: 9 },
  { kind: "psirt", title: "Crit <b>thing</b>", severity: "critical", cvss: 9.8, advisory: "FG-IR-26-002", link: "https://evil.example/x", published: 4 },
  { kind: "outbreak", title: "Outbreak", link: "https://fortiguard.fortinet.com/outbreak-alert/x", published: 8 },
  { kind: "psirt", title: "High thing", severity: "high", cvss: 7.5, advisory: "FG-IR-26-003", link: "", published: 3 },
]
let plan = M.notificationsFor(fresh, { psirtLevel: "high", outbreaks: true, threats: true })
// A high Fortinet advisory outranks a generic threat signal.
assert.deepStrictEqual(plan.single.map(n => n.title), ["Crit <b>thing</b>", "Outbreak", "High thing"])
assert.deepStrictEqual(plan.single.map(n => n.kind + ":" + n.urgency), ["psirt:critical", "outbreak:normal", "psirt:normal"])
assert.strictEqual(plan.overflow, 1)                      // "Signal"; "Low thing" is below the threshold
assert.strictEqual(plan.single[0].link, "")                // non-Fortinet link is never clickable
assert.ok(plan.single[0].body.startsWith("FG-IR-26-002 · CVSS 9.8 · "), plan.single[0].body)
assert.ok(!/[<>]/.test(plan.single[0].body))
plan = M.notificationsFor(fresh, { psirtLevel: "off", outbreaks: false, threats: false })
assert.deepStrictEqual(plan, { single: [], overflow: 0 })
plan = M.notificationsFor(fresh, { psirtLevel: "critical", outbreaks: false, threats: true })
assert.deepStrictEqual(plan.single.map(n => n.title), ["Crit <b>thing</b>", "Signal"])
plan = M.notificationsFor(fresh, { psirtLevel: "all", outbreaks: false, threats: false })
assert.deepStrictEqual(plan.single.map(n => n.urgency), ["critical", "normal", "low"])
assert.strictEqual(M.normalizeNotifyLevel("bogus"), "high")
assert.deepStrictEqual(M.notificationsFor([], {}), { single: [], overflow: 0 })
const sr = M.sanitizeResult({ fresh: [{ kind: "rm -rf", title: "x" }, { kind: "threat", title: "ok", link: "javascript:1" }] })
assert.deepStrictEqual(sr.fresh.map(f => f.kind + ":" + f.link), ["threat:"])

// Products: only Fortinet product-shaped names survive sanitizing, and they
// lead the PSIRT notification body.
const pr = M.sanitizeResult({ psirt: [{ title: "t", products: ["FortiOS", "<img>", "Evil", "FortiProxy", 7] }] })
assert.deepStrictEqual(pr.psirt[0].products, ["FortiOS", "FortiProxy"])
assert.deepStrictEqual(M.sanitizeResult({ psirt: [{ title: "t" }] }).psirt[0].products, [])
plan = M.notificationsFor([{ kind: "psirt", title: "Double free", severity: "critical", cvss: 9.1, advisory: "FG-IR-26-182",
  products: ["FortiOS", "FortiProxy", "FortiSwitch", "FortiWeb"], link: "" }], { psirtLevel: "high" })
assert.strictEqual(plan.single[0].body, "FG-IR-26-182 · CVSS 9.1 · FortiOS, FortiProxy, FortiSwitch +1 · Double free")

// Compact lists keep one-line rows short.
assert.strictEqual(M.compactList(["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"], 1), "CVE-2026-1 +2")
assert.strictEqual(M.compactList(["FortiOS"], 2), "FortiOS")
assert.strictEqual(M.compactList(undefined, 2), "")
assert.strictEqual(M.compactList("FortiOS", 2), "")
// QML hands nested lists over as array-likes, not real Arrays.
assert.strictEqual(M.compactList({ length: 2, 0: "FortiOS", 1: "FortiProxy" }, 1), "FortiOS +1")

// Held items: the panel lists all of them.
const many = n => Array.from({ length: n }, (_, i) => ({ id: "i" + i, title: "t" + i }))
const held = M.sanitizeResult({ psirt: many(20), outbreak: many(9), threat: many(9) })
assert.deepStrictEqual([held.psirt.length, held.outbreak.length, held.threat.length], [15, 5, 5])

// Background refresh timing (wall-clock seconds).
const H = 3600, RETRY = M.RETRY_SEC
assert.strictEqual(M.refreshDue(10 * H, 0, false, 0, H), true)                  // never fetched
assert.strictEqual(M.refreshDue(10 * H, 10 * H - 60, false, 0, H), false)       // fresh
assert.strictEqual(M.refreshDue(10 * H, 9 * H, false, 0, H), true)              // one interval old
assert.strictEqual(M.refreshDue(10 * H, 2 * H, false, 2 * H, H), true)         // slept through 8 intervals
assert.strictEqual(M.refreshDue(10 * H, 10 * H - 60, true, 10 * H - RETRY, H), true)       // errors: retry
assert.strictEqual(M.refreshDue(10 * H, 10 * H - 60, true, 10 * H - RETRY + 1, H), false)  // ...but not too soon
assert.strictEqual(M.refreshDue(10 * H, 2 * H, false, 10 * H - 30, H), false)  // just tried
assert.strictEqual(M.refreshDue(10 * H, 2 * H, false, 11 * H, H), true)        // clock went backwards

console.log("model.test.js: all assertions passed")
