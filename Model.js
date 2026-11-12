.pragma library

// Pure helpers for Bastion. No QML imports so they can be unit-tested in node.

var LOOKUP_BASE = "https://www.fortiguard.com"
var MAX_QUERY = 256

// Characters we never allow in a lookup query: control chars and bidi overrides.
var UNSAFE_RE = /[\u0000-\u001f\u007f‪-‮⁦-⁩]/

var CVE_RE = /^CVE-\d{4}-\d{4,7}$/i
var PSIRT_RE = /^FG-IR-\d{2}-\d{1,5}$/i
var IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
var IPV6_RE = /^[0-9a-f:]+$/i
var HASH_RE = /^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i
var DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

function normalizeQuery(raw) {
  var q = String(raw === undefined || raw === null ? "" : raw).trim()
  if (q === "" || q.length > MAX_QUERY || UNSAFE_RE.test(q)) return ""
  return q
}

function isIpv6(q) {
  return q.indexOf(":") >= 0 && q.split(":").length >= 3 && q.split(":").length <= 8 && IPV6_RE.test(q)
}

// Returns a host for URL-ish input ("https://evil.example/path", "evil.example/x"),
// or "" when the input isn't a URL or domain.
function hostOf(q) {
  var s = q.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
  s = s.split(/[\/?#]/)[0]
  s = s.replace(/^[^@]*@/, "").replace(/:\d+$/, "")
  return DOMAIN_RE.test(s) ? s.toLowerCase() : ""
}

// Classify a lookup query. kind is one of: cve, psirt, ip, hash, url, keyword, invalid.
function classify(raw) {
  var q = normalizeQuery(raw)
  if (q === "") return { kind: "invalid", query: "" }
  if (CVE_RE.test(q)) return { kind: "cve", query: q.toUpperCase() }
  if (PSIRT_RE.test(q)) return { kind: "psirt", query: q.toUpperCase() }
  if (IPV4_RE.test(q) || isIpv6(q)) return { kind: "ip", query: q.toLowerCase() }
  if (HASH_RE.test(q)) return { kind: "hash", query: q.toLowerCase() }
  if (/\s/.test(q) === false && hostOf(q) !== "") return { kind: "url", query: q }
  return { kind: "keyword", query: q }
}

// Build the FortiGuard page for a classified query. FortiGuard's /search
// answers every kind except advisory ids: domains and URLs come back with
// their Web Filtering category and Secure DNS verdict, IPs with geolocation,
// hashes with IOC verdicts. (The old /webfilter?q= deep link is gone: the
// lookup is now a POST form with signed one-time tokens.) Every user-supplied value
// is percent-encoded so nothing can escape the fixed https://www.fortiguard.com
// origin.
function lookupUrl(raw) {
  var c = classify(raw)
  switch (c.kind) {
  case "invalid": return ""
  case "psirt": return LOOKUP_BASE + "/psirt/" + encodeURIComponent(c.query)
  default: return LOOKUP_BASE + "/search?q=" + encodeURIComponent(c.query)
  }
}

// Only open feed links that are https on a Fortinet-owned host.
function safeFeedLink(raw) {
  var link = String(raw || "")
  if (link.length > 300 || UNSAFE_RE.test(link) || /\s/.test(link)) return ""
  var m = /^https:\/\/([a-z0-9.-]+)(\/[^\s]*)?$/i.exec(link)
  if (!m) return ""
  var host = m[1].toLowerCase()
  if (host === "fortinet.com" || host === "fortiguard.com" || /\.fortinet\.com$/.test(host) || host === "www.fortiguard.com")
    return link
  return ""
}

function severityRank(sev) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[sev] || 0
}

// Seconds since `ts` bucketed for display: { unit: "minutes"|"hours"|"days", value }.
function ageParts(ts, nowSec) {
  if (!ts || ts <= 0) return null
  var delta = Math.max(0, Math.floor(nowSec - ts))
  if (delta < 3600) return { unit: "minutes", value: Math.max(1, Math.floor(delta / 60)) }
  if (delta < 86400) return { unit: "hours", value: Math.floor(delta / 3600) }
  return { unit: "days", value: Math.floor(delta / 86400) }
}

// Items held per feed (bastion.py MAX_ITEMS). The panel lists all of them, so
// acking what it holds acks exactly what it showed.
var FEED_LIMITS = { psirt: 15, outbreak: 5, threat: 5 }

// Coerce helper output into the shape the panel expects, dropping anything
// unexpected. Defends against a corrupted cache file.
function sanitizeResult(obj) {
  var out = { fetchedAt: 0, errors: {}, psirt: [], outbreak: [], threat: [], unreadCritical: 0, unreadTotal: 0, fresh: [] }
  if (!obj || typeof obj !== "object") return out
  out.fetchedAt = Number(obj.fetchedAt) > 0 ? Number(obj.fetchedAt) : 0
  out.unreadCritical = Math.max(0, Math.min(99, Number(obj.unreadCritical) | 0))
  out.unreadTotal = Math.max(0, Math.min(999, Number(obj.unreadTotal) | 0))
  if (obj.errors && typeof obj.errors === "object") {
    for (var k in obj.errors) if (k === "psirt" || k === "outbreak" || k === "threat") out.errors[k] = str(obj.errors[k], 160)
  }
  for (var kind in FEED_LIMITS) {
    var list = Array.isArray(obj[kind]) ? obj[kind].slice(0, FEED_LIMITS[kind]) : []
    out[kind] = list.map(function(it) { return sanitizeItem(it) }).filter(function(it) { return it.title !== "" })
  }
  out.fresh = (Array.isArray(obj.fresh) ? obj.fresh : []).slice(0, 20).map(function(it) {
    var item = sanitizeItem(it)
    var kind = it && typeof it.kind === "string" ? it.kind : ""
    item.kind = (kind === "psirt" || kind === "outbreak" || kind === "threat") ? kind : ""
    return item
  }).filter(function(it) { return it.kind !== "" && it.title !== "" })
  return out
}

function str(v, limit) {
  var s = (v === undefined || v === null) ? "" : String(v)
  s = s.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, " ")
  return s.length > limit ? s.slice(0, limit - 1) + "…" : s
}

function sanitizeItem(it) {
  it = it || {}
  var cvss = Number(it.cvss)
  var sev = ["critical", "high", "medium", "low", "info"].indexOf(it.severity) >= 0 ? it.severity : ""
  return {
    id: str(it.id, 300),
    title: str(it.title, 160),
    link: safeFeedLink(it.link),
    published: Number(it.published) > 0 ? Number(it.published) : 0,
    summary: str(it.summary, 280),
    advisory: /^FG-IR-\d{2}-\d{1,5}$/.test(String(it.advisory || "")) ? String(it.advisory) : "",
    cvss: it.cvss !== null && it.cvss !== undefined && isFinite(cvss) && cvss >= 0 && cvss <= 10 ? cvss : -1,
    severity: sev,
    cves: (Array.isArray(it.cves) ? it.cves : []).filter(function(c) { return /^CVE-\d{4}-\d{4,7}$/.test(String(c)) }).slice(0, 8),
    products: (Array.isArray(it.products) ? it.products : []).filter(function(p) { return /^Forti[A-Za-z0-9-]{1,32}$/.test(String(p)) }).slice(0, 4),
    unread: it.unread === true
  }
}

// "FortiOS, FortiProxy +1": the first `shown` entries, then how many more, so a
// long list can't push the rest of a one-line row out of view.
// Accepts any array-like: lists read back through a Repeater's modelData are
// Qt sequence wrappers, for which Array.isArray() is false.
function compactList(list, shown) {
  list = list && typeof list !== "string" && typeof list.length === "number" ? Array.prototype.slice.call(list) : []
  var head = list.slice(0, shown).join(", ")
  return list.length > shown ? head + " +" + (list.length - shown) : head
}

// Plain-text, single-line notification body (notifications render markup, so
// strip anything tag-shaped and escape the rest).
function notificationText(s) {
  // A leading dash would be read as an option by omarchy-notification-send.
  return str(s, 200).replace(/[<>&]/g, function(ch) { return { "<": "‹", ">": "›", "&": "+" }[ch] }).replace(/^[\s-]+/, "")
}

var NOTIFY_LEVELS = ["off", "critical", "high", "medium", "all"]
var MAX_SINGLE_NOTIFICATIONS = 3

function normalizeNotifyLevel(v) {
  return NOTIFY_LEVELS.indexOf(v) >= 0 ? v : "high"
}

function psirtPasses(item, level) {
  if (level === "off") return false
  if (level === "all") return true
  var need = { critical: 4, high: 3, medium: 2 }[level]
  return severityRank(item.severity) >= need
}

// Decide which fresh items become desktop notifications.
// prefs: { psirtLevel: off|critical|high|medium|all, outbreaks: bool, threats: bool }
// Returns { single: [{kind, urgency, title, body, link}], overflow: n }. The most
// severe items are notified one by one (at most three); the rest are counted
// so the caller can send one summary instead of flooding the screen.
function notificationsFor(fresh, prefs) {
  prefs = prefs || {}
  var level = normalizeNotifyLevel(prefs.psirtLevel)
  var picked = (fresh || []).filter(function(it) {
    if (it.kind === "psirt") return psirtPasses(it, level)
    if (it.kind === "outbreak") return prefs.outbreaks !== false
    if (it.kind === "threat") return prefs.threats !== false
    return false
  })
  // Critical advisory > outbreak alert > high advisory > threat signal > the
  // rest: a high-severity Fortinet advisory must not drop into the "+N more"
  // summary behind generic threat signals.
  function weight(it) {
    if (it.kind === "psirt") return { critical: 10, high: 7 }[it.severity] || severityRank(it.severity)
    return it.kind === "outbreak" ? 9 : 5
  }
  picked.sort(function(a, b) { return weight(b) - weight(a) || (b.published || 0) - (a.published || 0) })

  var single = picked.slice(0, MAX_SINGLE_NOTIFICATIONS).map(function(it) {
    var parts = []
    if (it.kind === "psirt") {
      if (it.advisory) parts.push(it.advisory)
      if (it.cvss >= 0) parts.push("CVSS " + (Math.round(it.cvss * 10) / 10).toFixed(1))
      if (it.products && it.products.length > 0) parts.push(compactList(it.products, 3))
    }
    parts.push(it.title)
    var urgency = "normal"
    if (it.kind === "psirt") urgency = it.severity === "critical" ? "critical" : (severityRank(it.severity) >= 3 ? "normal" : "low")
    return { kind: it.kind, urgency: urgency, title: it.title, body: notificationText(parts.join(" · ")), link: safeFeedLink(it.link) }
  })
  return { single: single, overflow: Math.max(0, picked.length - single.length) }
}

// After a failed or recent attempt, wait this long before trying again.
var RETRY_SEC = 600

// Whether a background refresh is due. Works on wall-clock seconds, so a
// suspend that froze the Qt timers is noticed on the next tick after resume.
// Due when the data is older than the interval, or when the last fetch had
// errors, but never within RETRY_SEC of the last attempt (a clock that went
// backwards doesn't block refreshes).
function refreshDue(nowSec, fetchedAt, hasErrors, lastAttemptSec, intervalSec) {
  var since = nowSec - (lastAttemptSec || 0)
  if (since >= 0 && since < RETRY_SEC) return false
  if (!(fetchedAt > 0) || hasErrors) return true
  return nowSec - fetchedAt >= intervalSec
}

if (typeof module !== "undefined") {
  module.exports = { classify: classify, lookupUrl: lookupUrl, safeFeedLink: safeFeedLink, sanitizeResult: sanitizeResult,
    ageParts: ageParts, severityRank: severityRank, notificationText: notificationText, normalizeQuery: normalizeQuery,
    notificationsFor: notificationsFor, normalizeNotifyLevel: normalizeNotifyLevel, compactList: compactList,
    refreshDue: refreshDue, RETRY_SEC: RETRY_SEC, FEED_LIMITS: FEED_LIMITS }
}
