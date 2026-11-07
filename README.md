# Bastion — FortiGuard Labs for the Omarchy bar

A radar next to the clock that keeps FortiGuard Labs one click away. It turns
Fortinet red while an Outbreak Alert or a critical PSIRT advisory is unread, and stays
bar-coloured otherwise; hover it for unread counts per feed. The sweep turns while a
refresh runs (not with animations off).

## Install

```
omarchy plugin add https://github.com/charbelsarkis/omarchy-bastion.git --enable
```

Update later with `omarchy plugin update charbel.bastion`.

## Remove

```
omarchy plugin remove charbel.bastion
rm -rf ~/.cache/omarchy-bastion ~/.local/state/omarchy-bastion   # optional: cached feeds and read state
```

## Dependencies

- `python3` (standard library only): the bundled `bastion.py` fetches and sanitizes the feeds.
- Omarchy's own `omarchy-launch-browser` and `omarchy-notification-send`, which ship with Omarchy.
- Network: three fixed HTTPS RSS feeds on fortiguard.com, see [Network](#network). No other
  services, no sudo, and nothing outside `~/.cache/omarchy-bastion` and
  `~/.local/state/omarchy-bastion` is written (plus the plugin's own entry in
  `~/.config/omarchy/shell.json` when you change its settings).

## Features

- **Outbreak Alerts** and **Threat Signals**: FortiGuard Labs headlines.
- **PSIRT advisories**: the latest Fortinet product security advisories with CVSS
  score, severity and the affected products (FortiOS, FortiSIEM, …).
- **FortiGuard lookup**: type a CVE, FG-IR id, IP, domain/URL, file hash or keyword
  and press Enter to open the matching fortiguard.com page in your browser.

The panel lists Outbreak Alerts, then Threat Signals, then the Fortinet-specific PSIRT
advisories. Click a row to open it. Keys: `/` focuses lookup, `↑/↓` move, `Enter` opens,
`R` refreshes, `Esc` closes. Right- or middle-click the radar to refresh.

## Notifications

When a refresh finds new items, Bastion sends a desktop notification for each one.
Clicking a notification opens that advisory or alert on FortiGuard.

- PSIRT advisories at or above the threshold (default **high**, CVSS 7.0+). Critical
  ones use critical urgency.
- New Outbreak Alerts and Threat Signals.
- At most three individual notifications per refresh, most severe first; the rest are
  rolled into one "N more FortiGuard alerts" notification that opens the panel.
- A feed's first successful fetch never notifies, so you don't get the whole backlog at
  once, even if the very first fetch ran offline or with a feed down.
- Notifications are sent one at a time, most severe last, so it sits on top of the stack.

Notifications follow refreshes: hourly in the background, or when you refresh by hand.
To preview them: `omarchy-shell charbel.bastion testNotifications`.

## Network

Fetches only three fixed HTTPS RSS feeds on fortiguard.com (15s timeout, 2 MiB cap;
redirects are followed only to HTTPS Fortinet hosts),
hourly in the background. Switch background refresh off with the toggle in the panel
header; it then refreshes only when you open the panel (if older than 15 min) or press
refresh. Lookups never touch the network from the shell; they open your browser.

Settings (`~/.config/omarchy/shell.json`, entry `charbel.bastion`):
`backgroundRefresh` (true), `refreshIntervalMin` (60), `notify` (true),
`notifyPsirt` (`off`/`critical`/`high`/`medium`/`all`, default `high`), `notifyOutbreaks` (true),
`notifyThreatSignals` (true).

Cache: `~/.cache/omarchy-bastion/feeds.json`. Read state: `~/.local/state/omarchy-bastion/state.json`.

## IPC

```
omarchy-shell charbel.bastion toggle|open|close|refresh|status|testNotifications
omarchy-shell charbel.bastion lookup CVE-2024-21762     # opens the browser
omarchy-shell charbel.bastion lookupUrl google.com       # prints the URL only
```

## Tests

Run `omarchy restart shell` after edits: `Model.js` stays cached across hot reloads, and
hot reload has been seen to skip `Panel.qml` changes too.


```
python3 -I -m unittest discover -s tests
node tests/model.test.js
```

Not affiliated with or endorsed by Fortinet, Inc. Fortinet, FortiGuard and FortiGate
are trademarks of Fortinet, Inc.; data comes from FortiGuard Labs' public RSS feeds.
