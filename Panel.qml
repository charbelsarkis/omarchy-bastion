import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

// Bastion: a FortiGuard Labs companion for the Omarchy bar.
//
// - FortiGuard PSIRT advisories (Fortinet product vulnerabilities), with CVSS
//   severity and affected products. The bar icon is a radar that turns red for urgent news.
// - FortiGuard Outbreak Alerts and Threat Signals headlines.
// - A FortiGuard lookup box: CVE, FG-IR id, IP, domain/URL, file hash or
//   keyword, opened on fortiguard.com in the browser.
//
// Feeds come from three fixed HTTPS RSS URLs via bastion.py (timeout + size
// cap + sanitizing). Background refresh is hourly and can be switched off in
// the panel header. Not affiliated with or endorsed by Fortinet, Inc.
Panel {
  id: bastion
  moduleName: "charbel.bastion"
  ipcTarget: "charbel.bastion"
  manageIpc: false

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  // Fortinet-style red, used for the Fortinet-specific accents in the panel.
  readonly property color fortiRed: "#DA291C"
  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property string helperPath: decodeURIComponent(String(Qt.resolvedUrl("bastion.py")).replace(/^file:\/\//, ""))
  readonly property bool backgroundRefresh: bastion.setting("backgroundRefresh", true) === true
  readonly property int refreshIntervalMin: Math.max(15, Math.min(1440, Number(bastion.setting("refreshIntervalMin", 60)) || 60))
  // Notifications: master switch plus per-feed choices (see manifest schema).
  readonly property bool notifyEnabled: bastion.setting("notify", true) === true
  readonly property string notifyPsirtLevel: Model.normalizeNotifyLevel(bastion.setting("notifyPsirt", "high"))
  readonly property bool notifyOutbreaks: bastion.setting("notifyOutbreaks", true) === true
  readonly property bool notifyThreats: bastion.setting("notifyThreatSignals", true) === true

  property var feed: Model.sanitizeResult(null)
  property bool fetching: false
  // Helper jobs waiting for the running one: [{ command, args }], one per command.
  property var pendingJobs: []
  property real nowSec: Date.now() / 1000
  // Wall-clock second of the last fetch this copy started (see Model.refreshDue).
  property real lastAttemptSec: 0

  // Every monitor's bar builds its own copy of this widget. Only the copy that
  // answers IPC refreshes in the background; the others follow the shared
  // state file (stateWatch), so reading alerts on one screen clears them on all.
  readonly property bool leader: ipc.enabled
  readonly property string stateFile: {
    var base = String(Quickshell.env("XDG_STATE_HOME") || "")
    if (base === "") base = String(Quickshell.env("HOME") || "") + "/.local/state"
    return base + "/omarchy-bastion/state.json"
  }

  // Keyboard cursor over the flattened rows, in panel order: outbreak, threat,
  // then PSIRT (Fortinet-specific, so it sits last).
  property bool cursorActive: false
  property int cursorIndex: 0

  // Every held item is listed (Model.FEED_LIMITS), so closing the panel acks
  // only rows that were on screen.
  readonly property var psirtRows: feed.psirt
  readonly property var outbreakRows: feed.outbreak
  readonly property var threatRows: feed.threat
  readonly property int rowCount: psirtRows.length + outbreakRows.length + threatRows.length
  readonly property bool hasErrors: Object.keys(feed.errors).length > 0
  // Something urgent is unread: an outbreak alert or a critical PSIRT advisory.
  readonly property bool alerting: feed.unreadCritical > 0 || outbreakUnread > 0
  readonly property string radarGlyph: "󰐷"

  readonly property Item lookupField: panel.loadedContent ? panel.loadedContent.lookupField : null
  readonly property Item panelFlick: panel.loadedContent ? panel.loadedContent.panelFlick : null

  // ---- helper process -------------------------------------------------------

  function runHelper(command, args) {
    args = args || []
    if (helperProc.running) {
      // Queue it behind the running job; a repeat of a queued command merges
      // into it (acks pool their ids) so nothing is dropped or run twice.
      var queue = pendingJobs.slice()
      for (var i = 0; i < queue.length; i++) {
        if (queue[i].command !== command) continue
        var merged = queue[i].args.slice()
        for (var a = 0; a < args.length; a++) if (merged.indexOf(args[a]) < 0) merged.push(args[a])
        queue[i] = { command: command, args: merged }
        pendingJobs = queue
        return
      }
      queue.push({ command: command, args: args })
      pendingJobs = queue
      return
    }
    if (command === "fetch") fetching = true
    helperProc.command = ["python3", "-I", bastion.helperPath, command].concat(args)
    helperProc.running = true
  }

  // Ids of every item the panel lists right now (it lists all it holds), for
  // acking on close.
  function shownIds() {
    var ids = []
    var kinds = ["psirt", "outbreak", "threat"]
    for (var k = 0; k < kinds.length; k++)
      for (var i = 0; i < feed[kinds[k]].length; i++) if (feed[kinds[k]][i].id !== "") ids.push(feed[kinds[k]][i].id)
    return ids
  }

  function refresh() {
    bastion.lastAttemptSec = Date.now() / 1000
    runHelper("fetch")
  }

  function maybeRefresh() {
    if (Model.refreshDue(Date.now() / 1000, feed.fetchedAt, bastion.hasErrors, bastion.lastAttemptSec,
        bastion.refreshIntervalMin * 60))
      refresh()
  }

  function handleOutput(text, wasFetch) {
    var parsed = null
    try { parsed = JSON.parse(String(text || "").trim()) } catch (e) { parsed = null }
    if (!parsed) return
    bastion.feed = Model.sanitizeResult(parsed)
    if (wasFetch && bastion.notifyEnabled) announce(feed.fresh)
    clampCursor()
  }

  // Sends one notification per new alert (most severe first, at most three)
  // and a single summary for the rest. Returns how many were sent.
  function announce(items) {
    var plan = Model.notificationsFor(items, {
      psirtLevel: bastion.notifyPsirtLevel,
      outbreaks: bastion.notifyOutbreaks,
      threats: bastion.notifyThreats
    })
    var glyphs = { psirt: "󰒘", outbreak: "󰀦", threat: "󰑫" }
    // The newest notification lands on top of the stack, so send the summary
    // first and the most severe alert last.
    if (plan.overflow > 0)
      notify(strings.tn("notify.more", plan.overflow).arg(Commons.I18n.formatNumber(plan.overflow)),
        strings.t("notify.moreBody"), "low", bastion.radarGlyph, ["omarchy-shell", bastion.moduleName, "open"])
    for (var i = plan.single.length - 1; i >= 0; i--) {
      var n = plan.single[i]
      var headline = n.kind === "psirt"
        ? (n.urgency === "critical" ? strings.t("notify.psirtCritical") : strings.t("notify.psirt"))
        : strings.t("notify." + n.kind)
      // Clicking opens the advisory/alert; links are already limited to https Fortinet hosts.
      notify(headline, n.body, n.urgency, glyphs[n.kind], n.link !== "" ? ["omarchy-launch-browser", n.link] : [])
    }
    return plan.single.length + (plan.overflow > 0 ? 1 : 0)
  }

  function notify(headline, body, urgency, glyph, clickArgv) {
    var argv = ["omarchy-notification-send", "--app-name", "Bastion", "-g", glyph || bastion.radarGlyph, "-u", urgency,
      Model.notificationText(headline), body]
    // --exec must come last: it takes the rest of the line as the click command.
    if (clickArgv && clickArgv.length > 0) argv = argv.concat(["--exec"]).concat(clickArgv)
    // One at a time: parallel senders race, and arrival order is stack order.
    notifyQueue = notifyQueue.concat([argv])
    pumpNotifications()
  }

  property var notifyQueue: []

  function pumpNotifications() {
    if (notifyProc.running || notifyQueue.length === 0) return
    notifyProc.command = notifyQueue[0]
    notifyQueue = notifyQueue.slice(1)
    notifyProc.running = true
  }

  Process {
    id: notifyProc
    onExited: Qt.callLater(bastion.pumpNotifications)
  }

  function staleFor(seconds) {
    return feed.fetchedAt <= 0 || (Date.now() / 1000 - feed.fetchedAt) > seconds
  }

  // ---- settings ------------------------------------------------------------

  function persistSettings(values) {
    var entry = { id: bastion.moduleName }
    for (var existing in bastion.settings) if (existing !== "id") entry[existing] = bastion.settings[existing]
    for (var key in values) entry[key] = values[key]
    bastion.settings = entry
    if (bastion.bar && bastion.bar.shell && typeof bastion.bar.shell.updateEntryInline === "function")
      bastion.bar.shell.updateEntryInline(bastion.moduleName, entry)
  }

  function toggleBackgroundRefresh() {
    persistSettings({ backgroundRefresh: !bastion.backgroundRefresh })
  }

  // ---- lookup --------------------------------------------------------------

  function openUrl(url) {
    if (url === "") return
    Util.execArgv(["omarchy-launch-browser", url])
  }

  function lookup(text) {
    var url = Model.lookupUrl(text)
    if (url === "") return
    openUrl(url)
    bastion.close()
  }

  function lookupHint(text) {
    var c = Model.classify(text)
    if (text.trim() === "") return strings.t("lookup.hint")
    return strings.t("lookup.kind." + c.kind)
  }

  // ---- display helpers -----------------------------------------------------

  function ageText(ts) {
    var parts = Model.ageParts(ts, bastion.nowSec)
    if (!parts) return ""
    return strings.tn("age." + parts.unit, parts.value).arg(Commons.I18n.formatNumber(parts.value))
  }

  function statusText() {
    if (bastion.fetching) return strings.t("status.refreshing")
    if (feed.fetchedAt <= 0) return bastion.hasErrors ? strings.t("status.offline") : strings.t("status.never")
    var updated = strings.t("status.updated").arg(ageText(feed.fetchedAt))
    // Every feed failed: the data is as old as fetchedAt says, so say so.
    if (Object.keys(feed.errors).length >= 3) return strings.t("status.offlineSince").arg(updated)
    return bastion.hasErrors ? strings.t("status.partial").arg(updated) : updated
  }

  function severityColor(sev) {
    if (sev === "critical") return bastion.fortiRed
    if (sev === "high") return bastion.urgent
    return bastion.dim
  }

  function itemAt(index) {
    if (index < outbreakRows.length) return outbreakRows[index]
    index -= outbreakRows.length
    if (index < threatRows.length) return threatRows[index]
    index -= threatRows.length
    return index < psirtRows.length ? psirtRows[index] : null
  }

  // ---- keyboard cursor -----------------------------------------------------

  function clampCursor() {
    if (rowCount === 0) cursorIndex = 0
    else cursorIndex = Math.max(0, Math.min(rowCount - 1, cursorIndex))
  }

  function moveCursor(dy) {
    if (!cursorActive) { cursorActive = true; clampCursor(); return }
    if (dy < 0 && cursorIndex === 0) { focusLookup(); return }
    cursorIndex = Math.max(0, Math.min(rowCount - 1, cursorIndex + dy))
    scrollCursorIntoView()
  }

  function focusLookup() {
    cursorActive = false
    if (panelFlick) panelFlick.contentY = 0
    if (lookupField) lookupField.forceActiveFocus()
  }

  function activateCursor() {
    var item = itemAt(cursorIndex)
    if (item && item.link !== "") { openUrl(item.link); bastion.close() }
  }

  function scrollCursorIntoView() {
    var content = panel.loadedContent
    if (!panelFlick || !content) return
    Qt.callLater(function() {
      var item = content.rowItem(bastion.cursorIndex)
      if (!item) return
      var margin = Style.space(6)
      var top = item.mapToItem(panelFlick.contentItem, 0, 0).y
      var bottom = top + item.height
      var maxY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
      if (top < panelFlick.contentY + margin) panelFlick.contentY = Math.max(0, top - margin)
      else if (bottom > panelFlick.contentY + panelFlick.height - margin)
        panelFlick.contentY = Math.min(maxY, bottom + margin - panelFlick.height)
    })
  }

  // ---- lifecycle -----------------------------------------------------------

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  Component.onCompleted: runHelper("cached")

  onOpenedChanged: {
    if (opened) {
      bastion.nowSec = Date.now() / 1000
      bastion.cursorActive = false
      bastion.cursorIndex = 0
      if (panelFlick) panelFlick.contentY = 0
      if (staleFor(15 * 60)) refresh()
      Qt.callLater(function() { if (bastion.lookupField) bastion.lookupField.forceActiveFocus() })
    } else {
      if (bastion.lookupField) bastion.lookupField.text = ""
      // Rows stay marked while the panel is open; reading them clears the dots.
      // Ack only what was on screen: a fetch finishing now must stay unread.
      if (feed.unreadTotal > 0) runHelper("ack", shownIds())
    }
  }

  Process {
    id: helperProc
    property bool wasFetch: false
    onRunningChanged: if (running) wasFetch = command.length > 3 && command[3] === "fetch"
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: bastion.handleOutput(text, helperProc.wasFetch)
    }
    onExited: function(exitCode) {
      if (helperProc.wasFetch) bastion.fetching = false
      if (bastion.pendingJobs.length > 0) {
        var next = bastion.pendingJobs[0]
        bastion.pendingJobs = bastion.pendingJobs.slice(1)
        Qt.callLater(function() { bastion.runHelper(next.command, next.args) })
      }
    }
  }

  // Explicit paste for the lookup field (it is read-only, see there): at most
  // 1 KiB, given up after 2 s, read in a separate process off the GUI thread.
  Process {
    id: pasteProc
    command: ["sh", "-c", "timeout 2s wl-paste --no-newline --type text 2>/dev/null | head -c 1024"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (bastion.lookupField) bastion.lookupField.pasteText(text)
    }
  }

  // A helper run never needs this long (bastion.py gives up on the network
  // after 45 s); stop a stuck one so the jobs queued behind it can run.
  Timer {
    interval: 90000
    running: helperProc.running
    onTriggered: helperProc.running = false
  }

  // Background refresh (hourly by default; switchable from the panel). A
  // one-minute wall-clock check instead of one timer per interval: Qt timers
  // stop counting during suspend, so an hourly timer could fire up to an hour
  // after resume. The check also retries failed feeds (Model.refreshDue).
  Timer {
    interval: 60000
    repeat: true
    running: bastion.backgroundRefresh && bastion.leader
    onTriggered: bastion.maybeRefresh()
  }

  // First check shortly after startup, once the cached result has loaded.
  Timer {
    interval: 8000
    running: bastion.backgroundRefresh && bastion.leader
    repeat: false
    onTriggered: bastion.maybeRefresh()
  }

  // Another copy of the widget (other monitor) fetched or acked: reload.
  FileView {
    id: stateWatch
    path: bastion.stateFile
    watchChanges: true
    printErrors: false
    onFileChanged: bastion.runHelper("cached")
  }

  Timer {
    interval: 60000
    repeat: true
    running: bastion.opened
    onTriggered: bastion.nowSec = Date.now() / 1000
  }

  ShellIpc {
    id: ipc
    target: bastion.ipcTarget
    function open(): void { bastion.open() }
    function close(): void { bastion.close() }
    function show(): void { bastion.open() }
    function hide(): void { bastion.close() }
    function toggle(): void { bastion.toggle() }
    function refresh(): string { bastion.refresh(); return "ok" }
    function lookup(query: string): string {
      var url = Model.lookupUrl(query)
      if (url === "") return "invalid query"
      bastion.openUrl(url)
      return url
    }
    // Sends notifications for the newest cached item of each feed, through the
    // same rules and settings as real alerts. Returns how many were sent.
    function testNotifications(): string {
      var items = []
      var kinds = ["psirt", "outbreak", "threat"]
      for (var k = 0; k < kinds.length; k++) {
        var list = bastion.feed[kinds[k]]
        if (list.length > 0) {
          var it = Object.assign({}, list[0])
          it.kind = kinds[k]
          items.push(it)
        }
      }
      return String(bastion.notifyEnabled ? bastion.announce(items) : 0)
    }
    // Returns the FortiGuard URL a lookup would open, without opening it.
    function lookupUrl(query: string): string { return Model.lookupUrl(query) }
    function status(): string {
      return JSON.stringify({ unreadCritical: bastion.feed.unreadCritical, unreadTotal: bastion.feed.unreadTotal,
        fetchedAt: bastion.feed.fetchedAt, backgroundRefresh: bastion.backgroundRefresh, errors: bastion.feed.errors,
        leader: bastion.leader })
    }
  }

  // ---- bar button ----------------------------------------------------------

  // Unread counts per feed (whole feeds, not just shown rows), for the tooltip
  // and the alert colour.
  readonly property int outbreakUnread: countUnread(feed.outbreak)
  readonly property int threatUnread: countUnread(feed.threat)
  readonly property int psirtUnread: countUnread(feed.psirt)

  function iconTooltip() {
    var parts = []
    if (outbreakUnread > 0) parts.push(strings.tn("tooltip.outbreak", outbreakUnread).arg(Commons.I18n.formatNumber(outbreakUnread)))
    if (threatUnread > 0) parts.push(strings.tn("tooltip.threat", threatUnread).arg(Commons.I18n.formatNumber(threatUnread)))
    if (psirtUnread > 0) parts.push(strings.tn("tooltip.psirt", psirtUnread).arg(Commons.I18n.formatNumber(psirtUnread)))
    return parts.length > 0 ? strings.t("tooltip.title") + " · " + parts.join(" · ") : strings.t("tooltip.quiet")
  }

  // Radar: bar-coloured while calm, Fortinet red while an outbreak alert or a
  // critical advisory is unread. Ordinary news stays off the bar on purpose.
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: bastion.bar
    text: bastion.radarGlyph
    active: bastion.alerting
    activeColor: bastion.fortiRed
    tooltipText: bastion.iconTooltip()
    // The sweep turns while a refresh runs (not at all with animations off).
    textRotation: radarSweep.running ? button.sweepAngle : 0
    property real sweepAngle: 0
    NumberAnimation on sweepAngle {
      id: radarSweep
      running: bastion.fetching && Style.duration(1200) > 0
      from: 0; to: 360
      duration: Style.duration(1200)
      loops: Animation.Infinite
      easing.type: Easing.Linear
    }
    onPressed: function(b) {
      if (b === Qt.RightButton || b === Qt.MiddleButton) bastion.refresh()
      else bastion.toggle()
    }
  }

  // ---- panel ---------------------------------------------------------------

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: bastion
    bar: bastion.bar
    open: bastion.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(420))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(620))

    content: PanelKeyCatcher {
      id: keyCatcher
      property alias panelFlick: panelFlick
      property alias lookupField: lookupField
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      blocked: lookupField.activeFocus

      function rowItem(index) {
        var cols = [outbreakColumn, threatColumn, psirtColumn]
        for (var c = 0; c < cols.length; c++) {
          var rows = []
          for (var i = 0; i < cols[c].children.length; i++)
            if (cols[c].children[i].rowIndex !== undefined) rows.push(cols[c].children[i])
          for (var j = 0; j < rows.length; j++) if (rows[j].rowIndex === index) return rows[j]
        }
        return null
      }

      onMoveRequested: function(dx, dy) { if (dy !== 0) bastion.moveCursor(dy) }
      onActivateRequested: if (bastion.cursorActive) bastion.activateCursor()
      onCloseRequested: bastion.close()
      onTabRequested: function(direction) { bastion.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R") bastion.refresh()
        else if (t === "/") bastion.focusLookup()
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(12)

          // -- header --
          PanelHero {
            id: hero
            width: parent.width
            title: strings.t("title")
            meta: bastion.statusText()
            foreground: bastion.foreground
            fontFamily: bastion.fontFamily
            iconComponent: Component {
              Text {
                textFormat: Text.PlainText
                text: bastion.radarGlyph
                color: bastion.fortiRed
                font.family: bastion.fontFamily
                font.pixelSize: Style.font.display
              }
            }
            trailingControl: Component {
              Row {
                spacing: Style.space(8)

                PanelActionButton {
                  id: refreshButton
                  anchors.verticalCenter: parent.verticalCenter
                  iconText: "󰑐"
                  foreground: hero.foreground
                  fontFamily: hero.fontFamily
                  enabled: !bastion.fetching
                  opacity: bastion.fetching ? 0.5 : 1
                  tooltipText: strings.t("refresh")
                  onClicked: bastion.refresh()
                }

                ToggleSwitch {
                  id: autoSwitch
                  anchors.verticalCenter: parent.verticalCenter
                  checked: bastion.backgroundRefresh
                  foreground: hero.foreground
                  onToggled: bastion.toggleBackgroundRefresh()

                  PanelToolTip {
                    visible: autoSwitch.containsMouse
                    text: bastion.backgroundRefresh
                      ? strings.t("autoOn").arg(Commons.I18n.formatNumber(bastion.refreshIntervalMin))
                      : strings.t("autoOff")
                    fontFamily: hero.fontFamily
                  }
                }
              }
            }
          }

          // -- lookup --
          Column {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: strings.t("lookup.title")
              foreground: bastion.foreground
              fontFamily: bastion.fontFamily
            }

            TextField {
              id: lookupField
              width: parent.width
              placeholderText: strings.t("lookup.placeholder")
              foreground: bastion.foreground
              maximumLength: 256
              // Read-only on purpose. A writable TextInput reads the whole
              // clipboard on every clipboard change (QQuickTextInput::
              // q_canPasteChanged -> mimeData()->text()), unbounded and on the
              // shared shell's GUI thread, before any paste. So typing is
              // handled here and Ctrl+V goes through pasteProc (byte cap and
              // deadline, in a separate process).
              readOnly: true
              cursorDelegate: Rectangle {
                width: 1
                color: lookupField.color
                visible: lookupField.activeFocus && blink.on
                Timer {
                  id: blink
                  property bool on: true
                  interval: 530
                  repeat: true
                  running: lookupField.activeFocus
                  onRunningChanged: on = true
                  onTriggered: on = !on
                }
              }
              function replaceSelection(insert) {
                var a = Math.min(selectionStart, selectionEnd), b = Math.max(selectionStart, selectionEnd)
                if (a === b) { a = cursorPosition; b = cursorPosition }
                insert = insert.slice(0, Math.max(0, maximumLength - (text.length - (b - a))))
                text = text.slice(0, a) + insert + text.slice(b)
                cursorPosition = a + insert.length
              }
              function pasteText(raw) {
                replaceSelection(String(raw).split(/[\r\n]/)[0].replace(/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/g, "").trim())
              }
              Keys.onPressed: function(event) {
                var ctrl = (event.modifiers & Qt.ControlModifier) !== 0
                var alt = (event.modifiers & (Qt.AltModifier | Qt.MetaModifier)) !== 0
                var hasSel = selectionStart !== selectionEnd
                if (ctrl && event.key === Qt.Key_V) { if (!pasteProc.running) pasteProc.running = true; event.accepted = true }
                else if (ctrl && event.key === Qt.Key_X) { if (hasSel) { copy(); replaceSelection("") } event.accepted = true }
                else if (event.key === Qt.Key_Backspace) {
                  if (!hasSel && cursorPosition > 0) select(cursorPosition - 1, cursorPosition)
                  replaceSelection(""); event.accepted = true
                } else if (event.key === Qt.Key_Delete) {
                  if (!hasSel && cursorPosition < text.length) select(cursorPosition, cursorPosition + 1)
                  replaceSelection(""); event.accepted = true
                } else if (!ctrl && !alt && event.text.length > 0 && !/[\x00-\x1f\x7f]/.test(event.text)) {
                  replaceSelection(event.text); event.accepted = true
                }
              }
              Keys.onReturnPressed: bastion.lookup(text)
              Keys.onEnterPressed: bastion.lookup(text)
              Keys.onEscapePressed: {
                if (text !== "") text = ""
                else bastion.close()
              }
              Keys.onDownPressed: {
                keyCatcher.forceActiveFocus()
                bastion.cursorActive = true
                bastion.cursorIndex = 0
                bastion.scrollCursorIntoView()
              }
              Keys.onTabPressed: function(event) { event.accepted = true; bastion.switchPanel(1) }
            }

            Text {
              textFormat: Text.PlainText
              width: parent.width
              text: bastion.lookupHint(lookupField.text)
              color: bastion.dim
              font.family: bastion.fontFamily
              font.pixelSize: Style.font.caption
              elide: Text.ElideRight
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: bastion.hasErrors
            width: parent.width
            text: strings.t("status.feedError")
            color: bastion.urgent
            font.family: bastion.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }

          PanelSeparator { foreground: bastion.foreground }

          // -- Outbreak alerts --
          Column {
            id: outbreakColumn
            width: parent.width
            spacing: Style.space(4)

            SectionTitle { glyph: "󰀦"; text: strings.t("outbreak.title"); unread: bastion.countUnread(bastion.outbreakRows) }
            EmptyText { visible: bastion.outbreakRows.length === 0 }

            Repeater {
              model: bastion.outbreakRows
              FeedRow {
                required property var modelData
                required property int index
                width: outbreakColumn.width
                item: modelData
                rowIndex: index
                summaryText: modelData.summary
                metaText: bastion.ageText(modelData.published)
              }
            }
          }

          PanelSeparator { foreground: bastion.foreground }

          // -- Threat signals --
          Column {
            id: threatColumn
            width: parent.width
            spacing: Style.space(4)

            SectionTitle { glyph: "󰑫"; text: strings.t("threat.title"); unread: bastion.countUnread(bastion.threatRows) }
            EmptyText { visible: bastion.threatRows.length === 0 }

            Repeater {
              model: bastion.threatRows
              FeedRow {
                required property var modelData
                required property int index
                width: threatColumn.width
                item: modelData
                rowIndex: bastion.outbreakRows.length + index
                metaText: bastion.ageText(modelData.published)
              }
            }
          }

          PanelSeparator { foreground: bastion.foreground }

          // -- PSIRT --
          Column {
            id: psirtColumn
            width: parent.width
            spacing: Style.space(4)

            SectionTitle { glyph: "󰒘"; text: strings.t("psirt.title"); unread: bastion.countUnread(bastion.psirtRows) }
            EmptyText { visible: bastion.psirtRows.length === 0 }

            Repeater {
              model: bastion.psirtRows
              FeedRow {
                required property var modelData
                required property int index
                width: psirtColumn.width
                item: modelData
                rowIndex: bastion.outbreakRows.length + bastion.threatRows.length + index
                badgeText: modelData.cvss >= 0
                  ? Commons.I18n.formatNumber(modelData.cvss, 1) + " " + strings.t("severity." + (modelData.severity || "info"))
                  : ""
                badgeColor: bastion.severityColor(modelData.severity)
                // Product first (titles don't name it), CVEs last so elision
                // trims them before the date.
                metaText: [Model.compactList(modelData.products, 2), modelData.advisory, bastion.ageText(modelData.published),
                  Model.compactList(modelData.cves, 1)].filter(function(s) { return s !== "" }).join("  ·  ")
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: strings.t("footer")
            color: bastion.dim
            opacity: 0.8
            font.family: bastion.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
          }
        }
      }
    }
  }

  function countUnread(rows) {
    var n = 0
    for (var i = 0; i < rows.length; i++) if (rows[i].unread) n++
    return n
  }

  // ---- components ----------------------------------------------------------

  component SectionTitle: Row {
    property string glyph: ""
    property string text: ""
    property int unread: 0
    spacing: Style.space(6)
    bottomPadding: Style.space(2)

    Text {
      textFormat: Text.PlainText
      text: parent.glyph
      color: bastion.fortiRed
      font.family: bastion.fontFamily
      font.pixelSize: Style.font.bodySmall
      anchors.verticalCenter: parent.verticalCenter
    }
    PanelSectionHeader {
      text: parent.text
      foreground: bastion.foreground
      fontFamily: bastion.fontFamily
      anchors.verticalCenter: parent.verticalCenter
    }
    Text {
      textFormat: Text.PlainText
      visible: parent.unread > 0
      text: strings.tn("unread", parent.unread).arg(Commons.I18n.formatNumber(parent.unread))
      color: bastion.fortiRed
      font.family: bastion.fontFamily
      font.pixelSize: Style.font.caption
      anchors.verticalCenter: parent.verticalCenter
    }
  }

  component EmptyText: Text {
    textFormat: Text.PlainText
    width: parent.width
    text: bastion.fetching ? strings.t("status.refreshing") : strings.t("empty")
    color: bastion.dim
    font.family: bastion.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  component FeedRow: CursorSurface {
    id: feedRow
    property var item: null
    property int rowIndex: 0
    property string badgeText: ""
    property color badgeColor: bastion.dim
    property string summaryText: ""
    property string metaText: ""

    hasCursor: bastion.cursorActive && bastion.cursorIndex === rowIndex
    foreground: bastion.foreground
    implicitHeight: rowContent.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: feedRow.item && feedRow.item.link !== "" ? Qt.PointingHandCursor : Qt.ArrowCursor
      onEntered: { bastion.cursorActive = true; bastion.cursorIndex = feedRow.rowIndex }
      onClicked: if (feedRow.item && feedRow.item.link !== "") { bastion.openUrl(feedRow.item.link); bastion.close() }
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      // Unread dot.
      Rectangle {
        Layout.alignment: Qt.AlignTop
        Layout.topMargin: Style.space(6)
        width: Style.space(6)
        height: width
        radius: width / 2
        color: bastion.fortiRed
        opacity: feedRow.item && feedRow.item.unread ? 1 : 0
      }

      ColumnLayout {
        id: rowContent
        Layout.fillWidth: true
        spacing: Style.space(2)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(8)

          Text {
            textFormat: Text.PlainText
            Layout.fillWidth: true
            text: feedRow.item ? feedRow.item.title : ""
            color: bastion.foreground
            font.family: bastion.fontFamily
            font.pixelSize: Style.font.body
            elide: Text.ElideRight
          }

          Text {
            textFormat: Text.PlainText
            visible: feedRow.badgeText !== ""
            text: feedRow.badgeText
            color: feedRow.badgeColor
            font.family: bastion.fontFamily
            font.pixelSize: Style.font.caption
            font.bold: feedRow.item && feedRow.item.severity === "critical"
          }
        }

        Text {
          textFormat: Text.PlainText
          visible: feedRow.summaryText !== ""
          Layout.fillWidth: true
          text: feedRow.summaryText
          color: bastion.dim
          font.family: bastion.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
          maximumLineCount: 2
          elide: Text.ElideRight
        }

        Text {
          textFormat: Text.PlainText
          visible: feedRow.metaText !== ""
          Layout.fillWidth: true
          text: feedRow.metaText
          color: bastion.dim
          font.family: bastion.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }
    }
  }
}
