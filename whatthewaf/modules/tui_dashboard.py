"""
Real-time terminal UI dashboard for monitoring WAF bypass proxy/scanner activity.

Uses urwid for the TUI. Falls back to NullDashboard (no-op) if urwid is not installed.
All update methods are thread-safe.
"""

import threading
import time
from collections import deque
from datetime import datetime

try:
    import urwid

    _URWID_AVAILABLE = True
except ImportError:
    _URWID_AVAILABLE = False


class NullDashboard:
    """No-op dashboard used when urwid is not available."""

    @classmethod
    def is_available(cls):
        return False

    def __init__(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def update_traffic(self, method, url, status_code, response_time, technique=""):
        pass

    def update_technique(self, name, value):
        pass

    def update_ip(self, ip_type, ip_value):
        pass

    def update_source_port(self, port):
        pass

    def update_scanner(self, layer, finding):
        pass

    def set_status(self, text):
        pass

    def increment_counter(self, name):
        pass


if _URWID_AVAILABLE:

    class WAFDashboard:
        """Real-time terminal UI dashboard using urwid."""

        PALETTE = [
            ("header", "white,bold", "dark blue"),
            ("footer", "white", "dark gray"),
            ("stat_label", "light gray", ""),
            ("stat_value", "white,bold", ""),
            ("technique_label", "light cyan", ""),
            ("technique_value", "white,bold", ""),
            ("traffic_200", "light green", ""),
            ("traffic_301", "yellow", ""),
            ("traffic_403", "light red", ""),
            ("traffic_429", "yellow,bold", ""),
            ("traffic_500", "light red,bold", ""),
            ("traffic_default", "white", ""),
            ("panel_title", "white,bold", "dark cyan"),
            ("finding_high", "light red,bold", ""),
            ("finding_medium", "yellow", ""),
            ("finding_low", "light green", ""),
            ("finding_info", "light gray", ""),
            ("divider", "dark gray", ""),
        ]

        MAX_TRAFFIC_ENTRIES = 100
        MAX_SCANNER_ENTRIES = 50

        @classmethod
        def is_available(cls):
            return True

        def __init__(self):
            self._lock = threading.Lock()
            self._running = False
            self._loop = None
            self._thread = None
            self._pipe_fd = None

            # State
            self._counters = {
                "Requests": 0,
                "Blocked": 0,
                "Bypassed": 0,
                "Findings": 0,
            }
            self._techniques = {
                "TLS Identity": "---",
                "H2 Profile": "---",
                "TCP Profile": "---",
                "Source Port": "---",
                "Tor IP": "---",
                "Proxy": "---",
            }
            self._traffic_entries = deque(maxlen=self.MAX_TRAFFIC_ENTRIES)
            self._scanner_entries = deque(maxlen=self.MAX_SCANNER_ENTRIES)
            self._status_text = "Initializing..."

            # Build UI widgets
            self._build_ui()

        # ------------------------------------------------------------------ #
        # UI construction
        # ------------------------------------------------------------------ #

        def _build_ui(self):
            # Header
            self._header = urwid.AttrMap(
                urwid.Text(" WhatTheWAF Dashboard v2.0", align="center"),
                "header",
            )

            # Stats row
            self._stat_widgets = {}
            stat_cols = []
            for name in ("Requests", "Blocked", "Bypassed", "Findings"):
                label = urwid.Text(("stat_label", f" {name}: "))
                value = urwid.Text(("stat_value", "0"))
                self._stat_widgets[name] = value
                stat_cols.append(urwid.Columns([("pack", label), ("pack", value)]))
            self._stats_row = urwid.Columns(stat_cols)

            # Techniques panel
            self._technique_widgets = {}
            tech_items_left = []
            tech_items_right = []
            tech_keys = list(self._techniques.keys())
            for i, key in enumerate(tech_keys):
                label = urwid.Text(("technique_label", f"  {key}: "))
                value = urwid.Text(("technique_value", self._techniques[key]))
                self._technique_widgets[key] = value
                row = urwid.Columns([("pack", label), value])
                if i < 3:
                    tech_items_left.append(row)
                else:
                    tech_items_right.append(row)

            tech_left = urwid.Pile(tech_items_left)
            tech_right = urwid.Pile(tech_items_right)
            tech_body = urwid.Columns([tech_left, tech_right])
            self._techniques_panel = urwid.LineBox(
                tech_body, title="Active Techniques", title_attr="panel_title"
            )

            # Traffic log
            self._traffic_walker = urwid.SimpleFocusListWalker([])
            self._traffic_listbox = urwid.ListBox(self._traffic_walker)
            self._traffic_panel = urwid.LineBox(
                urwid.BoxAdapter(self._traffic_listbox, 12),
                title="Traffic Log",
                title_attr="panel_title",
            )

            # Scanner findings
            self._scanner_walker = urwid.SimpleFocusListWalker([])
            self._scanner_listbox = urwid.ListBox(self._scanner_walker)
            self._scanner_panel = urwid.LineBox(
                urwid.BoxAdapter(self._scanner_listbox, 8),
                title="Scanner Findings",
                title_attr="panel_title",
            )

            # Footer / status bar
            self._footer_text = urwid.Text(" Initializing...")
            self._footer = urwid.AttrMap(self._footer_text, "footer")

            # Main layout
            body = urwid.Pile(
                [
                    ("pack", self._stats_row),
                    ("pack", urwid.Divider()),
                    ("pack", self._techniques_panel),
                    ("pack", urwid.Divider()),
                    ("pack", self._traffic_panel),
                    ("pack", urwid.Divider()),
                    ("pack", self._scanner_panel),
                ]
            )

            self._frame = urwid.Frame(
                header=self._header,
                body=urwid.Filler(body, valign="top"),
                footer=self._footer,
            )

        # ------------------------------------------------------------------ #
        # Lifecycle
        # ------------------------------------------------------------------ #

        def start(self):
            """Start the urwid main loop in a background thread."""
            if self._running:
                return

            self._running = True
            self._loop = urwid.MainLoop(
                self._frame,
                palette=self.PALETTE,
                unhandled_input=self._handle_input,
            )
            self._pipe_fd = self._loop.watch_pipe(self._on_pipe_data)

            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name="tui-dashboard"
            )
            self._thread.start()

        def stop(self):
            """Stop the dashboard and clean up."""
            if not self._running:
                return
            self._running = False
            if self._loop is not None:
                try:
                    self._loop.draw_screen()
                except Exception:
                    pass
                try:
                    raise urwid.ExitMainLoop()
                except urwid.ExitMainLoop:
                    pass
                # Wake the pipe so the loop can exit
                self._wake()

        def _run_loop(self):
            try:
                self._loop.run()
            except urwid.ExitMainLoop:
                pass
            except Exception:
                pass
            finally:
                self._running = False

        def _handle_input(self, key):
            if key in ("q", "Q"):
                raise urwid.ExitMainLoop()

        def _wake(self):
            """Send a byte through the pipe to wake the main loop for a redraw."""
            if self._pipe_fd is not None and self._running:
                try:
                    import os

                    os.write(self._pipe_fd, b"1")
                except Exception:
                    pass

        def _on_pipe_data(self, data):
            """Called by urwid in the main loop thread when pipe data arrives."""
            self._refresh_ui()

        # ------------------------------------------------------------------ #
        # Thread-safe update methods
        # ------------------------------------------------------------------ #

        def update_traffic(self, method, url, status_code, response_time, technique=""):
            """Add a traffic log entry. Thread-safe."""
            ts = datetime.now().strftime("%H:%M:%S")
            entry = {
                "ts": ts,
                "method": method,
                "url": url,
                "status": status_code,
                "time": response_time,
                "technique": technique,
            }
            with self._lock:
                self._traffic_entries.append(entry)
            self._wake()

        def update_technique(self, name, value):
            """Update an active technique display value. Thread-safe."""
            with self._lock:
                self._techniques[name] = value
            self._wake()

        def update_ip(self, ip_type, ip_value):
            """Update an IP display (e.g. 'Tor IP' -> '1.2.3.4'). Thread-safe."""
            with self._lock:
                self._techniques[ip_type] = ip_value
            self._wake()

        def update_source_port(self, port):
            """Update the current source port display. Thread-safe."""
            with self._lock:
                self._techniques["Source Port"] = str(port)
            self._wake()

        def update_scanner(self, layer, finding):
            """Add a scanner finding. Thread-safe."""
            ts = datetime.now().strftime("%H:%M:%S")
            entry = {"ts": ts, "layer": layer, "finding": finding}
            with self._lock:
                self._scanner_entries.append(entry)
                self._counters["Findings"] = self._counters.get("Findings", 0) + 1
            self._wake()

        def set_status(self, text):
            """Update the footer status bar. Thread-safe."""
            with self._lock:
                self._status_text = text
            self._wake()

        def increment_counter(self, name):
            """Increment a named stats counter. Thread-safe."""
            with self._lock:
                self._counters[name] = self._counters.get(name, 0) + 1
            self._wake()

        # ------------------------------------------------------------------ #
        # UI refresh (always called in urwid main loop thread via pipe)
        # ------------------------------------------------------------------ #

        def _refresh_ui(self):
            with self._lock:
                counters = dict(self._counters)
                techniques = dict(self._techniques)
                traffic = list(self._traffic_entries)
                scanner = list(self._scanner_entries)
                status = self._status_text

            # Update stat counters
            for name, widget in self._stat_widgets.items():
                widget.set_text(("stat_value", str(counters.get(name, 0))))

            # Update techniques
            for name, widget in self._technique_widgets.items():
                widget.set_text(("technique_value", techniques.get(name, "---")))

            # Update traffic log
            self._traffic_walker.clear()
            for entry in traffic:
                attr = self._status_color(entry["status"])
                tech_str = f" {entry['technique']}" if entry.get("technique") else ""
                line = (
                    f"[{entry['ts']}] {entry['method']:6s} {entry['url']}"
                    f" [{entry['status']}] {entry['time']:.0f}ms{tech_str}"
                )
                self._traffic_walker.append(urwid.Text((attr, line)))
            # Auto-scroll to bottom
            if self._traffic_walker:
                self._traffic_listbox.set_focus(len(self._traffic_walker) - 1)

            # Update scanner findings
            self._scanner_walker.clear()
            for entry in scanner:
                attr = self._severity_color(entry.get("layer", ""))
                line = f"[{entry['ts']}] {entry['layer']}: {entry['finding']}"
                self._scanner_walker.append(urwid.Text((attr, line)))
            if self._scanner_walker:
                self._scanner_listbox.set_focus(len(self._scanner_walker) - 1)

            # Update footer
            self._footer_text.set_text(f" {status}")

        @staticmethod
        def _status_color(status_code):
            """Return urwid palette attribute name for an HTTP status code."""
            code = int(status_code)
            if code == 200:
                return "traffic_200"
            elif code in (301, 302):
                return "traffic_301"
            elif code == 429:
                return "traffic_429"
            elif code in (403, 503):
                return "traffic_403"
            elif code >= 500:
                return "traffic_500"
            return "traffic_default"

        @staticmethod
        def _severity_color(layer):
            """Return urwid palette attribute name based on layer/severity keywords."""
            layer_lower = layer.lower() if layer else ""
            if "critical" in layer_lower or "high" in layer_lower:
                return "finding_high"
            elif "medium" in layer_lower or "warn" in layer_lower:
                return "finding_medium"
            elif "low" in layer_lower:
                return "finding_low"
            return "finding_info"

else:
    # urwid not available -- WAFDashboard is just NullDashboard
    WAFDashboard = NullDashboard
