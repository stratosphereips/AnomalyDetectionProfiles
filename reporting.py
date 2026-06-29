"""Shared terminal and human-log reporting for the anomaly detectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional


class Reporter:
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "cyan": "\033[36m",
        "blue": "\033[34m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "magenta": "\033[35m",
        "green": "\033[32m",
        "white": "\033[37m",
    }

    def __init__(
        self,
        log_path: Path,
        quiet: bool = False,
        color: str = "auto",
        show_data: bool = True,
    ):
        self.quiet = quiet
        self.show_data = show_data
        self.color_enabled = color == "always" or (
            color == "auto" and sys.stdout.isatty()
        )
        self.log_path = log_path
        self.log = log_path.open("w", encoding="utf-8")

    def paint(self, text: str, *styles: str) -> str:
        if not self.color_enabled:
            return text
        prefix = "".join(self.COLORS[style] for style in styles)
        return f"{prefix}{text}{self.COLORS['reset']}"

    def _terminal(self, text: str) -> None:
        if not self.quiet:
            print(text)

    def _log(self, text: str = "") -> None:
        self.log.write(text + "\n")
        self.log.flush()

    def section(self, title: str, subtitle: str = "") -> None:
        plain = f"{'=' * 18} {title} {'=' * 18}"
        self._log("\n" + plain)
        if subtitle:
            self._log(subtitle)
        if not self.quiet:
            print()
            print(self.paint(plain, "bold", "cyan"))
            if subtitle:
                print(self.paint(subtitle, "dim"))

    def data(
        self,
        *,
        host: str,
        hour: int,
        phase: str,
        features: dict[str, Any],
        protocol: Optional[str] = None,
    ) -> None:
        scope = f"{protocol:<14} " if protocol else ""
        plain = (
            f"DATA     {scope}host={host:<39} hour={hour:<8} "
            f"phase={phase:<9} {json.dumps(features, sort_keys=True)}"
        )
        self._log(plain)
        if self.show_data:
            self._terminal(self.paint(plain, "blue"))

    def anomaly(
        self,
        *,
        kind: str,
        host: str,
        timestamp: int | float,
        score: float,
        reasons: list[dict[str, Any]],
        protocol: Optional[str] = None,
        confidence: Optional[str] = None,
        responsible_flows: Optional[list[dict[str, Any]]] = None,
        responsible_flow_count: Optional[int] = None,
    ) -> None:
        label = "ALERT" if kind == "ssl-flow" else "ANOMALY"
        protocol_text = f" protocol={protocol}" if protocol else ""
        confidence_text = f" confidence={confidence}" if confidence else ""
        headline = (
            f"{label:<8} type={kind}{protocol_text} host={host} ts={timestamp} "
            f"score={score:.4f}{confidence_text}"
        )
        self._log(headline)
        self._terminal(self.paint(headline, "bold", "red"))
        for reason in reasons:
            details = (
                f"         - {reason.get('feature', 'unknown')}: "
                f"value={reason.get('value', 'n/a')}"
            )
            if "zscore" in reason:
                details += (
                    f" z={reason['zscore']} threshold={reason.get('threshold')}"
                )
            if reason.get("direction"):
                details += f" direction={reason['direction']}"
            self._log(details)
            self._terminal(self.paint(details, "yellow"))
            if reason.get("explanation"):
                explanation = f"           {reason['explanation']}"
                self._log(explanation)
                self._terminal(self.paint(explanation, "dim"))
        flows = responsible_flows or []
        total = responsible_flow_count if responsible_flow_count is not None else len(flows)
        attribution = (
            f"         Responsible flows: showing {len(flows)} of {total}"
        )
        self._log(attribution)
        self._terminal(self.paint(attribution, "bold", "cyan"))
        for flow in flows:
            flow_line = (
                f"           - log={flow.get('log', 'unknown')} "
                f"ts={flow.get('ts', 'n/a')} "
                f"uid={flow.get('uid') or flow.get('fuid') or 'n/a'} "
                f"{flow.get('src', '?')}:{flow.get('src_port', '?')} -> "
                f"{flow.get('dst', '?')}:{flow.get('dst_port', '?')}"
            )
            detail_values = flow.get("details", {})
            if detail_values:
                flow_line += f" details={json.dumps(detail_values, sort_keys=True)}"
            if flow.get("matched_features"):
                flow_line += (
                    " matched="
                    + ",".join(sorted(flow["matched_features"]))
                )
            self._log(flow_line)
            self._terminal(self.paint(flow_line, "white"))

    def global_anomaly(self, event: dict[str, Any]) -> None:
        headline = (
            f"GLOBAL   host={event['host']} hour={event['hour_start']} "
            f"score={event['global_score']:.4f} "
            f"confidence={event['confidence']} "
            f"protocols={','.join(event['protocols'])}"
        )
        self._log(headline)
        self._terminal(self.paint(headline, "bold", "magenta"))
        for protocol, contribution in sorted(
            event["protocol_contributions"].items()
        ):
            detail = f"         - {protocol}: contribution={contribution:.4f}"
            self._log(detail)
            self._terminal(self.paint(detail, "yellow"))
        flows = event.get("responsible_flows", [])
        total = event.get("responsible_flow_count", len(flows))
        attribution = (
            f"         Responsible flows: showing {len(flows)} of {total}"
        )
        self._log(attribution)
        self._terminal(self.paint(attribution, "bold", "cyan"))
        for flow in flows:
            detail = (
                f"           - log={flow.get('log')} ts={flow.get('ts')} "
                f"uid={flow.get('uid') or flow.get('fuid') or 'n/a'} "
                f"{flow.get('src', '?')} -> {flow.get('dst', '?')}"
            )
            self._log(detail)
            self._terminal(self.paint(detail, "white"))

    def summary(self, title: str, rows: list[tuple[str, Any]]) -> None:
        plain = f"{'=' * 18} {title} {'=' * 18}"
        self._log("\n" + plain)
        print()
        print(self.paint(plain, "bold", "cyan"))
        width = max((len(label) for label, _ in rows), default=0)
        for label, value in rows:
            line = f"{label:<{width}} : {value}"
            self._log(line)
            print(
                self.paint(
                    line,
                    "green" if "anomal" not in label.lower() else "yellow",
                )
            )

    def close(self) -> None:
        self.log.close()
