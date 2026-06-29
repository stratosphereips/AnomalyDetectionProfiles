#!/usr/bin/env python3
"""Local web dashboard for configuring and running the Zeek detector."""

from __future__ import annotations

import argparse
import configparser
import html
import json
import re
import subprocess
import sys
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from detection_core import ZeekReader, number


ROOT = Path(__file__).resolve().parent
HTML_PATH = ROOT / "dashboard.html"
DEFAULT_CONFIG = ROOT / "anomaly_detector.conf"
DETECTOR = ROOT / "multi_protocol_anomaly_detector.py"
RUNS_DIR = ROOT / ".dashboard_runs"
DOC_FILES = {
    "README.md": ROOT / "README.md",
    "MULTI_PROTOCOL_ANOMALY_DETECTION.md": ROOT / "MULTI_PROTOCOL_ANOMALY_DETECTION.md",
    "COMPUTATION_REFERENCE.md": ROOT / "COMPUTATION_REFERENCE.md",
}
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
STRONG_RE = re.compile(r"\*\*([^*]+)\*\*")
EM_RE = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
ALLOWED_SECTIONS = {"common", "output", "multi_protocol"}
DETECTED_LOGS = {
    "analyzer",
    "conn",
    "dce_rpc",
    "dhcp",
    "dns",
    "files",
    "http",
    "known_hosts",
    "known_services",
    "notice",
    "ntlm",
    "smb_mapping",
    "software",
    "ssl",
    "weird",
}


SETTING_METADATA = {
    "training_hours": ("Benign training hours", "Observed traffic-hours treated as benign."),
    "sensitivity": ("Global sensitivity", "Higher values emit more anomalies; lower values emit fewer."),
    "ignore_multicast_broadcast": ("Ignore multicast/broadcast", "Skip multicast and broadcast flows entirely when enabled."),
    "minimum_points": ("Minimum baseline points", "Required observations before a z-score can trigger."),
    "threshold": ("Protocol z threshold", "Fallback z-score threshold for protocol-hour features."),
    "threshold_quantile": ("Threshold quantile", "Benign quantile used for empirical threshold calibration."),
    "drift_alpha": ("Drift adaptation rate", "EWMA update rate for small deviations."),
    "suspicious_alpha": ("Suspicious adaptation rate", "Slow EWMA rate that limits baseline poisoning."),
    "adaptation_score": ("Adaptation score boundary", "Score separating drift from suspicious behavior."),
    "protocol_score_cap": ("Protocol score cap", "Maximum contribution from one protocol to the ensemble."),
    "global_threshold": ("Global score threshold", "Global ensemble score required to alert."),
    "minimum_protocols": ("Minimum protocols", "Independent protocol votes sufficient to alert."),
    "corroboration_bonus": ("Corroboration bonus", "Bonus for each additional anomalous protocol."),
    "corroboration_bonus_cap": ("Corroboration cap", "Maximum total corroboration bonus."),
    "max_responsible_flows": ("Responsible flow limit", "Maximum representative flows embedded per anomaly."),
    "ssl_hourly_threshold": ("SSL hourly z threshold", "Fallback threshold for specialized SSL hourly features."),
    "ssl_flow_threshold": ("SSL flow z threshold", "Threshold for bytes to a known TLS server."),
    "ssl_novelty_threshold": ("SSL novelty threshold", "Gate for new server and JA3S evidence."),
    "ssl_baseline_alpha": ("SSL baseline adaptation", "EWMA rate for normal SSL flows."),
    "ssl_max_small_anomalies": ("SSL small-reason limit", "Maximum reasons still treated as small flow drift."),
}


def read_config(path: Path | str) -> dict[str, dict[str, Any]]:
    path = Path(path)
    parser = configparser.ConfigParser()
    with path.open("r", encoding="utf-8") as handle:
        parser.read_file(handle)
    result: dict[str, dict[str, Any]] = {}
    for section in parser.sections():
        if section not in ALLOWED_SECTIONS:
            continue
        result[section] = {}
        for key, value in parser[section].items():
            if key in {"color", "output_dir"}:
                continue
            if value.lower() in {"true", "false"}:
                converted: Any = value.lower() == "true"
            else:
                try:
                    converted = int(value)
                except ValueError:
                    try:
                        converted = float(value)
                    except ValueError:
                        converted = value
            result[section][key] = converted
    return result


def write_run_config(
    path: Path, submitted: dict[str, dict[str, Any]]
) -> None:
    baseline = configparser.ConfigParser()
    with DEFAULT_CONFIG.open("r", encoding="utf-8") as handle:
        baseline.read_file(handle)
    for section, values in submitted.items():
        if section not in ALLOWED_SECTIONS or not isinstance(values, dict):
            continue
        if section not in baseline:
            baseline.add_section(section)
        for key, value in values.items():
            if key not in SETTING_METADATA and key not in {
                "show_terminal_data",
                "quiet",
            }:
                continue
            baseline[section][key] = str(value).lower() if isinstance(value, bool) else str(value)
    baseline["output"]["color"] = "never"
    baseline["output"]["quiet"] = "true"
    with path.open("w", encoding="utf-8") as handle:
        baseline.write(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def escape_html(value: str) -> str:
    return html.escape(value, quote=True)


def render_inline_markdown(text: str) -> str:
    rendered = escape_html(text)
    rendered = INLINE_CODE_RE.sub(
        lambda match: f"<code>{escape_html(match.group(1))}</code>", rendered
    )
    rendered = LINK_RE.sub(
        lambda match: (
            f'<a href="{escape_html(match.group(2))}" target="_blank" '
            f'rel="noreferrer noopener">{escape_html(match.group(1))}</a>'
        ),
        rendered,
    )
    rendered = STRONG_RE.sub(r"<strong>\1</strong>", rendered)
    rendered = EM_RE.sub(r"<em>\1</em>", rendered)
    return rendered


def markdown_to_html(text: str) -> str:
    lines = text.splitlines()
    blocks: list[str] = []
    paragraph: list[str] = []
    list_stack: list[tuple[str, int]] = []
    in_code = False
    code_lang = ""
    code_lines: list[str] = []
    in_table = False
    table_rows: list[list[str]] = []
    table_header: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            blocks.append(
                f"<p>{render_inline_markdown(' '.join(paragraph).strip())}</p>"
            )
            paragraph = []

    def close_lists(target: int = 0) -> None:
        nonlocal list_stack
        while list_stack and len(list_stack) > target:
            tag, _indent = list_stack.pop()
            blocks.append(f"</{tag}>")

    def flush_table() -> None:
        nonlocal in_table, table_rows, table_header
        if not table_header:
            in_table = False
            table_rows = []
            return
        head = "".join(f"<th>{render_inline_markdown(cell.strip())}</th>" for cell in table_header)
        body = "".join(
            "<tr>" + "".join(
                f"<td>{render_inline_markdown(cell.strip())}</td>" for cell in row
            ) + "</tr>"
            for row in table_rows
        )
        blocks.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
        in_table = False
        table_rows = []
        table_header = []

    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if in_code:
            if stripped.startswith("```"):
                blocks.append(
                    f'<pre><code class="language-{escape_html(code_lang)}">{escape_html("\\n".join(code_lines))}</code></pre>'
                )
                in_code = False
                code_lang = ""
                code_lines = []
            else:
                code_lines.append(raw)
            continue
        if stripped.startswith("```"):
            flush_paragraph()
            close_lists()
            if in_table:
                flush_table()
            in_code = True
            code_lang = stripped[3:].strip()
            continue
        if not stripped:
            flush_paragraph()
            close_lists()
            if in_table:
                flush_table()
            continue
        if stripped in {"---", "***", "___"}:
            flush_paragraph()
            close_lists()
            if in_table:
                flush_table()
            blocks.append("<hr>")
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            flush_paragraph()
            close_lists()
            if in_table:
                flush_table()
            level = len(heading.group(1))
            blocks.append(
                f"<h{level}>{render_inline_markdown(heading.group(2).strip())}</h{level}>"
            )
            continue
        if stripped.startswith(">"):
            flush_paragraph()
            close_lists()
            if in_table:
                flush_table()
            blocks.append(f"<blockquote>{render_inline_markdown(stripped[1:].strip())}</blockquote>")
            continue
        table_match = "|" in stripped and re.match(r"^\s*\|?.+\|?\s*$", line)
        if table_match:
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            separator = all(set(cell) <= {"-", ":", " "} for cell in cells)
            if separator:
                if not in_table:
                    in_table = True
                continue
            flush_paragraph()
            close_lists()
            if not in_table:
                in_table = True
            if not table_header:
                table_header = cells
            else:
                table_rows.append(cells)
            continue
        list_match = re.match(r"^(\s*)([-*+]|\d+\.)\s+(.*)$", line)
        if list_match:
            flush_paragraph()
            if in_table:
                flush_table()
            indent = len(list_match.group(1))
            marker = list_match.group(2)
            tag = "ol" if marker.endswith(".") else "ul"
            while list_stack and indent < list_stack[-1][1]:
                blocks.append(f"</{list_stack.pop()[0]}>")
            if not list_stack or list_stack[-1][0] != tag or indent > list_stack[-1][1]:
                list_stack.append((tag, indent))
                blocks.append(f"<{tag}>")
            blocks.append(f"<li>{render_inline_markdown(list_match.group(3).strip())}</li>")
            continue
        flush_table()
        paragraph.append(stripped)

    flush_paragraph()
    if in_table:
        flush_table()
    close_lists()
    if in_code:
        blocks.append(
            f'<pre><code class="language-{escape_html(code_lang)}">{escape_html("\\n".join(code_lines))}</code></pre>'
        )
    return "".join(blocks)


def resolve_local_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def inspect_zeek_folder(raw_path: str) -> dict[str, Any]:
    path = resolve_local_path(raw_path)
    if not path.is_dir():
        raise ValueError(f"Zeek directory does not exist: {path}")
    timestamps: list[float] = []
    records = 0
    active_hours: set[int] = set()
    logs = 0
    for log_path in sorted(path.glob("*.log")):
        if log_path.stem not in DETECTED_LOGS:
            continue
        log_records = 0
        try:
            for record in ZeekReader(log_path):
                if not record.get("ts"):
                    continue
                ts = number(record.get("ts"))
                timestamps.append(ts)
                active_hours.add(int(ts) - int(ts) % 3600)
                records += 1
                log_records += 1
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if log_records:
            logs += 1
    if not timestamps:
        raise ValueError(f"No timestamped Zeek records found in: {path}")
    minimum, maximum = min(timestamps), max(timestamps)
    first_hour = int(minimum) - int(minimum) % 3600
    last_hour = int(maximum) - int(maximum) % 3600
    duration_seconds = maximum - minimum
    return {
        "path": str(path),
        "records": records,
        "logs": logs,
        "first_ts": minimum,
        "last_ts": maximum,
        "duration_seconds": round(duration_seconds, 3),
        "duration_hours": round(duration_seconds / 3600.0, 3),
        "traffic_hour_span": ((last_hour - first_hour) // 3600) + 1,
        "active_traffic_hours": len(active_hours),
    }


def run_detector(payload: dict[str, Any]) -> dict[str, Any]:
    zeek_dir = resolve_local_path(str(payload.get("zeek_dir", "")))
    if not zeek_dir.is_dir():
        raise ValueError(f"Zeek directory does not exist: {zeek_dir}")
    if not (zeek_dir / "ssl.log").is_file() or not (zeek_dir / "conn.log").is_file():
        raise ValueError("The selected folder must contain at least ssl.log and conn.log")

    run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000:06d}"
    run_root = RUNS_DIR / run_id
    output_dir = run_root / "output"
    run_root.mkdir(parents=True, exist_ok=False)
    config_path = run_root / "detector.conf"
    write_run_config(config_path, payload.get("config", {}))

    started = time.monotonic()
    command = [
        sys.executable,
        str(DETECTOR),
        str(zeek_dir),
        "--config",
        str(config_path),
        "--output-dir",
        str(output_dir),
        "--quiet",
        "--color",
        "never",
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or completed.stdout.strip()
            or f"Detector exited with status {completed.returncode}"
        )

    events = read_jsonl(output_dir / "multi_protocol_detector.log.jsonl")
    stop = next(
        (event for event in reversed(events) if event.get("event") == "detector_stop"),
        {},
    )
    flow_anomalies = read_jsonl(output_dir / "flow_anomalies.jsonl")
    protocol_anomalies = read_jsonl(output_dir / "protocol_anomalies.jsonl")
    target_anomalies = read_jsonl(output_dir / "target_anomalies.jsonl")
    global_anomalies = read_jsonl(output_dir / "global_anomalies.jsonl")
    flow_anomalies.sort(
        key=lambda event: number(event.get("total_score")), reverse=True
    )
    protocol_anomalies.sort(
        key=lambda event: number(event.get("total_score")), reverse=True
    )
    target_anomalies.sort(
        key=lambda event: number(event.get("importance_score")), reverse=True
    )
    global_anomalies.sort(
        key=lambda event: number(event.get("importance_score")), reverse=True
    )
    return {
        "run_id": run_id,
        "zeek_dir": str(zeek_dir),
        "elapsed_seconds": round(elapsed, 3),
        "summary": stop,
        "capture": inspect_zeek_folder(str(zeek_dir)),
        "model_updates": [
            event for event in events if event.get("event") == "model_update"
        ],
        "flow_anomalies": flow_anomalies,
        "protocol_anomalies": protocol_anomalies,
        "target_anomalies": target_anomalies,
        "global_anomalies": global_anomalies,
        "hourly_data": read_jsonl(output_dir / "protocol_hourly_data.jsonl"),
        "target_hourly_data": read_jsonl(output_dir / "target_hourly_data.jsonl"),
        "human_log": (output_dir / "multi_protocol_detector.log").read_text(
            encoding="utf-8"
        ),
        "output_dir": str(output_dir),
    }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ZeekADDashboard/1.0"

    def send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = HTML_PATH.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/config":
            config = read_config(DEFAULT_CONFIG)
            self.send_json(
                {
                    "config": config,
                    "metadata": {
                        key: {"label": label, "help": help_text}
                        for key, (label, help_text) in SETTING_METADATA.items()
                    },
                    "default_zeek_dir": str(ROOT / "bro"),
                }
            )
            return
        if parsed.path == "/api/inspect":
            query = parse_qs(parsed.query)
            try:
                self.send_json(
                    inspect_zeek_folder(query.get("path", [""])[0])
                )
            except (ValueError, OSError) as error:
                self.send_json({"error": str(error)}, 400)
            return
        if parsed.path == "/api/docs":
            documents = []
            for name, doc_path in DOC_FILES.items():
                try:
                    content = doc_path.read_text(encoding="utf-8")
                except OSError as error:
                    self.send_json({"error": str(error)}, 500)
                    return
                documents.append(
                    {
                        "name": name,
                        "title": doc_path.stem.replace("_", " "),
                        "html": markdown_to_html(content),
                        "content": markdown_to_html(content),
                    }
                )
            self.send_json({"documents": documents})
            return
        if parsed.path == "/api/browse":
            query = parse_qs(parsed.query)
            requested = query.get("path", [str(ROOT)])[0]
            path = Path(requested).expanduser()
            if not path.is_absolute():
                path = ROOT / path
            path = path.resolve()
            if not path.is_dir():
                self.send_json({"error": f"Not a directory: {path}"}, 400)
                return
            directories = []
            try:
                for child in path.iterdir():
                    if child.is_dir() and not child.name.startswith("."):
                        directories.append(
                            {
                                "name": child.name,
                                "path": str(child.resolve()),
                                "is_zeek": (child / "ssl.log").is_file()
                                and (child / "conn.log").is_file(),
                            }
                        )
            except PermissionError:
                self.send_json({"error": f"Permission denied: {path}"}, 403)
                return
            self.send_json(
                {
                    "path": str(path),
                    "parent": str(path.parent),
                    "is_zeek": (path / "ssl.log").is_file()
                    and (path / "conn.log").is_file(),
                    "directories": sorted(
                        directories, key=lambda item: item["name"].lower()
                    ),
                }
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if parsed.path == "/api/run":
                self.send_json(run_detector(payload))
                return
            if parsed.path == "/api/save-config":
                write_run_config(DEFAULT_CONFIG, payload.get("config", {}))
                self.send_json({"saved": str(DEFAULT_CONFIG), "ok": True})
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except subprocess.TimeoutExpired:
            self.send_json({"error": "Detector timed out after 180 seconds"}, 504)
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as error:
            self.send_json({"error": str(error)}, 400)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local Zeek anomaly dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print("error: dashboard may only bind to localhost", file=sys.stderr)
        return 2
    RUNS_DIR.mkdir(exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    url = f"http://{args.host}:{args.port}/"
    print(f"Zeek anomaly dashboard: {url}")
    print("Press Ctrl-C to stop.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
