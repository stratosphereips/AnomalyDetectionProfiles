#!/usr/bin/env python3
"""Adaptive anomaly detection over all IP-attributable Zeek protocol logs."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from configuration import load_settings
from detection_core import AdaptiveStats, ZeekReader, clean, number
from experimental_pipeline import (
    CoreMirrorModule,
    ExperimentalPipeline,
    NoOpModule,
    PipelineContext,
    RobustMultivariateModule,
    pipeline_summary,
)
from reporting import Reporter


SKIPPED_LOGS = {
    "capture_loss",
    "loaded_scripts",
    "ocsp",
    "packet_filter",
    "stats",
    "x509",
}
DEFAULT_CONFIG = Path(__file__).with_name("anomaly_detector.conf")
MULTI_DEFAULTS = {
    "training_hours": 3,
    "window_seconds": 3600,
    "normal_dirs": "",
    "sensitivity": 1.0,
    "ignore_multicast_broadcast": True,
    "color": "auto",
    "show_terminal_data": True,
    "quiet": False,
    "output_dir": Path("multi_protocol_ad_output"),
    "minimum_points": 3,
    "threshold": 3.5,
    "threshold_quantile": 0.995,
    "drift_alpha": 0.05,
    "suspicious_alpha": 0.005,
    "adaptation_score": 8.0,
    "protocol_score_cap": 10.0,
    "global_threshold": 0.65,
    "minimum_protocols": 2,
    "corroboration_bonus": 0.15,
    "corroboration_bonus_cap": 0.30,
    "uid_corroboration_bonus": 0.10,
    "uid_corroboration_bonus_cap": 0.20,
    "max_responsible_flows": 10,
    "ssl_hourly_threshold": 3.5,
    "ssl_flow_threshold": 3.5,
    "ssl_novelty_threshold": 1.5,
    "ssl_baseline_alpha": 0.10,
    "ssl_max_small_anomalies": 2,
    "experimental_noop_mode": "off",
    "experimental_mirror_mode": "shadow",
    "experimental_multivariate_mode": "shadow",
    "multivariate_minimum_points": 8,
    "multivariate_threshold": 3.0,
    "multivariate_shrinkage": 0.5,
    "multivariate_history_limit": 64,
}

# Protocol-specific categorical novelty, numeric volume, and failure signals.
PROTOCOL_FIELDS: dict[str, dict[str, Any]] = {
    "conn": {
        "categorical": ("id.resp_p", "service", "conn_state"),
        "numeric": ("orig_bytes", "resp_bytes", "duration", "missed_bytes"),
        "failure": lambda r: clean(r.get("conn_state")) not in {"SF", "S1"},
    },
    "dns": {
        "categorical": ("query", "qtype_name", "rcode_name"),
        "numeric": ("rtt",),
        "failure": lambda r: clean(r.get("rcode_name"))
        in {"NXDOMAIN", "SERVFAIL", "REFUSED"},
    },
    "http": {
        "categorical": ("host", "method", "status_code", "user_agent"),
        "numeric": (
            "request_body_len",
            "response_body_len",
            "trans_depth",
        ),
        "failure": lambda r: number(r.get("status_code")) >= 400,
    },
    "ssl": {
        "categorical": (
            "server_name",
            "version",
            "cipher",
            "ja3",
            "ja3s",
            "validation_status",
        ),
        "numeric": (),
        "failure": lambda r: clean(r.get("established")).upper() == "F",
    },
    "files": {
        "categorical": ("source", "mime_type", "filename", "sha256"),
        "numeric": (
            "seen_bytes",
            "total_bytes",
            "missing_bytes",
            "overflow_bytes",
            "duration",
            "depth",
        ),
        "failure": lambda r: clean(r.get("timedout")).upper() == "T"
        or number(r.get("missing_bytes")) > 0,
    },
    "dhcp": {
        "categorical": (
            "server_addr",
            "mac",
            "host_name",
            "requested_addr",
            "assigned_addr",
            "msg_types",
        ),
        "numeric": ("lease_time", "duration"),
        "failure": lambda r: not clean(r.get("assigned_addr")),
    },
    "notice": {
        "categorical": ("note", "proto", "msg"),
        "numeric": ("n",),
        "failure": lambda r: True,
    },
    "analyzer": {
        "categorical": ("analyzer_kind", "analyzer_name", "failure_reason"),
        "numeric": (),
        "failure": lambda r: bool(clean(r.get("failure_reason"))),
    },
    "dce_rpc": {
        "categorical": ("named_pipe", "endpoint", "operation"),
        "numeric": ("rtt",),
        "failure": lambda r: False,
    },
    "smb_mapping": {
        "categorical": ("path", "service", "share_type"),
        "numeric": (),
        "failure": lambda r: False,
    },
    "ntlm": {
        "categorical": ("username", "hostname", "domainname"),
        "numeric": (),
        "failure": lambda r: clean(r.get("success")).upper() == "F",
    },
    "ssh": {
        "categorical": ("client", "server", "auth_success", "direction"),
        "numeric": ("auth_attempts",),
        "failure": lambda r: clean(r.get("auth_success")).upper() == "F",
    },
    "weird": {
        "categorical": ("name", "addl"),
        "numeric": (),
        "failure": lambda r: True,
    },
    "known_hosts": {
        "categorical": (),
        "numeric": (),
        "failure": lambda r: False,
    },
    "known_services": {
        "categorical": ("port_num", "port_proto", "service"),
        "numeric": (),
        "failure": lambda r: False,
    },
    "software": {
        "categorical": ("software_type", "name", "unparsed_version"),
        "numeric": (),
        "failure": lambda r: False,
    },
}


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_multicast_or_broadcast(value: str, other: str = "") -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_multicast:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and int(ip) == 0xFFFFFFFF:
        return True
    if not other:
        return False
    try:
        other_ip = ipaddress.ip_address(other)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv4Address) or not isinstance(
        other_ip, ipaddress.IPv4Address
    ):
        return False
    return int(ip) & 0xFF == 0xFF and ip.packed[:-1] == other_ip.packed[:-1]


def source_ip(record: dict[str, Any], protocol: str) -> str:
    candidates = [
        record.get("id.orig_h"),
        record.get("src"),
        record.get("client_addr") if protocol == "dhcp" else None,
        record.get("host") if protocol in {"known_hosts", "known_services", "software"} else None,
    ]
    for candidate in candidates:
        value = clean(candidate)
        if value and is_ip(value):
            return value
    return ""


def peer_ip(record: dict[str, Any], protocol: str) -> str:
    candidates = [
        record.get("id.resp_h"),
        record.get("dst"),
        record.get("server_addr") if protocol == "dhcp" else None,
    ]
    for candidate in candidates:
        value = clean(candidate)
        if value and is_ip(value):
            return value
    return ""


def is_ignored_multicast_broadcast(host: str, peer: str) -> bool:
    return bool(
        (host and is_multicast_or_broadcast(host, peer))
        or (peer and is_multicast_or_broadcast(peer, host))
    )


def transform(value: float) -> float:
    return math.log1p(max(0.0, value))


def inverse(value: float) -> float:
    return math.expm1(value)


def bucket_start(timestamp: float, window_seconds: int) -> int:
    value = int(timestamp)
    return value - value % window_seconds


def zeek_values(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [clean(item) for item in value if clean(item)]
    normalized = clean(value)
    if not normalized:
        return []
    return [item for item in normalized.split(",") if item and item != "-"]


def zeek_bool(value: Any) -> bool:
    return clean(value).upper() in {"1", "T", "TRUE", "YES"}


def text_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def dns_lexical_metrics(value: Any) -> dict[str, Any]:
    query = clean(value).lower().rstrip(".")
    labels = query.split(".") if query else []
    first_label = labels[0] if labels else ""
    tld = labels[-1] if labels else ""
    alpha = [character for character in first_label if character.isalpha()]
    digits = sum(character.isdigit() for character in first_label)
    vowels = sum(character in "aeiou" for character in alpha)
    label_length = len(first_label)
    entropy = text_entropy(first_label)
    unique_ratio = len(set(first_label)) / max(1, label_length)
    vowel_ratio = vowels / max(1, len(alpha))
    digit_ratio = digits / max(1, label_length)
    dga_like = bool(
        label_length >= 8
        and entropy >= 2.8
        and unique_ratio >= 0.55
        and (vowel_ratio <= 0.45 or digit_ratio >= 0.10)
    )
    reverse = query.endswith(".in-addr.arpa") or query.endswith(".ip6.arpa")
    service_discovery = (
        query.startswith("_")
        or "._tcp.local" in query
        or "._udp.local" in query
    )
    return {
        "query": query,
        "tld": tld,
        "query_length": len(query),
        "label_count": len(labels),
        "first_label_length": label_length,
        "query_entropy": entropy,
        "unique_character_ratio": unique_ratio,
        "vowel_ratio": vowel_ratio,
        "digit_ratio": digit_ratio,
        "dga_like": dga_like,
        "is_local_tld": tld == "local",
        "is_reverse_lookup": reverse,
        "is_service_discovery": service_discovery,
        "pattern": f"{tld}:{label_length // 4}:{round(entropy * 2)}",
    }


def parse_normal_dirs(value: Any) -> list[Path]:
    if isinstance(value, (list, tuple)):
        items = [clean(item) for item in value]
    else:
        items = clean(value).replace("\n", ",").split(",")
    return [Path(item.strip()).expanduser() for item in items if item.strip()]


def flow_identifier_fields(flows: list[dict[str, Any]]) -> dict[str, list[str]]:
    uids = {clean(flow.get("uid")) for flow in flows if clean(flow.get("uid"))}
    fuids: set[str] = set()
    for flow in flows:
        fuid = clean(flow.get("fuid"))
        if fuid:
            fuids.add(fuid)
        fuids.update(zeek_values(flow.get("details", {}).get("linked_fuids")))
    return {
        "responsible_uids": sorted(uids),
        "responsible_fuids": sorted(fuids),
    }


def importance_metrics(
    reasons: list[dict[str, Any]],
    total_score: float,
    protocol_count: int = 1,
) -> dict[str, Any]:
    """Explainable UI ranking; does not participate in anomaly detection."""
    threshold_excess = sum(
        max(
            0.0,
            number(reason.get("zscore"), 2.0)
            - number(reason.get("threshold"), 1.5),
        )
        for reason in reasons
    )
    reason_count = len(reasons)
    score_component = 35.0 * (1.0 - math.exp(-total_score / 15.0))
    breadth_component = 25.0 * min(1.0, protocol_count / 4.0)
    reason_component = 20.0 * min(1.0, reason_count / 8.0)
    excess_component = 20.0 * (
        1.0 - math.exp(-threshold_excess / 10.0)
    )
    importance = min(
        100.0,
        score_component
        + breadth_component
        + reason_component
        + excess_component,
    )
    level = (
        "critical"
        if importance >= 80
        else "high"
        if importance >= 60
        else "medium"
        if importance >= 35
        else "low"
    )
    return {
        "total_score": round(total_score, 4),
        "threshold_excess": round(threshold_excess, 4),
        "reason_count": reason_count,
        "protocol_count": protocol_count,
        "importance_score": round(importance, 2),
        "importance_level": level,
        "importance_components": {
            "total_deviation": round(score_component, 2),
            "protocol_breadth": round(breadth_component, 2),
            "reason_breadth": round(reason_component, 2),
            "threshold_excess": round(excess_component, 2),
        },
    }


@dataclass
class ProtocolBucket:
    hour: int
    events: int = 0
    peers: set[str] = field(default_factory=set)
    new_peers: set[str] = field(default_factory=set)
    categorical: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    new_categorical: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    numeric_sums: dict[str, float] = field(
        default_factory=lambda: defaultdict(float)
    )
    numeric_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    derived_sums: dict[str, float] = field(
        default_factory=lambda: defaultdict(float)
    )
    derived_maxes: dict[str, float] = field(
        default_factory=lambda: defaultdict(float)
    )
    derived_sets: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    derived_counts: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    destination_ports: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    dns_patterns: dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    failures: int = 0
    uids: set[str] = field(default_factory=set)
    flow_records: list[dict[str, Any]] = field(default_factory=list)
    ssl_servers: set[str] = field(default_factory=set)
    ssl_new_servers: set[str] = field(default_factory=set)
    ssl_ja3_changes: int = 0
    ssl_known_server_bytes: float = 0.0
    ssl_known_server_flows: int = 0


@dataclass
class ProtocolState:
    bucket: Optional[ProtocolBucket] = None
    known_peers: set[str] = field(default_factory=set)
    known_values: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    models: dict[str, AdaptiveStats] = field(default_factory=dict)
    trained_hours: int = 0
    calibrated: bool = False
    ssl_known_servers: set[str] = field(default_factory=set)
    ssl_known_ja3s: set[str] = field(default_factory=set)
    ssl_server_ja3: dict[str, set[str]] = field(
        default_factory=dict
    )
    ssl_server_models: dict[str, AdaptiveStats] = field(default_factory=dict)
    anomaly_times: list[float] = field(default_factory=list)


@dataclass
class TargetBucket:
    hour: int
    events: int = 0
    sources: set[str] = field(default_factory=set)
    new_sources: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)
    new_ports: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    failures: int = 0
    uids: set[str] = field(default_factory=set)
    flow_records: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class TargetState:
    bucket: Optional[TargetBucket] = None
    known_sources: set[str] = field(default_factory=set)
    known_ports: set[str] = field(default_factory=set)
    models: dict[str, AdaptiveStats] = field(default_factory=dict)
    trained_hours: int = 0
    calibrated: bool = False
    anomaly_times: list[float] = field(default_factory=list)


class Outputs:
    def __init__(
        self,
        path: Path,
        quiet: bool,
        color: str = "auto",
        show_data: bool = True,
    ):
        path.mkdir(parents=True, exist_ok=True)
        self.quiet = quiet
        self.paths = {
            "data": path / "protocol_hourly_data.jsonl",
            "target_data": path / "target_hourly_data.jsonl",
            "flow": path / "flow_anomalies.jsonl",
            "protocol": path / "protocol_anomalies.jsonl",
            "target": path / "target_anomalies.jsonl",
            "global": path / "global_anomalies.jsonl",
            "events": path / "multi_protocol_detector.log.jsonl",
            "human": path / "multi_protocol_detector.log",
        }
        self.handles = {
            key: value.open("w", encoding="utf-8")
            for key, value in self.paths.items()
            if key != "human"
        }
        self.reporter = Reporter(
            self.paths["human"],
            quiet=quiet,
            color=color,
            show_data=show_data,
        )

    def write(self, target: str, event: dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True)
        self.handles[target].write(line + "\n")
        self.handles[target].flush()
        if target != "events":
            self.handles["events"].write(line + "\n")
            self.handles["events"].flush()
        if target == "data":
            self.reporter.data(
                protocol=event["protocol"],
                host=event["host"],
                hour=event["hour_start"],
                phase=event["phase"],
                features=event["features"],
            )
        elif target == "target_data":
            self.reporter.data(
                protocol="all",
                host=event["target"],
                hour=event["hour_start"],
                phase=event["phase"],
                features=event["features"],
            )
        elif target in {"flow", "protocol"}:
            self.reporter.anomaly(
                kind=event["type"],
                protocol=event["protocol"],
                host=event["host"],
                timestamp=event.get("hour_start", event.get("ts", 0)),
                score=event.get(
                    "score", event.get("confidence", {}).get("score", 0.0)
                ),
                reasons=event["reasons"],
                confidence=event.get("confidence", {}).get("level"),
                responsible_flows=event.get("responsible_flows", []),
                responsible_flow_count=event.get("responsible_flow_count"),
            )
        elif target == "target":
            self.reporter.anomaly(
                kind=event["type"],
                host=event["target"],
                timestamp=event.get("hour_start", event.get("ts", 0)),
                score=event.get("score", 0.0),
                reasons=event["reasons"],
                responsible_flows=event.get("responsible_flows", []),
                responsible_flow_count=event.get("responsible_flow_count"),
            )
        elif target == "global":
            self.reporter.global_anomaly(event)

    def close(self, close_reporter: bool = True) -> None:
        for handle in self.handles.values():
            handle.close()
        if close_reporter:
            self.reporter.close()


class MultiProtocolDetector:
    def __init__(self, args: argparse.Namespace, output: Outputs):
        self.args = args
        self.output = output
        self.states: dict[tuple[str, str], ProtocolState] = {}
        self.target_states: dict[str, TargetState] = {}
        self.protocol_anomalies: list[dict[str, Any]] = []
        self.target_anomalies: list[dict[str, Any]] = []
        self.flow_anomalies: list[dict[str, Any]] = []
        self.protocol_window_rows: list[dict[str, Any]] = []
        self.records_by_protocol: dict[str, int] = defaultdict(int)
        self.skipped_no_ip: dict[str, int] = defaultdict(int)
        self.ssl_conn_matches = 0
        self.force_training = False
        self.suppress_output = False

    def observe_derived_features(
        self,
        protocol: str,
        record: dict[str, Any],
        peer: str,
        bucket: ProtocolBucket,
    ) -> tuple[dict[str, Any], dict[str, bool]]:
        details: dict[str, Any] = {}
        flags: dict[str, bool] = {}
        if protocol == "conn":
            port = clean(record.get("id.resp_p"))
            if peer and port:
                bucket.destination_ports[peer].add(port)
            state = clean(record.get("conn_state"))
            history = clean(record.get("history"))
            duration_present = bool(clean(record.get("duration")))
            duration = number(record.get("duration"))
            total_bytes = number(record.get("orig_bytes")) + number(
                record.get("resp_bytes")
            )
            total_packets = number(record.get("orig_pkts")) + number(
                record.get("resp_pkts")
            )
            derived = {
                "failed_scan": state
                in {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH", "SH", "SHR"},
                "scan_history": history in {"S", "Sr", "Ar", "A", "R", "Sh", "ShR"},
                "short_connection": duration_present and duration <= 0.05,
                "zero_payload": total_bytes <= 0,
                "missing_service": not clean(record.get("service")),
                "established_session": state in {"SF", "S1"},
            }
            for name, matched in derived.items():
                if matched:
                    bucket.derived_counts[name] += 1
                flags[name] = matched
            bytes_per_second = total_bytes / duration if duration > 0 else 0.0
            bytes_per_packet = total_bytes / max(total_packets, 1.0)
            bucket.derived_sums["total_packets"] += total_packets
            bucket.derived_sums["bytes_per_second"] += bytes_per_second
            bucket.derived_sums["bytes_per_packet"] += bytes_per_packet
            bucket.derived_maxes["bytes_per_second"] = max(
                bucket.derived_maxes["bytes_per_second"], bytes_per_second
            )
            details.update(
                {
                    "history": history,
                    "total_packets": total_packets,
                    "total_bytes": total_bytes,
                    "bytes_per_second": round(bytes_per_second, 6),
                    "bytes_per_packet": round(bytes_per_packet, 6),
                }
            )
        elif protocol == "dns":
            metrics = dns_lexical_metrics(record.get("query"))
            port = clean(record.get("id.resp_p"))
            benign = bool(
                port == "5353"
                or metrics["is_local_tld"]
                or metrics["is_reverse_lookup"]
                or metrics["is_service_discovery"]
            )
            dga_like = bool(metrics["dga_like"] and not benign)
            answers = zeek_values(record.get("answers"))
            no_answer = not answers
            bucket.derived_sums["query_entropy"] += metrics["query_entropy"]
            bucket.derived_sums["first_label_length"] += metrics[
                "first_label_length"
            ]
            bucket.derived_maxes["query_entropy"] = max(
                bucket.derived_maxes["query_entropy"], metrics["query_entropy"]
            )
            bucket.derived_maxes["first_label_length"] = max(
                bucket.derived_maxes["first_label_length"],
                metrics["first_label_length"],
            )
            if metrics["tld"]:
                bucket.derived_sets["dns_tlds"].add(metrics["tld"])
            if dga_like:
                bucket.derived_counts["dga_like"] += 1
                bucket.dns_patterns[metrics["pattern"]] += 1
            if no_answer:
                bucket.derived_counts["no_answer"] += 1
            if zeek_bool(record.get("rejected")):
                bucket.derived_counts["rejected"] += 1
            if benign:
                bucket.derived_counts["benign_dns"] += 1
            flags.update(
                {
                    "dga_like": dga_like,
                    "no_answer": no_answer,
                    "rejected": zeek_bool(record.get("rejected")),
                    "benign_dns": benign,
                }
            )
            details.update(metrics)
            details["answer_count"] = len(answers)
        elif protocol == "http":
            uri = clean(record.get("uri"))
            linked_fuids = zeek_values(record.get("_linked_fuids"))
            bucket.derived_sums["uri_length"] += len(uri)
            bucket.derived_maxes["uri_length"] = max(
                bucket.derived_maxes["uri_length"], len(uri)
            )
            if uri:
                bucket.derived_sets["uris"].add(uri)
            bucket.derived_sums["linked_file_count"] += number(
                record.get("_linked_file_count")
            )
            bucket.derived_sums["linked_file_bytes"] += number(
                record.get("_linked_file_bytes")
            )
            bucket.derived_sets["linked_file_mimes"].update(
                zeek_values(record.get("_linked_file_mimes"))
            )
            flags["linked_file"] = bool(linked_fuids)
            details.update(
                {
                    "uri": uri,
                    "uri_length": len(uri),
                    "linked_fuids": linked_fuids,
                    "linked_file_count": number(record.get("_linked_file_count")),
                    "linked_file_bytes": number(record.get("_linked_file_bytes")),
                    "linked_file_mimes": zeek_values(
                        record.get("_linked_file_mimes")
                    ),
                }
            )
        elif protocol == "files":
            byte_gap = abs(
                number(record.get("total_bytes"))
                - number(record.get("seen_bytes"))
            )
            bucket.derived_sums["byte_gap"] += byte_gap
            bucket.derived_maxes["byte_gap"] = max(
                bucket.derived_maxes["byte_gap"], byte_gap
            )
            details["byte_gap"] = byte_gap
        elif protocol == "ssh":
            attempts = number(record.get("auth_attempts"))
            bucket.derived_maxes["auth_attempts"] = max(
                bucket.derived_maxes["auth_attempts"], attempts
            )
            details["auth_attempts"] = attempts

        uid_protocols = zeek_values(record.get("_uid_protocols"))
        linked_fuids = zeek_values(record.get("_linked_fuids"))
        if uid_protocols:
            details["uid_protocols"] = uid_protocols
        if linked_fuids:
            details["linked_fuids"] = linked_fuids
        details["uid_weird_count"] = int(number(record.get("_uid_weird_count")))
        details["uid_notice_count"] = int(number(record.get("_uid_notice_count")))
        flags["cross_log_uid"] = len(uid_protocols) >= 2
        return details, flags

    def ssl_confidence(
        self,
        state: ProtocolState,
        ts: float,
        reasons: list[dict[str, Any]],
        baseline_count: int,
    ) -> dict[str, Any]:
        state.anomaly_times[:] = [
            item for item in state.anomaly_times if ts - item <= 86400
        ]
        scores = [number(reason.get("zscore"), 2.0) for reason in reasons]
        severity = 1.0 - math.exp(-max(scores, default=0.0) / 3.0)
        persistence = min(
            1.0,
            sum(ts - item <= 10800 for item in state.anomaly_times) / 3.0,
        )
        stable = max(10, self.args.minimum_points * 3)
        quality = min(1.0, baseline_count / stable)
        multi_signal = min(1.0, len(reasons) / 3.0)
        score = min(
            1.0,
            0.45 * severity
            + 0.25 * persistence
            + 0.20 * quality
            + 0.10 * multi_signal,
        )
        level = "high" if score >= 0.80 else "medium" if score >= 0.55 else "low"
        return {
            "score": round(score, 4),
            "level": level,
            "severity": round(severity, 4),
            "persistence": round(persistence, 4),
            "baseline_quality": round(quality, 4),
            "multi_signal": round(multi_signal, 4),
        }

    def process_ssl_flow(
        self,
        record: dict[str, Any],
        host: str,
        ts: float,
        state: ProtocolState,
        bucket: ProtocolBucket,
    ) -> dict[str, Any]:
        uid = clean(record.get("uid"))
        destination = clean(record.get("id.resp_h"))
        server_name = clean(record.get("server_name"))
        server = server_name or destination or "<unknown_server>"
        ja3 = clean(record.get("ja3"))
        ja3s = clean(record.get("ja3s"))
        server_ja3 = state.ssl_server_ja3.setdefault(server, set())
        new_server = server not in state.ssl_known_servers
        new_ja3 = bool(ja3 and ja3 not in server_ja3)
        new_ja3s = bool(ja3s and ja3s not in state.ssl_known_ja3s)
        total_bytes = record.get("_conn_total_bytes")
        if total_bytes is not None:
            self.ssl_conn_matches += 1

        bucket.ssl_servers.add(server)
        if new_server:
            bucket.ssl_new_servers.add(server)
        if new_ja3:
            bucket.ssl_ja3_changes += 1
        if total_bytes is not None and not new_server:
            bucket.ssl_known_server_bytes += number(total_bytes)
            bucket.ssl_known_server_flows += 1

        flow = {
            "log": "ssl",
            "ts": ts,
            "uid": uid,
            "fuid": "",
            "src": host,
            "src_port": clean(record.get("id.orig_p")),
            "dst": destination,
            "dst_port": clean(record.get("id.resp_p")),
            "details": {
                "server": server,
                "ja3": ja3,
                "ja3s": ja3s,
                "version": clean(record.get("version")),
                "cipher": clean(record.get("cipher")),
                "total_bytes": total_bytes,
            },
            "_new_server": new_server,
            "_new_ja3": new_ja3,
            "_new_ja3s": new_ja3s,
            "_known_server_bytes": total_bytes is not None and not new_server,
        }

        detecting = (
            not self.force_training
            and state.trained_hours >= self.args.training_hours
        )
        reasons: list[dict[str, Any]] = []
        server_model = state.ssl_server_models.setdefault(
            server, AdaptiveStats()
        )
        if (
            total_bytes is not None
            and not new_server
            and detecting
            and server_model.count >= self.args.minimum_points
        ):
            zscore = server_model.robust_zscore(
                transform(number(total_bytes)), self.args.minimum_points
            )
            threshold = (
                server_model.threshold or self.args.ssl_flow_threshold
            ) / self.args.sensitivity
            if zscore >= threshold:
                mean = inverse(server_model.mean)
                reasons.append(
                    {
                        "feature": "bytes_to_known_server",
                        "value": number(total_bytes),
                        "mean": round(mean, 3),
                        "zscore": round(zscore, 3),
                        "threshold": round(threshold, 3),
                        "direction": (
                            "higher" if number(total_bytes) >= mean else "lower"
                        ),
                        "explanation": (
                            "This SSL flow transferred an unusual amount of "
                            "data for this source IP and known server."
                        ),
                    }
                )
        novelty_threshold = (
            self.args.ssl_novelty_threshold / self.args.sensitivity
        )
        if detecting and new_server and 2.0 >= novelty_threshold:
            reasons.append(
                {
                    "feature": "new_server",
                    "value": server,
                    "direction": "new",
                    "explanation": (
                        "This SNI or destination IP was absent from the "
                        "source IP's benign SSL history."
                    ),
                }
            )
        if detecting and new_ja3s and 2.0 >= novelty_threshold:
            reasons.append(
                {
                    "feature": "new_ja3s",
                    "value": ja3s,
                    "direction": "new",
                    "explanation": (
                        "This server TLS fingerprint was absent from the "
                        "source IP's benign SSL history."
                    ),
                }
            )

        if reasons:
            state.anomaly_times.append(ts)
            public_flow = {
                key: value for key, value in flow.items()
                if not key.startswith("_")
            }
            public_flow["matched_features"] = [
                reason["feature"] for reason in reasons
            ]
            total_score = sum(
                number(reason.get("zscore"), 2.0) for reason in reasons
            )
            event = {
                "event": "flow_anomaly",
                "type": "ssl-flow",
                "protocol": "ssl",
                "host": host,
                "ts": ts,
                "window_start": bucket_start(ts, self.args.window_seconds),
                "window_seconds": self.args.window_seconds,
                "uid": uid,
                "server": server,
                "responsible_uids": [uid] if uid else [],
                "responsible_fuids": [],
                "reasons": reasons,
                "responsible_flow_count": 1,
                "responsible_flows": [public_flow],
                "confidence": self.ssl_confidence(
                    state,
                    ts,
                    reasons,
                    max(
                        server_model.count,
                        min(
                            (model.count for model in state.models.values()),
                            default=0,
                        ),
                    ),
                ),
                **importance_metrics(reasons, total_score),
            }
            self.flow_anomalies.append(event)
            self.output.write("flow", event)
        if total_bytes is not None:
            transformed = transform(number(total_bytes))
            if not detecting:
                server_model.fit(transformed)
            else:
                alpha = (
                    self.args.ssl_baseline_alpha
                    if not reasons
                    else self.args.drift_alpha
                    if len(reasons) <= self.args.ssl_max_small_anomalies
                    else self.args.suspicious_alpha
                )
                server_model.update(transformed, alpha)

        state.ssl_known_servers.add(server)
        if ja3:
            server_ja3.add(ja3)
        if ja3s:
            state.ssl_known_ja3s.add(ja3s)
        return flow

    def attribute_flows(
        self,
        bucket: ProtocolBucket,
        reasons: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int, dict[str, list[str]]]:
        selected: dict[str, dict[str, Any]] = {}
        preferred_keys: list[str] = []
        per_reason_limit = max(
            1, self.args.max_responsible_flows // max(1, len(reasons))
        )
        for reason in reasons:
            feature = reason["feature"]
            candidates = bucket.flow_records
            if feature == "new_peers":
                candidates = [f for f in candidates if f["_new_peer"]]
            elif feature == "new_servers":
                candidates = [f for f in candidates if f.get("_new_server")]
            elif feature == "ja3_changes":
                candidates = [f for f in candidates if f.get("_new_ja3")]
            elif feature == "known_server_avg_bytes":
                candidates = [
                    f for f in candidates if f.get("_known_server_bytes")
                ]
                candidates = sorted(
                    candidates,
                    key=lambda f: number(
                        f["details"].get("total_bytes")
                    ),
                    reverse=reason["direction"] == "higher",
                )
            elif feature == "unique_servers":
                by_server: dict[str, dict[str, Any]] = {}
                for flow in candidates:
                    server = clean(flow["details"].get("server"))
                    if server:
                        by_server.setdefault(server, flow)
                candidates = list(by_server.values())
            elif feature == "failure_ratio":
                candidates = [f for f in candidates if f["_failure"]]
            elif feature == "max_ports_per_destination":
                largest = max(
                    (len(ports) for ports in bucket.destination_ports.values()),
                    default=0,
                )
                destinations = {
                    destination
                    for destination, ports in bucket.destination_ports.items()
                    if len(ports) == largest
                }
                candidates = [
                    flow for flow in candidates if flow.get("dst") in destinations
                ]
            elif feature in {
                "failed_scan_ratio",
                "scan_history_ratio",
                "short_connection_ratio",
                "zero_payload_ratio",
                "missing_service_ratio",
                "established_session_ratio",
                "dga_like_count",
                "dga_like_ratio",
                "no_answer_ratio",
                "rejected_ratio",
                "linked_file_count",
                "linked_file_bytes",
            }:
                flag = {
                    "failed_scan_ratio": "failed_scan",
                    "scan_history_ratio": "scan_history",
                    "short_connection_ratio": "short_connection",
                    "zero_payload_ratio": "zero_payload",
                    "missing_service_ratio": "missing_service",
                    "established_session_ratio": "established_session",
                    "dga_like_count": "dga_like",
                    "dga_like_ratio": "dga_like",
                    "no_answer_ratio": "no_answer",
                    "rejected_ratio": "rejected",
                    "linked_file_count": "linked_file",
                    "linked_file_bytes": "linked_file",
                }[feature]
                candidates = [
                    flow
                    for flow in candidates
                    if flow.get("_derived_flags", {}).get(flag)
                ]
            elif feature in {
                "avg_query_entropy",
                "max_query_entropy",
                "avg_first_label_length",
                "max_first_label_length",
                "avg_bytes_per_second",
                "max_bytes_per_second",
                "avg_bytes_per_packet",
                "total_packets",
                "total_byte_gap",
                "max_byte_gap",
                "max_auth_attempts",
                "avg_uri_length",
                "max_uri_length",
            }:
                detail_name = {
                    "avg_query_entropy": "query_entropy",
                    "max_query_entropy": "query_entropy",
                    "avg_first_label_length": "first_label_length",
                    "max_first_label_length": "first_label_length",
                    "avg_bytes_per_second": "bytes_per_second",
                    "max_bytes_per_second": "bytes_per_second",
                    "avg_bytes_per_packet": "bytes_per_packet",
                    "total_packets": "total_packets",
                    "total_byte_gap": "byte_gap",
                    "max_byte_gap": "byte_gap",
                    "max_auth_attempts": "auth_attempts",
                    "avg_uri_length": "uri_length",
                    "max_uri_length": "uri_length",
                }[feature]
                candidates = sorted(
                    [
                        flow
                        for flow in candidates
                        if detail_name in flow.get("details", {})
                    ],
                    key=lambda flow: number(
                        flow.get("details", {}).get(detail_name)
                    ),
                    reverse=reason["direction"] == "higher",
                )
            elif feature.startswith("new_"):
                field_name = feature.removeprefix("new_")
                candidates = [
                    f
                    for f in candidates
                    if field_name in f["_new_fields"]
                ]
            elif feature.startswith("unique_") and feature != "unique_peers":
                field_name = feature.removeprefix("unique_")
                by_value: dict[str, dict[str, Any]] = {}
                for flow in candidates:
                    value = clean(flow["details"].get(field_name))
                    if value:
                        by_value.setdefault(value, flow)
                candidates = list(by_value.values())
            elif feature == "unique_peers":
                by_peer: dict[str, dict[str, Any]] = {}
                for flow in candidates:
                    if flow["dst"]:
                        by_peer.setdefault(flow["dst"], flow)
                candidates = list(by_peer.values())
            elif feature.startswith(("total_", "avg_")):
                field_name = feature.split("_", 1)[1]
                candidates = [
                    f
                    for f in candidates
                    if clean(f["details"].get(field_name))
                ]
                candidates = sorted(
                    candidates,
                    key=lambda f: number(f["details"].get(field_name)),
                    reverse=reason["direction"] == "higher",
                )
            if not candidates:
                # A lower-than-baseline novelty/count value can be caused by
                # absent expected records. Show what was present so the user
                # can inspect the window even though missing flows have no UID.
                candidates = bucket.flow_records
            candidate_keys = []
            for flow in candidates:
                key = (
                    flow.get("uid")
                    or flow.get("fuid")
                    or f"{flow['ts']}:{flow['src']}:{flow['dst']}"
                )
                item = selected.setdefault(key, dict(flow))
                item.setdefault("matched_features", []).append(feature)
                candidate_keys.append(key)
            for key in candidate_keys[:per_reason_limit]:
                if key not in preferred_keys:
                    preferred_keys.append(key)
        total = len(selected)
        ordered_keys = preferred_keys + [
            key for key in selected if key not in preferred_keys
        ]
        result = []
        for key in ordered_keys[: self.args.max_responsible_flows]:
            flow = selected[key]
            result.append(
                {key: value for key, value in flow.items() if not key.startswith("_")}
            )
        identifiers = flow_identifier_fields(list(selected.values()))
        return result, total, identifiers

    def target_features(self, bucket: TargetBucket) -> dict[str, float]:
        return {
            "incoming_flow_count": float(bucket.events),
            "unique_sources": float(len(bucket.sources)),
            "new_sources": float(len(bucket.new_sources)),
            "unique_ports": float(len(bucket.ports)),
            "new_ports": float(len(bucket.new_ports)),
            "unique_protocols": float(len(bucket.protocols)),
            "failure_ratio": bucket.failures / max(1, bucket.events),
        }

    def target_attribute_flows(
        self,
        bucket: TargetBucket,
        reasons: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int, dict[str, list[str]]]:
        selected: dict[str, dict[str, Any]] = {}
        preferred_keys: list[str] = []
        per_reason_limit = max(
            1, self.args.max_responsible_flows // max(1, len(reasons))
        )
        for reason in reasons:
            feature = reason["feature"]
            candidates = bucket.flow_records
            if feature == "unique_sources":
                by_source: dict[str, dict[str, Any]] = {}
                for flow in candidates:
                    source = clean(flow["src"])
                    if source:
                        by_source.setdefault(source, flow)
                candidates = list(by_source.values())
            elif feature == "new_sources":
                candidates = [flow for flow in candidates if flow.get("_new_source")]
            elif feature in {"unique_ports", "new_ports"}:
                if feature == "new_ports":
                    candidates = [flow for flow in candidates if flow.get("_new_port")]
                else:
                    by_port: dict[str, dict[str, Any]] = {}
                    for flow in candidates:
                        port = clean(flow["dst_port"])
                        if port:
                            by_port.setdefault(port, flow)
                    candidates = list(by_port.values())
            elif feature == "unique_protocols":
                by_protocol: dict[str, dict[str, Any]] = {}
                for flow in candidates:
                    proto = clean(flow.get("log"))
                    if proto:
                        by_protocol.setdefault(proto, flow)
                candidates = list(by_protocol.values())
            elif feature == "failure_ratio":
                candidates = [flow for flow in candidates if flow.get("_failure")]
            elif feature == "incoming_flow_count":
                candidates = bucket.flow_records
            if not candidates:
                candidates = bucket.flow_records
            candidate_keys = []
            for flow in candidates:
                key = (
                    flow.get("uid")
                    or flow.get("fuid")
                    or f"{flow['ts']}:{flow['src']}:{flow['dst']}"
                )
                item = selected.setdefault(key, dict(flow))
                item.setdefault("matched_features", []).append(feature)
                candidate_keys.append(key)
            for key in candidate_keys[:per_reason_limit]:
                if key not in preferred_keys:
                    preferred_keys.append(key)
        total = len(selected)
        ordered_keys = preferred_keys + [
            key for key in selected if key not in preferred_keys
        ]
        result = []
        for key in ordered_keys[: self.args.max_responsible_flows]:
            flow = selected[key]
            result.append(
                {key: value for key, value in flow.items() if not key.startswith("_")}
            )
        identifiers = flow_identifier_fields(list(selected.values()))
        return result, total, identifiers

    def observe_target(
        self,
        protocol: str,
        record: dict[str, Any],
        source: str,
        target: str,
        ts: float,
    ) -> None:
        state = self.target_states.setdefault(target, TargetState())
        hour = bucket_start(ts, self.args.window_seconds)
        if state.bucket is None:
            state.bucket = TargetBucket(hour)
        elif state.bucket.hour != hour:
            self.finalize_target(target, state)
            state.bucket = TargetBucket(hour)
        bucket = state.bucket
        bucket.events += 1
        bucket.protocols.add(protocol)
        uid = clean(record.get("uid") or record.get("fuid"))
        if uid:
            bucket.uids.add(uid)
        source = clean(source)
        port = clean(record.get("id.resp_p") or record.get("dst_port"))
        if source:
            bucket.sources.add(source)
            if source not in state.known_sources:
                bucket.new_sources.add(source)
            state.known_sources.add(source)
        if port:
            bucket.ports.add(port)
            if port not in state.known_ports:
                bucket.new_ports.add(port)
            state.known_ports.add(port)
        failure = False
        if protocol in PROTOCOL_FIELDS:
            failure = bool(PROTOCOL_FIELDS[protocol]["failure"](record))
        if failure:
            bucket.failures += 1
        bucket.flow_records.append(
            {
                "log": protocol,
                "ts": ts,
                "uid": uid,
                "fuid": clean(record.get("fuid")),
                "src": source,
                "src_port": clean(record.get("id.orig_p")),
                "dst": target,
                "dst_port": port,
                "details": {
                    "protocol": protocol,
                    "service": clean(record.get("service")),
                    "server_name": clean(record.get("server_name")),
                    "conn_state": clean(record.get("conn_state")),
                    "status_code": clean(record.get("status_code")),
                    "rcode_name": clean(record.get("rcode_name")),
                    "uid_protocols": zeek_values(
                        record.get("_uid_protocols")
                    ),
                    "linked_fuids": zeek_values(record.get("_linked_fuids")),
                },
                "_new_source": source in bucket.new_sources,
                "_new_port": port in bucket.new_ports,
                "_failure": failure,
            }
        )

    def finalize_target(
        self, target: str, state: TargetState
    ) -> None:
        bucket = state.bucket
        if bucket is None:
            return
        features = self.target_features(bucket)
        training = (
            self.force_training
            or state.trained_hours < self.args.training_hours
        )
        reasons: list[dict[str, Any]] = []
        zscores: dict[str, float] = {}
        for name, value in features.items():
            model = state.models.setdefault(name, AdaptiveStats())
            zscore = model.robust_zscore(
                transform(value), self.args.minimum_points
            )
            threshold = (model.threshold or self.args.threshold) / self.args.sensitivity
            zscores[name] = round(zscore, 3)
            if not training and zscore >= threshold:
                mean = inverse(model.mean)
                direction = "higher" if value >= mean else "lower"
                if name == "incoming_flow_count":
                    explanation = (
                        f"Destination IP {target} received {value:g} flows "
                        f"during window {bucket.hour}; its learned "
                        f"baseline is {mean:.3f} per window."
                    )
                else:
                    explanation = (
                        f"Destination IP {target} had an unusual {name} "
                        f"value for this window. Matching Zeek records are "
                        "listed under responsible_flows."
                    )
                reasons.append(
                    {
                        "feature": name,
                        "value": round(value, 6),
                        "mean": round(mean, 6),
                        "zscore": round(zscore, 3),
                        "threshold": round(threshold, 3),
                        "direction": direction,
                        "target_ip": target,
                        "window_seconds": self.args.window_seconds,
                        "hour_start": bucket.hour,
                        "window_start": bucket.hour,
                        "explanation": explanation,
                    }
                )
        if not self.suppress_output:
            self.output.write(
                "target_data",
                {
                "event": "target_hourly_data",
                "target": target,
                "host": target,
                "hour_start": bucket.hour,
                "window_start": bucket.hour,
                "window_seconds": self.args.window_seconds,
                "phase": "training" if training else "detection",
                "trained_hours": state.trained_hours,
                "features": features,
                "zscores": zscores,
                "protocols": sorted(bucket.protocols),
                },
            )
        score = sum(reason["zscore"] for reason in reasons)
        if reasons:
            (
                responsible_flows,
                responsible_count,
                identifiers,
            ) = self.target_attribute_flows(bucket, reasons)
            event = {
                "event": "target_anomaly",
                "type": "target-hour",
                "target": target,
                "host": target,
                "hour_start": bucket.hour,
                "window_start": bucket.hour,
                "window_seconds": self.args.window_seconds,
                "protocols": sorted(bucket.protocols),
                "uids": sorted(bucket.uids),
                "score": round(score, 3),
                "normalized_score": round(
                    min(self.args.protocol_score_cap, score)
                    / self.args.protocol_score_cap,
                    4,
                ),
                "reasons": reasons,
                "responsible_flow_count": responsible_count,
                "responsible_flows": responsible_flows,
                **identifiers,
                **importance_metrics(reasons, score, protocol_count=len(bucket.protocols)),
            }
            self.target_anomalies.append(event)
            if not self.suppress_output:
                self.output.write("target", event)
        if training:
            for name, value in features.items():
                state.models[name].fit(transform(value))
            state.trained_hours += 1
            if (
                state.trained_hours >= self.args.training_hours
                and not state.calibrated
            ):
                for model in state.models.values():
                    model.calibrate(self.args.threshold, self.args.threshold_quantile)
                state.calibrated = True
        else:
            alpha = (
                self.args.drift_alpha
                if score <= self.args.adaptation_score
                else self.args.suspicious_alpha
            )
            for name, value in features.items():
                state.models[name].update(transform(value), alpha)
        state.bucket = None

    def finalize_targets(self) -> None:
        for target, state in self.target_states.items():
            self.finalize_target(target, state)

    def observe(
        self, protocol: str, record: dict[str, Any], host: str, ts: float
    ) -> None:
        key = (host, protocol)
        state = self.states.setdefault(key, ProtocolState())
        hour = bucket_start(ts, self.args.window_seconds)
        if state.bucket is None:
            state.bucket = ProtocolBucket(hour)
        elif state.bucket.hour != hour:
            self.finalize(host, protocol, state)
            state.bucket = ProtocolBucket(hour)
        bucket = state.bucket
        spec = PROTOCOL_FIELDS[protocol]
        ssl_flow = (
            self.process_ssl_flow(record, host, ts, state, bucket)
            if protocol == "ssl"
            else None
        )
        bucket.events += 1
        uid = clean(record.get("uid") or record.get("fuid"))
        if uid:
            bucket.uids.add(uid)
        peer = peer_ip(record, protocol)
        new_peer = bool(peer and peer not in state.known_peers)
        if peer:
            bucket.peers.add(peer)
            if new_peer:
                bucket.new_peers.add(peer)
            state.known_peers.add(peer)
        new_fields: set[str] = set()
        for field_name in spec["categorical"]:
            value = clean(record.get(field_name))
            if not value:
                continue
            bucket.categorical[field_name].add(value)
            if value not in state.known_values[field_name]:
                bucket.new_categorical[field_name].add(value)
                new_fields.add(field_name)
            state.known_values[field_name].add(value)
        for field_name in spec["numeric"]:
            value = clean(record.get(field_name))
            if not value:
                continue
            bucket.numeric_sums[field_name] += number(value)
            bucket.numeric_counts[field_name] += 1
        failure: Callable[[dict[str, Any]], bool] = spec["failure"]
        is_failure = failure(record)
        if is_failure:
            bucket.failures += 1
        details = {
            field_name: clean(record.get(field_name))
            for field_name in (*spec["categorical"], *spec["numeric"])
            if clean(record.get(field_name))
        }
        derived_details, derived_flags = self.observe_derived_features(
            protocol, record, peer, bucket
        )
        details.update(derived_details)
        generic_flow = {
                "log": protocol,
                "ts": ts,
                "uid": clean(record.get("uid")),
                "fuid": clean(record.get("fuid")),
                "src": host,
                "src_port": clean(record.get("id.orig_p")),
                "dst": peer,
                "dst_port": clean(record.get("id.resp_p")),
                "details": details,
                "_new_peer": new_peer,
                "_new_fields": new_fields,
                "_failure": is_failure,
                "_derived_flags": derived_flags,
            }
        if ssl_flow is not None:
            # Keep specialized SSL attribution fields while retaining generic
            # novelty/failure flags used by common protocol features.
            ssl_flow.update(
                {
                    "_new_peer": new_peer,
                    "_new_fields": new_fields,
                    "_failure": is_failure,
                    "_derived_flags": derived_flags,
                }
            )
            ssl_flow["details"].update(details)
            bucket.flow_records.append(ssl_flow)
        else:
            bucket.flow_records.append(generic_flow)
        self.records_by_protocol[protocol] += 1

    def features(
        self, protocol: str, bucket: ProtocolBucket
    ) -> dict[str, float]:
        spec = PROTOCOL_FIELDS[protocol]
        if protocol == "ssl":
            result = {
                "ssl_flows": float(bucket.events),
                "unique_servers": float(len(bucket.ssl_servers)),
                "new_servers": float(len(bucket.ssl_new_servers)),
                "ja3_changes": float(bucket.ssl_ja3_changes),
                "known_server_avg_bytes": (
                    bucket.ssl_known_server_bytes
                    / bucket.ssl_known_server_flows
                    if bucket.ssl_known_server_flows
                    else 0.0
                ),
                "failure_ratio": bucket.failures / max(1, bucket.events),
            }
            # Preserve useful TLS diversity/novelty signals without duplicating
            # server identity, which is represented by unique/new_servers.
            for field_name in spec["categorical"]:
                if field_name == "server_name":
                    continue
                result[f"unique_{field_name}"] = float(
                    len(bucket.categorical[field_name])
                )
                result[f"new_{field_name}"] = float(
                    len(bucket.new_categorical[field_name])
                )
            return result

        result = {
            "flow_count": float(bucket.events),
            "unique_peers": float(len(bucket.peers)),
            "new_peers": float(len(bucket.new_peers)),
            "failure_ratio": bucket.failures / max(1, bucket.events),
        }
        for field_name in spec["categorical"]:
            result[f"unique_{field_name}"] = float(
                len(bucket.categorical[field_name])
            )
            result[f"new_{field_name}"] = float(
                len(bucket.new_categorical[field_name])
            )
        for field_name in spec["numeric"]:
            result[f"total_{field_name}"] = bucket.numeric_sums[field_name]
            result[f"avg_{field_name}"] = (
                bucket.numeric_sums[field_name]
                / max(1, bucket.numeric_counts[field_name])
            )
        events = max(1, bucket.events)
        if protocol == "conn":
            result.update(
                {
                    "max_ports_per_destination": float(
                        max(
                            (
                                len(ports)
                                for ports in bucket.destination_ports.values()
                            ),
                            default=0,
                        )
                    ),
                    "failed_scan_ratio": bucket.derived_counts["failed_scan"]
                    / events,
                    "scan_history_ratio": bucket.derived_counts["scan_history"]
                    / events,
                    "short_connection_ratio": bucket.derived_counts[
                        "short_connection"
                    ]
                    / events,
                    "zero_payload_ratio": bucket.derived_counts["zero_payload"]
                    / events,
                    "missing_service_ratio": bucket.derived_counts[
                        "missing_service"
                    ]
                    / events,
                    "established_session_ratio": bucket.derived_counts[
                        "established_session"
                    ]
                    / events,
                    "total_packets": bucket.derived_sums["total_packets"],
                    "avg_bytes_per_second": bucket.derived_sums[
                        "bytes_per_second"
                    ]
                    / events,
                    "max_bytes_per_second": bucket.derived_maxes[
                        "bytes_per_second"
                    ],
                    "avg_bytes_per_packet": bucket.derived_sums[
                        "bytes_per_packet"
                    ]
                    / events,
                }
            )
        elif protocol == "dns":
            result.update(
                {
                    "avg_query_entropy": bucket.derived_sums["query_entropy"]
                    / events,
                    "max_query_entropy": bucket.derived_maxes["query_entropy"],
                    "avg_first_label_length": bucket.derived_sums[
                        "first_label_length"
                    ]
                    / events,
                    "max_first_label_length": bucket.derived_maxes[
                        "first_label_length"
                    ],
                    "dga_like_count": float(bucket.derived_counts["dga_like"]),
                    "dga_like_ratio": bucket.derived_counts["dga_like"] / events,
                    "repeated_dga_pattern_count": float(
                        sum(max(0, count - 1) for count in bucket.dns_patterns.values())
                    ),
                    "unique_tlds": float(len(bucket.derived_sets["dns_tlds"])),
                    "no_answer_ratio": bucket.derived_counts["no_answer"]
                    / events,
                    "rejected_ratio": bucket.derived_counts["rejected"]
                    / events,
                    "benign_dns_ratio": bucket.derived_counts["benign_dns"]
                    / events,
                }
            )
        elif protocol == "http":
            result.update(
                {
                    "unique_uris": float(len(bucket.derived_sets["uris"])),
                    "avg_uri_length": bucket.derived_sums["uri_length"] / events,
                    "max_uri_length": bucket.derived_maxes["uri_length"],
                    "linked_file_count": bucket.derived_sums[
                        "linked_file_count"
                    ],
                    "linked_file_bytes": bucket.derived_sums[
                        "linked_file_bytes"
                    ],
                    "unique_linked_file_mimes": float(
                        len(bucket.derived_sets["linked_file_mimes"])
                    ),
                }
            )
        elif protocol == "files":
            result.update(
                {
                    "total_byte_gap": bucket.derived_sums["byte_gap"],
                    "max_byte_gap": bucket.derived_maxes["byte_gap"],
                }
            )
        elif protocol == "ssh":
            result["max_auth_attempts"] = bucket.derived_maxes[
                "auth_attempts"
            ]
        return result

    def finalize(
        self, host: str, protocol: str, state: ProtocolState
    ) -> None:
        bucket = state.bucket
        if bucket is None:
            return
        features = self.features(protocol, bucket)
        training = (
            self.force_training
            or state.trained_hours < self.args.training_hours
        )
        reasons: list[dict[str, Any]] = []
        zscores: dict[str, float] = {}
        for name, value in features.items():
            model = state.models.setdefault(name, AdaptiveStats())
            zscore = model.robust_zscore(
                transform(value), self.args.minimum_points
            )
            fallback_threshold = (
                self.args.ssl_hourly_threshold
                if protocol == "ssl"
                and name
                in {
                    "ssl_flows",
                    "unique_servers",
                    "new_servers",
                    "ja3_changes",
                    "known_server_avg_bytes",
                }
                else self.args.threshold
            )
            threshold = (
                model.threshold or fallback_threshold
            ) / self.args.sensitivity
            zscores[name] = round(zscore, 3)
            if not training and zscore >= threshold:
                mean = inverse(model.mean)
                direction = "higher" if value >= mean else "lower"
                if name == "flow_count":
                    explanation = (
                        f"Source IP {host} produced {value:g} {protocol} "
                        f"flows/records during window {bucket.hour}; "
                        f"its learned baseline is {mean:.3f} per window."
                    )
                else:
                    explanation = (
                        f"For source IP {host}, the {protocol} window's {name} "
                        f"value was {direction} than the learned baseline. "
                        "Matching Zeek records are listed under "
                        "responsible_flows."
                    )
                reasons.append(
                    {
                        "feature": name,
                        "value": round(value, 6),
                        "mean": round(mean, 6),
                        "zscore": round(zscore, 3),
                        "threshold": round(threshold, 3),
                        "direction": direction,
                        "source_ip": host,
                        "protocol": protocol,
                        "hour_start": bucket.hour,
                        "window_start": bucket.hour,
                        "window_seconds": self.args.window_seconds,
                        "explanation": explanation,
                    }
                )
        data_event = {
            "event": "protocol_hourly_data",
            "host": host,
            "protocol": protocol,
            "hour_start": bucket.hour,
            "window_start": bucket.hour,
            "window_seconds": self.args.window_seconds,
            "phase": "training" if training else "detection",
            "trained_hours": state.trained_hours,
            "features": features,
            "zscores": zscores,
        }
        identifiers = flow_identifier_fields(bucket.flow_records)
        self.protocol_window_rows.append(
            {
                **data_event,
                "external_baseline": self.force_training,
                "uids": identifiers["responsible_uids"],
                "fuids": identifiers["responsible_fuids"],
            }
        )
        if not self.suppress_output:
            self.output.write(
                "data",
                data_event,
            )
        score = sum(reason["zscore"] for reason in reasons)
        if reasons:
            (
                responsible_flows,
                responsible_count,
                identifiers,
            ) = self.attribute_flows(bucket, reasons)
            severity = 1.0 - math.exp(-max(
                reason["zscore"] for reason in reasons
            ) / 3.0)
            event = {
                "event": "protocol_anomaly",
                "type": "protocol-hour",
                "host": host,
                "protocol": protocol,
                "hour_start": bucket.hour,
                "window_start": bucket.hour,
                "window_seconds": self.args.window_seconds,
                "uids": sorted(bucket.uids),
                "score": round(score, 3),
                "normalized_score": round(
                    min(self.args.protocol_score_cap, score)
                    / self.args.protocol_score_cap,
                    4,
                ),
                "severity": round(severity, 4),
                "reasons": reasons,
                "responsible_flow_count": responsible_count,
                "responsible_flows": responsible_flows,
                **identifiers,
                **importance_metrics(reasons, score),
            }
            self.protocol_anomalies.append(event)
            if not self.suppress_output:
                self.output.write("protocol", event)
        if training:
            for name, value in features.items():
                state.models[name].fit(transform(value))
            state.trained_hours += 1
            if (
                state.trained_hours >= self.args.training_hours
                and not state.calibrated
            ):
                for feature_name, model in state.models.items():
                    fallback = (
                        self.args.ssl_hourly_threshold
                        if protocol == "ssl"
                        and feature_name
                        in {
                            "ssl_flows",
                            "unique_servers",
                            "new_servers",
                            "ja3_changes",
                            "known_server_avg_bytes",
                        }
                        else self.args.threshold
                    )
                    model.calibrate(
                        fallback, self.args.threshold_quantile
                    )
                for model in state.ssl_server_models.values():
                    model.calibrate(
                        self.args.ssl_flow_threshold,
                        self.args.threshold_quantile,
                    )
                state.calibrated = True
            mode = "training_fit"
        else:
            small = score <= self.args.adaptation_score
            alpha = (
                self.args.drift_alpha
                if small
                else self.args.suspicious_alpha
            )
            for name, value in features.items():
                state.models[name].update(transform(value), alpha)
            mode = (
                "drift_update" if small else "suspicious_update"
            )
        if not self.suppress_output:
            self.output.write(
                "events",
                {
                "event": "model_update",
                "host": host,
                "protocol": protocol,
                "hour_start": bucket.hour,
                "window_start": bucket.hour,
                "window_seconds": self.args.window_seconds,
                "mode": mode,
                "score": round(score, 3),
                },
            )
        state.bucket = None

    def finalize_all(self) -> None:
        for (host, protocol), state in self.states.items():
            self.finalize(host, protocol, state)

    def calibrate_baseline(self) -> None:
        """Calibrate every model after explicitly normal traffic is fitted."""
        for (_, protocol), state in self.states.items():
            for feature_name, model in state.models.items():
                fallback = (
                    self.args.ssl_hourly_threshold
                    if protocol == "ssl"
                    and feature_name
                    in {
                        "ssl_flows",
                        "unique_servers",
                        "new_servers",
                        "ja3_changes",
                        "known_server_avg_bytes",
                    }
                    else self.args.threshold
                )
                model.calibrate(fallback, self.args.threshold_quantile)
            for model in state.ssl_server_models.values():
                model.calibrate(
                    self.args.ssl_flow_threshold,
                    self.args.threshold_quantile,
                )
            state.calibrated = True
            state.trained_hours = max(
                state.trained_hours, self.args.training_hours
            )
        for state in self.target_states.values():
            for model in state.models.values():
                model.calibrate(
                    self.args.threshold, self.args.threshold_quantile
                )
            state.calibrated = True
            state.trained_hours = max(
                state.trained_hours, self.args.training_hours
            )

    def reset_run_counters(self) -> None:
        """Keep learned state but exclude baseline input from run statistics."""
        self.records_by_protocol.clear()
        self.skipped_no_ip.clear()
        self.ssl_conn_matches = 0
        self.protocol_anomalies.clear()
        self.target_anomalies.clear()
        self.flow_anomalies.clear()

    def ensemble(self) -> list[dict[str, Any]]:
        self.output.reporter.section(
            "GLOBAL IP ENSEMBLE",
            "Magenta=global anomaly, yellow=protocol contribution",
        )
        grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for anomaly in self.protocol_anomalies:
            grouped[(anomaly["host"], anomaly["hour_start"])].append(anomaly)
        for anomaly in self.target_anomalies:
            grouped[(anomaly["target"], anomaly["hour_start"])].append(anomaly)
        global_events = []
        for (host, hour), events in sorted(grouped.items()):
            # At most one capped vote per component; avoids volume domination.
            by_protocol = {
                (
                    event.get("protocol")
                    if "protocol" in event
                    else f"target:{event.get('target', '?')}"
                ): event
                for event in sorted(events, key=lambda item: item["normalized_score"])
            }
            contributions = {
                protocol: event["normalized_score"]
                for protocol, event in by_protocol.items()
            }
            protocols = sorted(contributions)
            vote_sum = sum(contributions.values())
            corroboration = min(
                self.args.corroboration_bonus_cap,
                max(0, len(protocols) - 1) * self.args.corroboration_bonus,
            )
            uid_owners: dict[str, set[str]] = defaultdict(set)
            fuid_owners: dict[str, set[str]] = defaultdict(set)
            for component, item in by_protocol.items():
                for uid in item.get("responsible_uids", []):
                    uid_owners[uid].add(component)
                for fuid in item.get("responsible_fuids", []):
                    fuid_owners[fuid].add(component)
            shared_uids = sorted(
                uid for uid, owners in uid_owners.items() if len(owners) >= 2
            )
            shared_fuids = sorted(
                fuid
                for fuid, owners in fuid_owners.items()
                if len(owners) >= 2
            )
            uid_corroboration = min(
                self.args.uid_corroboration_bonus_cap,
                len(shared_uids) * self.args.uid_corroboration_bonus,
            )
            global_score = min(
                1.0, vote_sum + corroboration + uid_corroboration
            )
            effective_global_threshold = min(
                1.0, self.args.global_threshold / self.args.sensitivity
            )
            effective_minimum_protocols = max(
                1,
                math.ceil(
                    self.args.minimum_protocols / self.args.sensitivity
                ),
            )
            should_emit = (
                global_score >= effective_global_threshold
                or len(protocols) >= effective_minimum_protocols
            )
            if not should_emit:
                continue
            confidence = (
                "high"
                if global_score >= 0.8
                else "medium"
                if global_score >= 0.55
                else "low"
            )
            event = {
                "event": "global_anomaly",
                "host": host,
                "hour_start": hour,
                "window_start": hour,
                "window_seconds": self.args.window_seconds,
                "global_score": round(global_score, 4),
                "confidence": confidence,
                "protocols": protocols,
                "protocol_contributions": contributions,
                "corroboration_bonus": round(corroboration, 4),
                "uid_corroboration_bonus": round(uid_corroboration, 4),
                "shared_uids": shared_uids,
                "shared_fuids": shared_fuids,
                "responsible_uids": sorted(uid_owners),
                "responsible_fuids": sorted(fuid_owners),
                "effective_global_threshold": round(
                    effective_global_threshold, 4
                ),
                "effective_minimum_protocols": effective_minimum_protocols,
                "protocol_anomalies": [
                    {
                        "protocol": item["protocol"],
                        "score": item["score"],
                        "reasons": item["reasons"],
                        "responsible_flow_count": item[
                            "responsible_flow_count"
                        ],
                        "responsible_flows": item["responsible_flows"],
                    }
                    for item in by_protocol.values()
                    if item.get("event") == "protocol_anomaly"
                ],
                "target_anomalies": [
                    {
                        "target": item["target"],
                        "score": item["score"],
                        "reasons": item["reasons"],
                        "responsible_flow_count": item[
                            "responsible_flow_count"
                        ],
                        "responsible_flows": item["responsible_flows"],
                    }
                    for item in by_protocol.values()
                    if item.get("event") == "target_anomaly"
                ],
            }
            global_reasons = [
                reason
                for item in by_protocol.values()
                for reason in item["reasons"]
            ]
            global_total_score = sum(
                number(item["score"]) for item in by_protocol.values()
            )
            event.update(
                importance_metrics(
                    global_reasons,
                    global_total_score,
                    protocol_count=len(protocols),
                )
            )
            combined: dict[str, dict[str, Any]] = {}
            total_responsible = 0
            for item in by_protocol.values():
                total_responsible += item["responsible_flow_count"]
                for flow in item["responsible_flows"]:
                    key = (
                        f"{flow.get('log')}:{flow.get('uid') or flow.get('fuid')}"
                        f":{flow.get('ts')}:{flow.get('dst')}"
                    )
                    combined.setdefault(key, flow)
            event["responsible_flow_count"] = total_responsible
            event["responsible_flows"] = list(combined.values())[
                : self.args.max_responsible_flows
            ]
            global_events.append(event)
            self.output.write("global", event)
        return global_events


Observation = tuple[float, str, dict[str, Any], str, str]


def enrich_cross_log_context(observations: list[Observation]) -> None:
    """Attach exact UID and file-transfer context before window aggregation."""
    uid_protocols: dict[str, set[str]] = defaultdict(set)
    uid_weird: dict[str, int] = defaultdict(int)
    uid_notice: dict[str, int] = defaultdict(int)
    files: dict[str, dict[str, Any]] = {}
    for _, protocol, record, _, _ in observations:
        uid = clean(record.get("uid"))
        if uid:
            uid_protocols[uid].add(protocol)
            if protocol == "weird":
                uid_weird[uid] += 1
            elif protocol == "notice":
                uid_notice[uid] += 1
        if protocol == "files":
            fuid = clean(record.get("fuid"))
            if fuid:
                files[fuid] = {
                    "bytes": max(
                        number(record.get("total_bytes")),
                        number(record.get("seen_bytes")),
                    ),
                    "mime": clean(record.get("mime_type")),
                }
    for _, protocol, record, _, _ in observations:
        uid = clean(record.get("uid"))
        if uid:
            record["_uid_protocols"] = sorted(uid_protocols[uid])
            record["_uid_weird_count"] = uid_weird[uid]
            record["_uid_notice_count"] = uid_notice[uid]
        if protocol != "http":
            continue
        linked: list[str] = []
        for field_name in ("resp_fuids", "orig_fuids", "fuid"):
            for fuid in zeek_values(record.get(field_name)):
                if fuid not in linked:
                    linked.append(fuid)
        linked_files = [files[fuid] for fuid in linked if fuid in files]
        record["_linked_fuids"] = linked
        record["_linked_file_count"] = len(linked_files)
        record["_linked_file_bytes"] = sum(
            item["bytes"] for item in linked_files
        )
        record["_linked_file_mimes"] = sorted(
            {item["mime"] for item in linked_files if item["mime"]}
        )


def collect_observations(
    directory: Path,
    args: argparse.Namespace,
    detector: MultiProtocolDetector,
) -> tuple[list[Observation], list[tuple[str, Path]], list[str]]:
    logs, skipped = discover_logs(directory)
    observations: list[Observation] = []
    connections: dict[str, dict[str, Any]] = {}
    for protocol, path in logs:
        for record in ZeekReader(path):
            uid = clean(record.get("uid"))
            if protocol == "conn" and uid:
                connections[uid] = record
            host = source_ip(record, protocol)
            if not host:
                detector.skipped_no_ip[protocol] += 1
                continue
            peer = peer_ip(record, protocol)
            if args.ignore_multicast_broadcast and is_ignored_multicast_broadcast(
                host, peer
            ):
                continue
            observations.append(
                (number(record.get("ts")), protocol, record, host, peer)
            )
    for _, protocol, record, _, _ in observations:
        if protocol != "ssl":
            continue
        conn = connections.get(clean(record.get("uid")))
        if conn:
            record["_conn_total_bytes"] = number(
                conn.get("orig_bytes")
            ) + number(conn.get("resp_bytes"))
    enrich_cross_log_context(observations)
    observations.sort(key=lambda item: item[0])
    return observations, logs, skipped


def process_observations(
    detector: MultiProtocolDetector, observations: list[Observation]
) -> None:
    for ts, protocol, record, host, peer in observations:
        detector.observe(protocol, record, host, ts)
        if peer:
            detector.observe_target(protocol, record, host, peer, ts)
    detector.finalize_all()
    detector.finalize_targets()


def discover_logs(directory: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    selected = []
    skipped = []
    for path in sorted(directory.glob("*.log")):
        protocol = path.stem
        if protocol in SKIPPED_LOGS:
            skipped.append(protocol)
        elif protocol in PROTOCOL_FIELDS:
            selected.append((protocol, path))
        else:
            skipped.append(protocol)
    return selected, skipped


def parser(
    settings: Optional[dict[str, Any]] = None,
) -> argparse.ArgumentParser:
    settings = settings or MULTI_DEFAULTS
    result = argparse.ArgumentParser(
        description=(
            "Adaptive per-protocol Zeek anomaly detection with a global "
            "per-IP ensemble."
        )
    )
    result.add_argument("zeek_dir", type=Path)
    result.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"INI configuration file (default: {DEFAULT_CONFIG.name})",
    )
    result.add_argument(
        "-o", "--output-dir", type=Path, default=settings["output_dir"]
    )
    result.add_argument(
        "--training-hours",
        type=int,
        default=settings["training_hours"],
        help=(
            "initial observed windows fitted as benign per model; "
            "0 skips explicit training but still requires --minimum-points"
        ),
    )
    result.add_argument(
        "--window-seconds",
        type=int,
        default=settings["window_seconds"],
        help="aggregation window size in seconds (default: 3600)",
    )
    result.add_argument(
        "--normal-dir",
        dest="normal_dirs",
        action="append",
        type=Path,
        default=parse_normal_dirs(settings["normal_dirs"]),
        help=(
            "Zeek directory known to be normal; repeat to fit external "
            "baseline windows before analyzing zeek_dir"
        ),
    )
    result.add_argument(
        "--sensitivity",
        type=float,
        default=settings["sensitivity"],
        help="global anomaly sensitivity; >1 produces more anomalies, <1 fewer",
    )
    multicast_group = result.add_mutually_exclusive_group()
    multicast_group.add_argument(
        "--ignore-multicast-broadcast",
        dest="ignore_multicast_broadcast",
        action="store_true",
        default=settings["ignore_multicast_broadcast"],
        help="skip multicast and broadcast flows",
    )
    multicast_group.add_argument(
        "--keep-multicast-broadcast",
        dest="ignore_multicast_broadcast",
        action="store_false",
        help="keep multicast and broadcast flows",
    )
    result.add_argument(
        "--minimum-points",
        type=int,
        default=settings["minimum_points"],
        help="prior model observations required before a nonzero z-score",
    )
    result.add_argument("--threshold", type=float, default=settings["threshold"])
    result.add_argument(
        "--threshold-quantile",
        type=float,
        default=settings["threshold_quantile"],
    )
    result.add_argument(
        "--drift-alpha", type=float, default=settings["drift_alpha"]
    )
    result.add_argument(
        "--suspicious-alpha",
        type=float,
        default=settings["suspicious_alpha"],
    )
    result.add_argument(
        "--adaptation-score", type=float, default=settings["adaptation_score"]
    )
    result.add_argument(
        "--protocol-score-cap",
        type=float,
        default=settings["protocol_score_cap"],
    )
    result.add_argument(
        "--global-threshold", type=float, default=settings["global_threshold"]
    )
    result.add_argument(
        "--minimum-protocols",
        type=int,
        default=settings["minimum_protocols"],
    )
    result.add_argument(
        "--corroboration-bonus",
        type=float,
        default=settings["corroboration_bonus"],
    )
    result.add_argument(
        "--corroboration-bonus-cap",
        type=float,
        default=settings["corroboration_bonus_cap"],
    )
    result.add_argument(
        "--uid-corroboration-bonus",
        type=float,
        default=settings["uid_corroboration_bonus"],
    )
    result.add_argument(
        "--uid-corroboration-bonus-cap",
        type=float,
        default=settings["uid_corroboration_bonus_cap"],
    )
    result.add_argument(
        "--max-responsible-flows",
        type=int,
        default=settings["max_responsible_flows"],
        help="maximum representative flows stored per aggregate anomaly",
    )
    result.add_argument(
        "--ssl-hourly-threshold",
        type=float,
        default=settings["ssl_hourly_threshold"],
    )
    result.add_argument(
        "--ssl-flow-threshold",
        type=float,
        default=settings["ssl_flow_threshold"],
    )
    result.add_argument(
        "--ssl-novelty-threshold",
        type=float,
        default=settings["ssl_novelty_threshold"],
    )
    result.add_argument(
        "--ssl-baseline-alpha",
        type=float,
        default=settings["ssl_baseline_alpha"],
    )
    result.add_argument(
        "--ssl-max-small-anomalies",
        type=int,
        default=settings["ssl_max_small_anomalies"],
    )
    result.add_argument(
        "--experimental-noop-mode",
        choices=("off", "shadow"),
        default=settings["experimental_noop_mode"],
        help=(
            "no-op experimental pipeline validation: off or shadow"
        ),
    )
    result.add_argument(
        "--experimental-mirror-mode",
        choices=("off", "shadow"),
        default=settings["experimental_mirror_mode"],
        help=(
            "core-mirror validation module: compares identical host/window "
            "decisions without adding a second detection contribution"
        ),
    )
    result.add_argument(
        "--experimental-multivariate-mode",
        choices=("off", "shadow"),
        default=settings["experimental_multivariate_mode"],
        help="robust multivariate detector; gated to off or shadow during evaluation",
    )
    result.add_argument(
        "--multivariate-minimum-points",
        type=int,
        default=settings["multivariate_minimum_points"],
    )
    result.add_argument(
        "--multivariate-threshold",
        type=float,
        default=settings["multivariate_threshold"],
    )
    result.add_argument(
        "--multivariate-shrinkage",
        type=float,
        default=settings["multivariate_shrinkage"],
    )
    result.add_argument(
        "--multivariate-history-limit",
        type=int,
        default=settings["multivariate_history_limit"],
    )
    result.add_argument(
        "-q", "--quiet", action="store_true", default=settings["quiet"]
    )
    result.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default=settings["color"],
        help="terminal color policy (default: auto)",
    )
    result.add_argument(
        "--no-terminal-data",
        action="store_true",
        default=not settings["show_terminal_data"],
        help="hide window DATA lines but still show anomalies and summary",
    )
    return result


def main(argv: Optional[list[str]] = None) -> int:
    raw_argv = sys.argv[1:] if argv is None else argv
    bootstrap = argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    config_args, _ = bootstrap.parse_known_args(raw_argv)
    try:
        settings = load_settings(
            config_args.config, "multi_protocol", MULTI_DEFAULTS
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args = parser(settings).parse_args(raw_argv)
    if not args.zeek_dir.is_dir():
        print(f"error: not a directory: {args.zeek_dir}", file=sys.stderr)
        return 2
    for normal_dir in args.normal_dirs:
        if not normal_dir.is_dir():
            print(f"error: not a directory: {normal_dir}", file=sys.stderr)
            return 2
    if (
        args.training_hours < 0
        or args.window_seconds < 1
        or args.minimum_points < 1
        or args.protocol_score_cap <= 0
        or not 0 <= args.threshold_quantile <= 1
        or args.sensitivity <= 0
        or args.max_responsible_flows < 1
        or args.uid_corroboration_bonus < 0
        or args.uid_corroboration_bonus_cap < 0
        or args.multivariate_minimum_points < 3
        or args.multivariate_threshold <= 0
        or not 0 <= args.multivariate_shrinkage <= 1
        or args.multivariate_history_limit < args.multivariate_minimum_points
    ):
        print("error: invalid detector parameters", file=sys.stderr)
        return 2
    logs, skipped = discover_logs(args.zeek_dir)
    if not logs:
        print("error: no supported Zeek protocol logs found", file=sys.stderr)
        return 2
    output = Outputs(
        args.output_dir,
        args.quiet,
        color=args.color,
        show_data=not args.no_terminal_data,
    )
    detector = MultiProtocolDetector(args, output)
    output.reporter.section(
        "MULTI-PROTOCOL ANOMALY DETECTOR",
        f"input={args.zeek_dir} protocols={len(logs)} "
        f"config={args.config} sensitivity={args.sensitivity} "
        f"training_windows={args.training_hours} "
        f"window_seconds={args.window_seconds} "
        f"normal_dirs={len(args.normal_dirs)}",
    )
    output.reporter.section(
        "PROTOCOL-WINDOW DATA AND ANOMALIES",
        "Blue=window data, red=protocol anomaly, yellow=reason",
    )
    output.reporter.section(
        "TARGET-IP WINDOW DATA AND ANOMALIES",
        "Blue=window data, red=target anomaly, yellow=reason",
    )
    output.write(
        "events",
        {
            "event": "detector_start",
            "directory": str(args.zeek_dir),
            "protocols": [protocol for protocol, _ in logs],
            "skipped_non_ip_logs": skipped,
            "configuration": str(args.config),
            "training_hours": args.training_hours,
            "training_windows": args.training_hours,
            "window_seconds": args.window_seconds,
            "normal_dirs": [str(path) for path in args.normal_dirs],
            "sensitivity": args.sensitivity,
            "experimental_noop_mode": args.experimental_noop_mode,
            "experimental_mirror_mode": args.experimental_mirror_mode,
            "experimental_multivariate_mode": args.experimental_multivariate_mode,
        },
    )
    try:
        baseline_records = 0
        if args.normal_dirs:
            detector.force_training = True
            detector.suppress_output = True
            for normal_dir in args.normal_dirs:
                normal_observations, normal_logs, _ = collect_observations(
                    normal_dir, args, detector
                )
                if not normal_logs:
                    raise ValueError(
                        f"no supported Zeek protocol logs found in normal "
                        f"directory: {normal_dir}"
                    )
                baseline_records += len(normal_observations)
                process_observations(detector, normal_observations)
            detector.calibrate_baseline()
            detector.force_training = False
            detector.suppress_output = False
            detector.reset_run_counters()
            output.write(
                "events",
                {
                    "event": "external_baseline_loaded",
                    "normal_dirs": [str(path) for path in args.normal_dirs],
                    "records": baseline_records,
                },
            )
        observations, _, _ = collect_observations(
            args.zeek_dir, args, detector
        )
        process_observations(detector, observations)
        global_events = detector.ensemble()
        pipeline_context = PipelineContext(
            records_processed=sum(detector.records_by_protocol.values()),
            window_seconds=args.window_seconds,
            protocols=tuple(protocol for protocol, _ in logs),
            protocol_anomalies=len(detector.protocol_anomalies),
            target_anomalies=len(detector.target_anomalies),
            ssl_flow_alerts=len(detector.flow_anomalies),
            global_anomalies=len(global_events),
            core_detections=tuple(
                {
                    "detection_id": f'{event["host"]}@{event["hour_start"]}',
                    "host": event["host"],
                    "window_start": event["hour_start"],
                    "score": event["global_score"],
                }
                for event in global_events
            ),
            protocol_windows=tuple(detector.protocol_window_rows),
        )
        module_results = ExperimentalPipeline(
            [
                (NoOpModule(), args.experimental_noop_mode),
                (CoreMirrorModule(), args.experimental_mirror_mode),
                (
                    RobustMultivariateModule(
                        minimum_points=args.multivariate_minimum_points,
                        threshold=args.multivariate_threshold,
                        shrinkage=args.multivariate_shrinkage,
                        history_limit=args.multivariate_history_limit,
                    ),
                    args.experimental_multivariate_mode,
                ),
            ]
        ).run(pipeline_context)
        for module_result in module_results:
            output.write(
                "events",
                {"event": "experimental_module_result", **module_result.to_dict()},
            )
        summary = {
            "window_seconds": args.window_seconds,
            "training_windows": args.training_hours,
            "external_baseline_records": baseline_records,
            "records_processed": sum(detector.records_by_protocol.values()),
            "records_by_protocol": dict(sorted(detector.records_by_protocol.items())),
            "records_skipped_without_ip": dict(
                sorted(detector.skipped_no_ip.items())
            ),
            "protocol_anomalies": len(detector.protocol_anomalies),
            "target_anomalies": len(detector.target_anomalies),
            "ssl_flow_alerts": len(detector.flow_anomalies),
            "ssl_conn_matches": detector.ssl_conn_matches,
            "global_anomalies": len(global_events),
            "hosts": len({host for host, _ in detector.states}),
            "targets": len(detector.target_states),
            "pipeline": pipeline_summary(module_results),
            "protocol_anomalies_by_protocol": dict(
                sorted(
                    (
                        protocol,
                        sum(
                            event["protocol"] == protocol
                            for event in detector.protocol_anomalies
                        ),
                    )
                    for protocol in {
                        event["protocol"]
                        for event in detector.protocol_anomalies
                    }
                )
            ),
            "global_anomalies_by_host": dict(
                sorted(
                    (
                        host,
                        sum(event["host"] == host for event in global_events),
                    )
                    for host in {event["host"] for event in global_events}
                )
            ),
        }
        output.write("events", {"event": "detector_stop", **summary})
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        output.close()
        return 2
    output.close(close_reporter=False)
    output.reporter.summary(
        "GLOBAL DETECTION SUMMARY",
        [
            ("Records processed", summary["records_processed"]),
            ("Source hosts", summary["hosts"]),
            ("Target IPs", summary["targets"]),
            ("Window seconds", args.window_seconds),
            ("Training windows", args.training_hours),
            ("External baseline records", summary["external_baseline_records"]),
            ("Sensitivity", args.sensitivity),
            ("Protocol anomalies", summary["protocol_anomalies"]),
            ("Target anomalies", summary["target_anomalies"]),
            ("Independent SSL flow alerts", summary["ssl_flow_alerts"]),
            ("SSL/conn UID matches", summary["ssl_conn_matches"]),
            ("Global anomalies", summary["global_anomalies"]),
            (
                "Anomalies by protocol",
                ", ".join(
                    f"{name}={count}"
                    for name, count in summary[
                        "protocol_anomalies_by_protocol"
                    ].items()
                )
                or "none",
            ),
            (
                "Global anomalies by host",
                ", ".join(
                    f"{host}={count}"
                    for host, count in summary[
                        "global_anomalies_by_host"
                    ].items()
                )
                or "none",
            ),
            (
                "Records by protocol",
                ", ".join(
                    f"{name}={count}"
                    for name, count in summary["records_by_protocol"].items()
                ),
            ),
            (
                "Skipped without IP",
                ", ".join(
                    f"{name}={count}"
                    for name, count in summary[
                        "records_skipped_without_ip"
                    ].items()
                )
                or "none",
            ),
            ("Window data JSONL", output.paths["data"]),
            ("Target window JSONL", output.paths["target_data"]),
            ("Flow anomalies JSONL", output.paths["flow"]),
            ("Protocol anomalies JSONL", output.paths["protocol"]),
            ("Target anomalies JSONL", output.paths["target"]),
            ("Global anomalies JSONL", output.paths["global"]),
            ("Operational JSONL", output.paths["events"]),
            ("Human-readable log", output.paths["human"]),
        ],
    )
    output.reporter.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
