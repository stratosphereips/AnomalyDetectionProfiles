# Multi-protocol Zeek anomaly detection and global IP ensemble

## Running it

```bash
python3 multi_protocol_anomaly_detector.py bro/ \
  --config anomaly_detector.conf \
  --sensitivity 1.0 \
  --training-hours 3
```

The program requires Python 3.9 or newer and has no third-party dependencies.
Use `--help` to change training duration, anomaly thresholds, adaptation rates,
or ensemble policy.

## Configuration and sensitivity

All operating values are stored in
[`anomaly_detector.conf`](anomaly_detector.conf):

- `[common]` contains default sensitivity and benign training hours;
- `[common]` also controls whether multicast and broadcast traffic is ignored;
- `[output]` controls terminal presentation;
- `[multi_protocol]` configures every protocol model, the specialized SSL
  flow path, and the global ensemble.

Select a configuration with `--config PATH`. Command-line
`--sensitivity` and `--training-hours` override `[common]`; this makes those
two experiment variables easy to sweep without editing a file.

Sensitivity is positive, with `1.0` preserving configured thresholds:

```text
effective feature threshold = configured threshold / sensitivity
effective global threshold  = configured global threshold / sensitivity
required protocols          = ceil(configured minimum / sensitivity)
```

Thus values above `1.0` produce more anomalies and values below `1.0` produce
fewer. Sensitivity affects both per-protocol decisions and final global-IP
decisions. Training hours are traffic-time buckets observed for each
IP/protocol model, not wall-clock time.

For the complete equations and exact meanings of `value`, `mean`, `zscore`,
protocol score, normalized contribution, global score, confidence, and EWMA
adaptation, see the
[anomaly detection computation reference](COMPUTATION_REFERENCE.md).

## Scope

The detector processes every IP-attributable network log present in the Zeek
folder:

`analyzer`, `conn`, `dce_rpc`, `dhcp`, `dns`, `files`, `http`, `known_hosts`,
`known_services`, `notice`, `ntlm`, `smb_mapping`, `software`, `ssl`, and
`weird`.

The following logs are intentionally excluded from per-IP detection:

- `capture_loss`, `packet_filter`, and `stats` describe the sensor;
- `loaded_scripts` is static configuration and has no traffic timestamp;
- `ocsp` and `x509` contain certificate records without endpoint IPs.

These exclusions prevent sensor health or certificate metadata from being
incorrectly attributed to a client IP.

There is one detector and one SSL model path. SSL records receive the common
protocol-hour features plus specialized server, JA3/JA3S, and correlated byte
features. Individual SSL-flow anomalies and SSL protocol-hour anomalies share
the same training state and feed the same global ensemble.

## Per-protocol detection

Records are sorted by traffic timestamp and grouped by source IP, protocol, and
traffic hour. The first three observed hours for each IP/protocol pair are
assumed benign by default.

Non-SSL protocols produce a common behavioral core:

- `flow_count`: Zeek flows/records for that source IP and protocol in the
  traffic-hour;
- unique and previously unseen destination IPs;
- failure ratio.

Protocol-aware features are then added. Examples include DNS queries, response
codes and RTT; HTTP hosts, methods, status codes and body sizes; connection
states, ports, duration and bytes; file MIME types, hashes, missing bytes and
sizes; TLS server names, versions, ciphers and fingerprints; NTLM identities
and failures; and SMB shares.

SSL uses the specialized names `ssl_flows`, `unique_servers`, `new_servers`,
`ja3_changes` and `known_server_avg_bytes`, plus TLS
version, cipher, JA3, JA3S, validation-status diversity, and failure ratio.
Equivalent generic SSL counts are omitted to avoid double-counting the same
behavior in its protocol anomaly score.

Individual `ssl-flow` items are independent alerts. They are not counted as an
hourly feature and cannot create or amplify a `protocol-hour` anomaly.

Training uses Welford online moments. Heavy-tailed values are transformed with
`log1p`. Detection uses median/MAD robust z-scores with a learned noise floor.
After training, small deviations update the baseline with an EWMA alpha of
`0.05`; suspicious periods use `0.005` to reduce baseline poisoning.

Only host-hours present in a protocol log are modeled. Missing events are not
invented as zero-valued traffic because a missing Zeek log may mean disabled
logging rather than genuine absence.

## Global per-IP ensemble

Protocol anomalies are grouped by source IP and traffic hour. Each protocol
gets at most one vote:

```text
protocol contribution = min(protocol anomaly score, 10) / 10
global score = min(1, sum(contributions) + corroboration bonus)
```

The corroboration bonus is `0.15` for every additional anomalous protocol,
capped at `0.30`. A global anomaly is emitted when its score reaches `0.65` or
at least two independent protocols agree.

Per-protocol score capping is important: high-volume DNS or connection logs
cannot drown out a lower-volume but independent NTLM, SMB, HTTP, or notice
signal. The output retains every contribution and underlying feature reason,
so the ensemble remains auditable.

## 🔎 Flow attribution

Every protocol and global anomaly identifies the Zeek records behind it.
`responsible_flow_count` gives the complete matching count, while
`responsible_flows` provides a configurable representative subset containing
the source log, timestamp, UID/FUID, endpoints, relevant protocol fields, and
the anomaly features matched by each record.

Attribution is feature-aware: new-value reasons select flows carrying the new
value, failures select failed flows, numeric anomalies rank flows in the
anomalous direction, and unique-value anomalies select representative distinct
values. The subset is balanced across reasons and limited by
`max_responsible_flows`.

Global anomalies retain the responsible flows of every contributing protocol.
The [computation reference](COMPUTATION_REFERENCE.md#responsible-flow-attribution)
defines selection and explains lower-than-baseline anomalies where missing
expected flows cannot have a UID.

## Output

The default `multi_protocol_ad_output` directory contains JSON Lines files:

- `protocol_hourly_data.jsonl`: all feature vectors and z-scores;
- `flow_anomalies.jsonl`: specialized individual SSL-flow anomalies;
- `protocol_anomalies.jsonl`: detailed per-protocol anomalies;
- `global_anomalies.jsonl`: global per-IP ensemble results;
- `multi_protocol_detector.log.jsonl`: start, model-update, data, anomaly, and
  completion events.
- `multi_protocol_detector.log`: plain human-readable sections, anomaly
  reasons, protocol contributions, and the final summary.

Hourly data, protocol anomalies, and global anomalies also appear in the
terminal. Blue identifies data, red protocol anomalies, magenta global
anomalies, yellow reasons/contributions, and green/yellow summary rows. Colors
are enabled automatically on a TTY and can be controlled with `--color`.
Pass `--no-terminal-data` to hide data rows or `--quiet` to print only the
final summary.

Each invocation replaces files in the selected output directory.
