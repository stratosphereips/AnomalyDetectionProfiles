# Unified Zeek anomaly detector

`multi_protocol_anomaly_detector.py` is the only detector program. It analyzes
all IP-attributable Zeek protocols, performs specialized SSL flow alerting and
hourly detection, and combines protocol-hour anomalies into global per-IP
anomalies.

## Running the detector

```bash
python3 multi_protocol_anomaly_detector.py bro/ \
  --config anomaly_detector.conf \
  --sensitivity 1.0 \
  --training-hours 3
```

The input must be a Zeek log directory. The detector automatically correlates
`ssl.log` and `conn.log` by UID.

### Local web dashboard

Start the full-width configuration and results dashboard:

```bash
python3 dashboard.py --open
```

Then use `http://127.0.0.1:8765/`. The dashboard provides a local folder
browser, every detection threshold, optional debounced auto-run, summaries,
filters, colored anomaly levels, expandable explanations, responsible-flow
tables, hourly data, and the complete run log. Its timeline tab plots hourly
flow/record volume, benign-training intervals, model updates, drift,
suspicious adaptation, SSL-flow alerts, protocol-hour anomalies, and global
anomalies. SSL-flow items are explicitly labeled as alerts and supporting
evidence, not anomalies. The training-hours control shows the selected
capture's total traffic-hour span for reference.

The left-side importance controls filter low/medium/high/critical anomalies
and change ranking between composite importance, total anomaly score,
threshold excess, protocol breadth, and reason count. Flow and protocol-hour
views default to total score descending; global anomalies default to composite
importance because global scores commonly saturate at `1.0`.

Each dashboard execution uses a private configuration snapshot under
`.dashboard_runs/`; it does not modify `anomaly_detector.conf`.

## Detection levels

| Type | Meaning |
| ---- | ------- |
| `ssl-flow` | One SSL record is an alert because of a new server, new JA3S, or unusual bytes to a known server; it supports later anomaly explanation |
| `protocol-hour` | One source IP's behavior for one protocol and traffic-hour is anomalous |
| `global` | One source IP has a sufficiently strong or corroborated set of protocol-hour anomalies |

SSL is not a separate detector. It uses specialized flow features and
specialized hourly features inside the same protocol-hour pipeline and global
ensemble as DNS, HTTP, connections, files, DHCP, NTLM, SMB, and other logs.

## Output

The configured output directory contains:

- `flow_anomalies.jsonl`: individual specialized SSL flow anomalies
- `protocol_hourly_data.jsonl`: all protocol-hour feature values and z-scores
- `protocol_anomalies.jsonl`: anomalous protocol-hours
- `global_anomalies.jsonl`: global per-IP ensemble anomalies
- `multi_protocol_detector.log.jsonl`: complete machine-readable event log
- `multi_protocol_detector.log`: separated human-readable report

Every anomaly includes `responsible_flow_count` and `responsible_flows` with
the source log, timestamp, UID/FUID, endpoints, relevant fields, and matched
reasons. `max_responsible_flows` controls representative-flow truncation.

Terminal output uses blue for data, red for flow/protocol anomalies, magenta
for global anomalies, and yellow for reasons. Use `--no-terminal-data`,
`--quiet`, or `--color auto|always|never` to control presentation.

## Configuration and equations

All model and output settings are in
[`anomaly_detector.conf`](anomaly_detector.conf). Command-line
`--sensitivity` and `--training-hours` override their `[common]` values.

See:

- [Multi-protocol design and ensemble](MULTI_PROTOCOL_ANOMALY_DETECTION.md)
- [Exact values and equations](COMPUTATION_REFERENCE.md)
