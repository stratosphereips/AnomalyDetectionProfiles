# Unified Zeek anomaly detector

<img width="1412" height="762" alt="image" src="https://github.com/user-attachments/assets/6588e94b-9303-4aa7-a676-ad84041f27ef" />

### Run using the local web dashboard

Start the full-width configuration and results dashboard:

```bash
python3 dashboard.py --open
```

Then use `http://127.0.0.1:8765/`. The dashboard provides a local folder
browser that starts in the directory from which the dashboard was launched,
every detection threshold, optional debounced auto-run, summaries,
filters, colored anomaly levels, expandable explanations, responsible-flow
tables, window data, and the complete run log. Its timeline tab plots windowed
flow/record volume, benign-training intervals, model updates, drift,
suspicious adaptation, SSL-flow alerts, protocol-window anomalies, and global
anomalies. SSL-flow items are explicitly labeled as alerts and supporting
evidence, not anomalies. Change **Window size (seconds)** and press **Run
analysis** to recompute everything. When **Auto-run** is enabled, changing the
window or any other model parameter starts a new run after 700 ms.

The left-side importance controls filter low/medium/high/critical anomalies
and change ranking between composite importance, total anomaly score,
threshold excess, protocol breadth, and reason count. Flow and protocol-window
views default to total score descending; global anomalies default to composite
importance because global scores commonly saturate at `1.0`.

Each dashboard execution uses a private configuration snapshot under
`.dashboard_runs/`; it does not modify `anomaly_detector.conf`.

# Direct detection run without dashboard
`multi_protocol_anomaly_detector.py` is the only detector program. It analyzes
all IP-attributable Zeek protocols, performs specialized SSL flow alerting and
windowed detection, and combines protocol-window anomalies into global per-IP
anomalies.

## Running the detector

```bash
python3 multi_protocol_anomaly_detector.py /path/to/zeek-logs \
  --config anomaly_detector.conf \
  --normal-dir /path/to/known-normal-zeek-logs \
  --window-seconds 300 \
  --sensitivity 1.0 \
  --training-hours 3
```

The input must be a directory containing at least one supported Zeek protocol
log. TLS is optional; when both `ssl.log` and `conn.log` are available, the
detector automatically correlates them by UID.

Every supported log is optional except that at least one supported log must be
present. A folder with `conn.log`, `dns.log`, or `ssh.log` but no `ssl.log`
still runs normally; only TLS-specific features are absent. Supported inputs
include `conn`, `dns`, `http`, `files`, `ssh`, `ssl`, DHCP, NTLM, SMB, notice,
weird, and the other IP-attributable logs documented below.

## Training and zero-training mode

Training is independent for each source-IP/protocol model and counts observed
windows, not elapsed wall-clock intervals. `window_seconds` controls their
size and defaults to `3600`; for example, `300` selects five-minute windows.
With `training_hours = N`
where `N > 0`, the first `N` observed buckets are assumed benign and fitted
with Welford moments. Statistical alerts additionally require
`minimum_points` prior observations, so the earliest eligible bucket is
`max(training_hours, minimum_points) + 1` for that model.

Setting `training_hours = 0` skips the explicit assume-benign phase; it does
not provide immediate statistical detection from an empty model. The first
`minimum_points` buckets have z-score zero and seed the baseline through
normal EWMA adaptation. The next bucket is the first that can produce a
statistical protocol-window or target-window anomaly. Because there are no benign
training values, empirical threshold calibration is unavailable and the
configured fallback thresholds are used. If SSL exists, zero training can
still produce immediate `new_server` or `new_ja3s` flow alerts; these alerts
do not enter the global ensemble.

For example, `training_hours = 0` and `minimum_points = 8` makes the ninth
observed bucket for an IP/protocol pair the first statistically eligible one.
Use zero only when no trusted benign prefix exists; early traffic necessarily
influences the adaptive baseline.

`training_hours` is retained as a configuration key for compatibility, but it
counts observed windows when `window_seconds` differs from `3600`. For a
one-hour capture, `window_seconds = 300`, `training_hours = 3`, and
`minimum_points = 3` provide at most twelve windows per continuously active
IP/protocol model, with the fourth active window first eligible for scoring.
Sparse models may have fewer observations because empty windows are not
invented.

For a trusted baseline that is separate from the analyzed capture, set
`normal_dirs` to comma-separated Zeek folders in the configuration/dashboard,
or repeat `--normal-dir`. Their windows are fitted first, produce no alerts,
and do not enter analyzed-run counts. External baseline traffic must use the
same window size and should contain the same source or target IP identities as
the traffic being compared; an unseen IP/protocol model still follows the
ordinary training or cold-start behavior.



## Detection levels

| Type | Meaning |
| ---- | ------- |
| `ssl-flow` | One SSL record is an alert because of a new server, new JA3S, or unusual bytes to a known server; it supports later anomaly explanation |
| `protocol-hour` | Legacy event name for one source IP's anomalous protocol window |
| `global` | One source IP has a sufficiently strong or corroborated set of protocol-window anomalies |

SSL is not a separate detector. It uses specialized flow features and
specialized window features inside the same protocol-window pipeline and global
ensemble as DNS, HTTP, connections, files, DHCP, NTLM, SMB, and other logs.
Connection windows additionally model scan shape and transfer rates; DNS
windows model lexical/DGA-like behavior while excluding common local and
service-discovery traffic; SSH models client/server identity, authentication
success, and attempts; and HTTP records are enriched with exact FUID-linked
file metadata when `files.log` is available.

## Output

The configured output directory contains:

- `flow_anomalies.jsonl`: individual specialized SSL flow anomalies
- `protocol_hourly_data.jsonl`: all protocol-window feature values and z-scores; filename retained for compatibility
- `protocol_anomalies.jsonl`: anomalous protocol windows
- `global_anomalies.jsonl`: global per-IP ensemble anomalies
- `multi_protocol_detector.log.jsonl`: complete machine-readable event log
- `multi_protocol_detector.log`: separated human-readable report

Every anomaly includes `responsible_flow_count` and `responsible_flows` with
the source log, timestamp, UID/FUID, endpoints, relevant fields, and matched
reasons. `max_responsible_flows` controls representative-flow truncation.
Anomaly objects also expose `responsible_uids` and `responsible_fuids`. When
the same responsible UID occurs in multiple anomalous components in one
window, the global event records `shared_uids` and applies the configurable,
capped exact-UID corroboration bonus.

Terminal output uses blue for data, red for flow/protocol anomalies, magenta
for global anomalies, and yellow for reasons. Use `--no-terminal-data`,
`--quiet`, or `--color auto|always|never` to control presentation.

## Configuration and equations

All model and output settings are in
[`anomaly_detector.conf`](anomaly_detector.conf). Command-line
`--sensitivity` and `--training-hours` override their `[common]` values.

See:

- [Interactive guide: how the complete detector works](docs/index.html)
- [Multi-protocol design and ensemble](MULTI_PROTOCOL_ANOMALY_DETECTION.md)
- [Exact values and equations](COMPUTATION_REFERENCE.md)
