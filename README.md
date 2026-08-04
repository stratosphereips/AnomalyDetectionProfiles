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

The **Experimental pipeline** control has three modes. **Off** does not run the
module. **Shadow** runs it and records its result but guarantees a zero
contribution to detection. **Active** permits a module contribution. The first
module is intentionally a no-op pipeline check, so it contributes zero even in
Active mode. The adaptive statistical detector remains the locked core in all
three modes. The pipeline status cards on the main page show the mode, module
health, and whether it affected detection for the completed run.

The **Core mirror comparison check** is enabled in Shadow mode by default. It
copies the locked core's final global decision IDs and scores without adding a
second vote. Open **Pipeline comparison** to verify the comparison machinery:
the mirror should show 100% decision agreement and a mean absolute score
difference of zero. A future detector can use the same table to show overlap,
core-only decisions, module-only decisions, and score differences. The core is
a reference in this display, not assumed ground truth.

Six independent optional detectors are available after the statistical core:
robust multivariate relationships, PCA reconstruction, Isolation Forest,
empirical rarity/novelty, rolling time-series change, and communication-graph
behavior. The first five analyze source-IP/protocol streams and destination-IP
streams; the graph detector analyzes each source IP's contacted destinations
across all protocols.

Every real detector can be **Off**, **Shadow**, or **Active** from the dashboard.
Shadow computes candidates with zero official effect. Active may add a
module-only candidate to the official anomaly set or annotate a matching core
anomaly. Active modules never remove, lower, or replace core anomalies. All
methods are local pure-Python implementations: no model download or external
API is required.

The left-side importance controls filter low/medium/high/critical anomalies
and change ranking between composite importance, total anomaly score,
threshold excess, protocol breadth, and reason count. Flow and protocol-window
views default to total score descending; global anomalies default to composite
importance because global scores commonly saturate at `1.0`.

The application directory may be read-only. Runtime configuration snapshots,
detector output, and dashboard-saved settings are stored by default under
`/tmp/anomaly-detection-profiles-dashboard-<uid>/`; the packaged
`anomaly_detector.conf` is never modified. Set
`ANOMALY_DASHBOARD_STATE_DIR=/writable/path` before starting the dashboard to
choose a persistent writable location.

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
  --training-windows 6
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

`training_windows = N` defines one capture-wide assume-benign interval. Its
duration follows the configured aggregation-window size:

```text
capture_start = timestamp of the first analyzed record
training_end = capture_start + N * window_seconds
training traffic: capture_start <= timestamp < training_end
```

All and only records in that elapsed-time interval may produce trusted Welford
training values. The interval is shared by every source-IP/protocol model and
every destination-IP model. It is not restarted when a protocol first appears.
For example, `training_windows = 6` and `window_seconds = 600` select exactly
the first 60 minutes. If the capture starts at 09:00, records from 09:00 up to
but not including 10:00 may train. Selected-capture windows are anchored at
the first record, so this produces exactly six consecutive training windows.
SSH first seen at 11:00 starts directly in detection mode with an empty model.
Window seven begins at the cutoff, so post-training traffic cannot enter a
training value.

Setting `training_windows = 0` skips the explicit assume-benign phase; it does
not provide immediate statistical detection from an empty model. The first
`minimum_points` observed windows for a new model have z-score zero and seed
the baseline through normal EWMA adaptation. The next observed window is the
first that can produce a statistical source-IP/protocol/window or
destination-IP/window anomaly. Because there are no benign
training values, empirical threshold calibration is unavailable and the
configured fallback thresholds are used. If SSL exists, zero training can
still produce immediate `new_server` or `new_ja3s` flow alerts; these alerts
do not enter the global ensemble.

For example, `training_windows = 0` and `minimum_points = 8` makes the ninth
observed window for an IP/protocol pair the first statistically eligible one.
Use zero only when no trusted benign prefix exists; early traffic necessarily
influences the adaptive baseline.

After the global training cutoff, any model with fewer than `minimum_points`
prior values remains statistically ineligible until it accumulates enough
detection-phase observations. These observations use EWMA adaptation; they do
not become trusted training values and do not enter empirical threshold
calibration.

For a trusted baseline that is separate from the analyzed capture, set
`normal_dirs` to comma-separated Zeek folders in the configuration/dashboard,
or repeat `--normal-dir`. Their windows are fitted first, produce no alerts,
and do not enter analyzed-run counts. The selected capture's global initial
training interval is then applied as configured. External baseline traffic
should contain the same source or destination IP identities as the traffic
being compared; a model unseen in both trusted sources follows detection-phase
cold start.



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

Every experimental module returns the same structured fields: module ID,
label, mode, health status, eligibility, score, candidate contribution,
effective contribution, detection-effect flag, reasons, top features, and
responsible UID/FUID lists. Candidate decisions also include a stable
`source-IP@window-start` identity so same-run model outputs can be compared.
One module failure is converted into an error
result and does not stop the locked statistical detector. Module results are
written as `experimental_module_result` entries in the operational JSONL.

Terminal output uses blue for data, red for flow/protocol anomalies, magenta
for global anomalies, and yellow for reasons. Use `--no-terminal-data`,
`--quiet`, or `--color auto|always|never` to control presentation.

## Configuration and equations

All model and output settings are in
[`anomaly_detector.conf`](anomaly_detector.conf). Command-line
`--sensitivity` and `--training-windows` override their `[common]` values.

See:

- [Interactive guide: how the complete detector works](docs/index.html)
- [Multi-protocol design and ensemble](MULTI_PROTOCOL_ANOMALY_DETECTION.md)
- [Exact values and equations](COMPUTATION_REFERENCE.md)
