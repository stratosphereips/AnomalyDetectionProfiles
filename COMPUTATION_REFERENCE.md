# Anomaly detection computation reference

_Exact equations and value definitions implemented by the unified multi-protocol detector._

---

## 🔄 Computation pipeline

```mermaid
flowchart LR
    accTitle: Anomaly Score Computation Pipeline
    accDescr: Zeek records become host-window feature values, transformed model inputs, robust z-scores, protocol anomalies, and finally global per-IP ensemble anomalies

    records[📥 Read Zeek records] --> group[🗂️ Group by IP protocol window]
    group --> value[📊 Compute raw value]
    value --> transform[⚙️ Apply log1p]
    transform --> score[🔍 Compute robust z-score]
    score --> decision{Threshold crossed?}
    decision -->|No| adapt[🔄 Update baseline]
    decision -->|Yes| anomaly[⚠️ Emit anomaly]
    anomaly --> adapt
    anomaly --> ensemble[🧠 Combine protocol votes]
    ensemble --> global_check{Global threshold crossed?}
    global_check -->|Yes| output[📤 Emit global IP anomaly]

    classDef process fill:#dbeafe,stroke:#2563eb,stroke-width:2px,color:#1e3a5f
    classDef decision fill:#fef9c3,stroke:#ca8a04,stroke-width:2px,color:#713f12
    classDef warning fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#7f1d1d

    class records,group,value,transform,score,adapt,ensemble process
    class decision,global_check decision
    class anomaly,output warning
```

The current observation is always scored against the baseline that existed
before that observation. Only after scoring and anomaly emission does the
detector update the model.

## 📐 Symbols and transformations

| Symbol | Meaning |
| ------ | ------- |
| \(x\) | Raw feature value written as `value` |
| \(y\) | Transformed model value |
| \(n\) | Number of fitted observations in one feature model |
| \(\mu\) | Model mean in transformed space |
| \(s^2\) | Model variance in transformed space |
| \(m\) | Median of retained transformed values |
| \(\operatorname{MAD}\) | Median absolute deviation from \(m\) |
| \(f\) | Adaptive minimum standard-deviation floor |
| \(z\) | Absolute standardized deviation reported as `zscore` |
| \(T\) | Configured or empirically calibrated base threshold |
| \(S\) | Global sensitivity supplied by `--sensitivity` |
| \(\alpha\) | EWMA adaptation rate |

### What are `x` and `y`?

`x` is the actual value measured from the Zeek logs. Examples are:

- `x = 12000` for a flow containing 12,000 bytes
- `x = 35` for 35 DNS requests in one configured window
- `x = 0.20` for a 20% failure ratio

This raw value is also the `value` shown in anomaly output.

`y` is the smaller number used internally by the statistical model. The
detector converts `x` to `y` with:

$$
y = \ln(1 + \max(0,x)).
$$

In plain language:

- negative values are replaced with zero as a defensive check;
- one is added so a zero value remains valid;
- the natural logarithm, `ln`, compresses the range.

For example:

| Raw value `x` | Internal value `y = ln(1+x)` |
| ------------: | ----------------------------: |
| `0` | `0.00` |
| `100` bytes | `4.62` |
| `1,000` bytes | `6.91` |
| `10,000` bytes | `9.21` |
| `1,000,000` bytes | `13.82` |

### Why use `ln`?

Network measurements often cover very different scales. Most flows may
contain thousands of bytes while a few contain millions. Without compression,
one very large flow can dominate the mean and variance and make the baseline
unstable.

The logarithm reduces this effect. It also makes multiplicative changes easier
to compare: increasing from 100 to 1,000 bytes has roughly the same internal
difference as increasing from 1,000 to 10,000 bytes. Both are tenfold
increases.

The current implementation applies this same transformation consistently to
all non-negative modeled values, including counts, durations, averages, and
ratios.

### Why perform an inverse transformation?

The model's mean is learned in the compressed `y` scale. Reporting a statement
such as `mean=8.0` would not be useful to someone examining a Zeek log because
the log contains bytes, seconds, counts, and ratios—not logarithms.

The detector converts the internal mean back to the original unit:

$$
\text{reported mean} = e^{\text{internal mean}} - 1.
$$

For example, an internal mean of `8.0` is reported as approximately `2,980`
bytes:

$$
e^8 - 1 \approx 2980.
$$

This conversion is only for understandable output. It does not change the
anomaly decision. Because the model averages logarithms, the reported mean is
a typical multiplicative scale and may differ from the ordinary arithmetic
average of the raw values.

## 🎓 Benign training

`--training-windows N` defines one capture-wide assume-benign interval. Let
\(t_0\) be the timestamp of the first analyzed record and \(W\) be
`window_seconds`:

$$
t_{\mathrm{end}} = t_0 + NW.
$$

A selected-capture record is eligible for trusted training exactly when:

$$
t_0 \le t < t_{\mathrm{end}}.
$$

- The same \([t_0,t_{\mathrm{end}})\) interval applies to every source IP,
  protocol, specialized SSL path, and destination IP.
- The interval is based on elapsed capture time, not the number of observed
  windows for an individual model.
- Selected-capture windows are anchored at \(t_0\), so the first \(N\)
  consecutive intervals end exactly at \(t_{\mathrm{end}}\).
- A model first appearing at or after \(t_{\mathrm{end}}\) receives no trusted
  training values.
- Records inside the interval are aggregated into window feature values and
  fitted with Welford's method; no anomaly is emitted for them.
- Detection begins with window \(N+1\), whose start is
  \(t_{\mathrm{end}}\), so post-cutoff records cannot enter training.
- Empty windows are not inserted as zero-valued observations.

After the cutoff, a model with fewer than `minimum_points` prior values returns
z-score zero until it accumulates enough detection-phase EWMA observations.
Those observations are not trusted training values and do not enter empirical
threshold calibration. Eligibility does not guarantee an anomaly; the z-score
must still reach its effective threshold.

### Zero training windows

`training_windows = 0` skips the explicit assume-benign branch. From the first
window, output records use `phase = "detection"`, and `trained_windows` remains
zero. This does not eliminate the need for a baseline. While model count is
below `minimum_points`, `robust_zscore` returns zero, no statistical reason is
emitted, and the observation updates the model with the ordinary
post-detection EWMA rule. The first observation initializes the mean and count;
subsequent observations use `drift_alpha` while the anomaly score remains zero.

Because the Welford training branch is never entered, `training_values` stays
empty and empirical quantile calibration is not performed. Feature decisions
therefore use the configured fallback threshold. For example, with
`training_windows = 0` and `minimum_points = 8`, windows one through eight seed
the adaptive baseline with z-score zero, and window nine is the first eligible
for a statistical anomaly.

Specialized SSL novelty does not use `minimum_points`. With zero training, the
first SSL flow to a previously unseen server or with a previously unseen JA3S
may immediately produce an `ssl-flow` alert when its novelty gate is met. This
is a flow alert, not a protocol-window anomaly, and it does not contribute to the
global ensemble. SSL byte-volume alerts still require `minimum_points` prior
byte observations for the same known server.

Zero training is thus an adaptive cold start, not baseline-free anomaly
detection. It is appropriate only when no trusted benign prefix is available;
the earliest observations necessarily influence the baseline.

When `normal_dirs` or `--normal-dir` is set, all supported windows from those
folders pass through the Welford training branch before the analyzed folder.
They emit no data or anomaly events. The detector then calibrates every fitted
model, retains its per-IP/protocol state, clears run counters, and processes the
selected folder. External observations count as prior model points but not as
analyzed records. A model absent from external input starts with the configured
training or cold-start behavior.

### Why Welford is used

Each feature model needs a center and a measure of variation. The mean provides
the center; the sample variance records how widely trusted values normally
move around that center. A later distance from the mean is meaningful only
relative to that normal variation.

Welford produces the ordinary sample mean and variance incrementally as each
trusted window arrives. A two-pass calculation would collect the values and
scan them again. The simple one-pass identity
\(E[y^2]-E[y]^2\) can lose numerical precision because it subtracts two large,
nearly equal quantities. Welford avoids that unstable subtraction and does not
need to recompute the statistics from the full history after every window.

Welford is a baseline estimator, not an anomaly decision. Its mean and
variance support early z-score calculations; later robust scoring uses the
stored median and MAD. Training values are also retained separately for
empirical threshold calibration.

For each transformed trusted value \(y_n\), Welford updates:

$$
n \leftarrow n + 1,
$$

$$
\delta = y_n - \mu_{n-1},
$$

$$
\mu_n = \mu_{n-1} + \frac{\delta}{n},
$$

$$
M_{2,n} = M_{2,n-1} + \delta(y_n-\mu_n),
$$

$$
s_n^2 = \frac{M_{2,n}}{\max(1,n-1)}.
$$

`M2` accumulates squared deviations. Once two values exist, `n - 1` makes
this the sample variance. Trusted training values receive equal weight. After
training, observations are not assumed benign, so the detector uses EWMA
instead: ordinary changes update at `drift_alpha`, while strong anomalies use
the much smaller `suspicious_alpha` to limit baseline contamination.

## 📏 Adaptive noise floor

The noise floor is the smallest normal variation that a feature model allows
in the denominator of its z-score. Each feature model stores its own floor
\(f\), initially `0.1` in transformed space:

$$
\text{variation used by z-score}
= \max(\text{measured variation}, f).
$$

It is needed because identical historical values have zero measured
variation, which would cause division by zero. Even a very small measured
variation can turn a harmless difference into a huge z-score. The floor keeps
the denominator above a realistic minimum. It is not an anomaly threshold and
is not a minimum number of packets or bytes.

The minimum adapts because different feature models can have different levels
of recurring small prediction error. Before a value updates the model, its
absolute residual is:


$$
r = |y-\mu|.
$$

The latest 64 residuals are retained. Once at least five exist:

$$
q_{10} = Q_{0.10}(r),
$$

$$
m_r = \operatorname{median}(r),
$$

$$
\operatorname{MAD}_r =
  \operatorname{median}(|r_i-m_r|),
$$

$$
f_{\mathrm{candidate}} =
  \max(0.01,q_{10},1.4826\operatorname{MAD}_r),
$$

$$
f \leftarrow 0.95f + 0.05f_{\mathrm{candidate}}.
$$

The factor `1.4826` scales MAD to a standard-deviation-like unit. It is part
of the algorithm and does not require network traffic to be normally
distributed.

## 🔍 Z-score computation

`zscore` means: how far is the current transformed value from its recent
baseline, measured in robust baseline standard deviations?

If the model has fewer than `minimum_points`, the implementation returns:

$$
z = 0.
$$

### Fewer than seven retained values

The detector uses online mean and variance:

$$
\sigma = \sqrt{\max(s^2,f^2)},
$$

$$
z = \frac{|y-\mu|}{\sigma}.
$$

### Seven or more retained values

The detector uses the latest 256 transformed values:

$$
m = \operatorname{median}(y_1,\ldots,y_k),
$$

$$
\operatorname{MAD} =
  \operatorname{median}(|y_i-m|),
$$

$$
\sigma_{\mathrm{robust}} =
  \max(1.4826\operatorname{MAD},f),
$$

$$
z = \frac{|y-m|}{\sigma_{\mathrm{robust}}}.
$$

The absolute value makes detection two-sided: an unusual increase or decrease
can be anomalous.

### Worked z-score example

Assume a bytes feature has transformed median `8.0`, MAD `0.20`, and floor
`0.10`. A new raw value is `10,000` bytes:

$$
y = \ln(1+10000) \approx 9.2104,
$$

$$
\sigma_{\mathrm{robust}}
  = \max(1.4826 \times 0.20,0.10)
  = 0.29652,
$$

$$
z = \frac{|9.2104-8.0|}{0.29652} \approx 4.082.
$$

With base threshold `3.5` and sensitivity `1.0`, this is anomalous. At
sensitivity `0.5`, the effective threshold is `7.0`, so it is not anomalous.

## 🎯 Threshold calibration and sensitivity

Every model starts with its configured threshold. With at least ten benign
training values, it calibrates an empirical threshold. For benign median
\(m_b\) and robust scale \(\sigma_b\):

$$
z_{b,i} = \frac{|y_i-m_b|}{\sigma_b}.
$$

At configured quantile \(q\), normally `0.995`:

$$
T_{\mathrm{empirical}} =
  \min(15,\max(1.5,Q_q(z_b))).
$$

With fewer than ten benign values, the configured fallback is used. The
empirical threshold is bounded to `[1.5, 15]`.

Sensitivity modifies every statistical anomaly boundary:

$$
T_{\mathrm{effective}} = \frac{T}{S}, \qquad S>0.
$$

| Sensitivity | Effect |
| ----------: | ------ |
| `0.5` | Doubles thresholds; fewer anomalies |
| `1.0` | Leaves thresholds unchanged |
| `2.0` | Halves thresholds; more anomalies |

The statistical decision is:

$$
\text{anomaly} \iff z \ge T_{\mathrm{effective}}.
$$

## 🔐 Specialized SSL values

### Flow-level values

| Feature | Raw `value` | Baseline and decision |
| ------- | ----------- | --------------------- |
| `new_server` | SNI, otherwise destination IP | Novelty against all servers previously seen for the source IP |
| `new_ja3s` | JA3S string | Novelty against all JA3S values previously seen for the source IP |
| `bytes_to_known_server` | `orig_bytes + resp_bytes` from UID-matched `conn.log` | Separate transformed byte model for each source IP and server |

`new_server` and `new_ja3s` receive an implicit novelty evidence value of
`2.0`. Their gate is:

$$
T_{\mathrm{novelty,effective}} =
  \frac{T_{\mathrm{novelty}}}{S},
$$

$$
\text{novelty anomaly} \iff
  2.0 \ge T_{\mathrm{novelty,effective}}.
$$

The default novelty threshold is `1.5`. At sensitivity `1.0`, novelty emits.
At sensitivity `0.5`, its effective threshold is `3.0`, so novelty alone does
not emit.

Bytes are scored only when the server is already known and its byte model has
at least `minimum_points`. The first flow to a server can establish its byte
baseline, but is excluded from `known_server_avg_bytes` for that window.

### SSL window values

| Feature | Exact raw value \(x\) |
| ------- | --------------------- |
| `ssl_flows` | Number of SSL records from the source IP in the window |
| `unique_servers` | Number of distinct SNI values, falling back to destination IP |
| `new_servers` | Number of servers never previously observed for the source IP |
| `ja3_changes` | Count of first-seen JA3 values for their server |
| `known_server_avg_bytes` | Bytes for flows to already-known servers divided by their flow count; `0` when none exist |

Each feature has an independent adaptive model. One window anomaly may contain
multiple reasons and z-scores.

### SSL anomaly confidence

Confidence is descriptive metadata; it does not decide emission. Novelty
reasons without a z-score use an internal reason score of `2.0`.

Let \(z_{\max}\) be the largest reason score:

$$
\mathrm{severity} = 1-e^{-z_{\max}/3}.
$$

The current anomaly is inserted into history before confidence is computed.
If \(a_3\) is the number of anomalies in the preceding three elapsed hours,
including the current anomaly:

$$
\mathrm{persistence} = \min(1,a_3/3).
$$

For configured `minimum_points` \(p\):

$$
n_{\mathrm{stable}} = \max(10,3p),
$$

$$
\mathrm{baselineQuality} =
  \min(1,n_{\mathrm{baseline}}/n_{\mathrm{stable}}).
$$

Flow confidence uses the larger of the host-window count and relevant
server-byte count. Window confidence uses the minimum count across window
feature models.

For \(R\) anomaly reasons:

$$
\mathrm{multiSignal} = \min(1,R/3).
$$

The final confidence score is:

$$
C = \min\left(
1,\,
0.45\,\mathrm{severity}
+0.25\,\mathrm{persistence}
+0.20\,\mathrm{baselineQuality}
+0.10\,\mathrm{multiSignal}
\right).
$$

| Confidence | Condition |
| ---------- | --------- |
| `low` | \(C < 0.55\) |
| `medium` | \(0.55 \le C < 0.80\) |
| `high` | \(C \ge 0.80\) |

### SSL window anomaly score

If a window feature crosses its threshold, its z-score becomes a reason:

$$
A_{\mathrm{window}} =
  \sum_{j \in \mathrm{anomalous\ features}} z_j.
$$

`anomaly_score` measures total standardized deviation. `confidence.score`
instead combines severity, persistence, baseline maturity, and signal count.

## 🌐 Multi-protocol values

Every non-SSL source-IP/protocol/window has four common raw features.

| Feature | Exact raw value \(x\) |
| ------- | --------------------- |
| `flow_count` | Number of Zeek flows/records for one source IP and one protocol in the configured window |
| `unique_peers` | Number of distinct destination IPs |
| `new_peers` | Destination IPs never seen for this source-IP/protocol pair |
| `failure_ratio` | Records matching the failure rule divided by `max(1, flow_count)` |

SSL instead uses the specialized window values in the previous section,
`failure_ratio`, and the `unique_F`/`new_F` features for TLS version, cipher,
JA3, JA3S, and validation status. Generic `flow_count`, peer counts, and
server-name counts are not also added for SSL because they would duplicate
`ssl_flows`, `unique_servers`, and `new_servers`.

For each configured categorical field `F`:

$$
\mathrm{unique\_F} =
  |\{\text{distinct non-empty F values this window}\}|,
$$

$$
\mathrm{new\_F} =
  |\{\text{F values never previously seen by this model}\}|.
$$

For each configured numeric field `N`:

$$
\mathrm{total\_N} = \sum_i N_i,
$$

$$
\mathrm{avg\_N} =
  \frac{\sum_i N_i}{\max(1,\text{number of non-empty N values})}.
$$

### Protocol-specific fields

Connection-derived features include destination-port fan-out, ratios of failed
scan states, scan-like histories, short connections, zero payload, missing
services and established sessions, plus packet totals and transfer rates.
DNS-derived values include first-label length and Shannon entropy, DGA-like and
repeated-pattern counts, TLD diversity, and answer/rejection ratios. The
DGA-like predicate requires a first label of at least eight characters,
entropy of at least `2.8`, unique-character ratio of at least `0.55`, and
either vowel ratio at most `0.45` or digit ratio at least `0.10`; mDNS,
`.local`, reverse DNS, and service discovery are excluded.

HTTP adds URI diversity and lengths plus exact-FUID-linked file counts, bytes,
and MIME diversity. Files add the absolute total-versus-seen byte gap. SSH adds
maximum authentication attempts. These values are adaptive window features;
none is a fixed standalone alert threshold.

| Protocol | Categorical fields | Numeric fields | Failure condition |
| -------- | ------------------ | -------------- | ----------------- |
| `conn` | Destination port, service, state | Origin/response bytes, duration, missed bytes | State is neither `SF` nor `S1` |
| `dns` | Query, query type, response code | RTT | `NXDOMAIN`, `SERVFAIL`, or `REFUSED` |
| `http` | Host, method, status, user agent | Request/response body lengths, transaction depth | Status is at least `400` |
| `ssl` | Server, version, cipher, JA3, JA3S, validation | None | `established` is `F` |
| `files` | Source, MIME, filename, SHA-256 | Seen/total/missing/overflow bytes, duration, depth | Timed out or missing bytes are positive |
| `dhcp` | Server, MAC, hostname, requested/assigned address, message types | Lease time, duration | Assigned address is empty |
| `notice` | Note, protocol, message | `n` | Every notice |
| `analyzer` | Analyzer kind/name, failure reason | None | Failure reason is non-empty |
| `dce_rpc` | Named pipe, endpoint, operation | RTT | Never |
| `smb_mapping` | Path, service, share type | None | Never |
| `ntlm` | Username, hostname, domain | None | `success` is `F` |
| `ssh` | Client, server, authentication success, direction | Authentication attempts | `auth_success` is `F` |
| `weird` | Name, detail | None | Every weird record |
| `known_hosts` | None | None | Never |
| `known_services` | Port, transport, service | None | Never |
| `software` | Type, name, version | None | Never |

Each generated feature is transformed and modeled independently. A protocol
hour is anomalous if any feature has:

$$
z \ge \frac{T_{\mathrm{feature}}}{S}.
$$

### Protocol anomaly score

For anomalous feature set \(J\):

$$
A_p = \sum_{j \in J} z_j.
$$

The informational protocol severity is:

$$
\mathrm{severity}_p =
  1-e^{-\max_{j \in J}(z_j)/3}.
$$

The ensemble uses the capped normalized protocol score, not severity.

## 🧠 Global per-IP ensemble

Protocol anomalies are grouped by source IP and traffic window. Each protocol
contributes at most once.

With protocol score cap \(K\), normally `10`:

$$
c_p = \frac{\min(A_p,K)}{K}.
$$

Every contribution \(c_p\) is in `[0, 1]`. If \(P\) protocols are anomalous,
the corroboration bonus is:

$$
B = \min(B_{\max},\max(0,P-1)B_{\mathrm{step}}).
$$

Defaults are `B_step = 0.15` and `B_max = 0.30`. Let (U) be the number of
exact responsible UIDs present in at least two anomalous components. Its bonus
is:

$$
B_U = \min(B_{U,\max}, U B_{U,\mathrm{step}}).
$$

The defaults are `0.10` per shared UID and a `0.20` cap. Shared FUIDs are
reported but not scored. The global score is:

$$
G = \min\left(1,\sum_{p=1}^{P}c_p+B+B_U\right).
$$

Sensitivity changes both global gates:

$$
T_{G,\mathrm{effective}} =
  \min\left(1,\frac{T_G}{S}\right),
$$

$$
P_{\mathrm{effective}} =
  \max\left(1,\left\lceil\frac{P_{\min}}{S}\right\rceil\right).
$$

A global anomaly is emitted when either gate passes:

$$
\text{global anomaly} \iff
G \ge T_{G,\mathrm{effective}}
\quad \lor \quad
P \ge P_{\mathrm{effective}}.
$$

| Global confidence | Condition |
| ----------------- | --------- |
| `low` | \(G < 0.55\) |
| `medium` | \(0.55 \le G < 0.80\) |
| `high` | \(G \ge 0.80\) |

### Ensemble example

Assume DNS score `4.0`, HTTP score `3.0`, cap `10`, and the same IP/window:

$$
c_{\mathrm{DNS}} = 4/10 = 0.4,
$$

$$
c_{\mathrm{HTTP}} = 3/10 = 0.3,
$$

$$
B = \min(0.30,(2-1)0.15)=0.15,
$$

$$
G = \min(1,0.4+0.3+0.15)=0.85.
$$

At sensitivity `1.0`, the default global threshold is `0.65`, so this emits a
high-confidence global anomaly.

## ⭐ Dashboard importance ranking

Importance is a dashboard ranking heuristic. It does not create, suppress, or
modify anomalies. It exists because many global scores reach the maximum
`1.0`, which makes `global_score` alone unsuitable for ordering.

For one anomaly, define:

- \(D\): `total_score`, the uncapped sum of all reason z-scores; novelty
  reasons without a z-score contribute `2.0`
- \(E\): `threshold_excess`, the sum of
  `max(0, zscore - threshold)` across reasons
- \(P\): number of independently anomalous protocols
- \(R\): number of anomalous reasons

The composite importance score is:

$$
I = \min\left(
100,\,
35(1-e^{-D/15})
+25\min(1,P/4)
+20\min(1,R/8)
+20(1-e^{-E/10})
\right).
$$

Its four displayed components mean:

| Component | Maximum | Meaning |
| --------- | ------: | ------- |
| Total deviation | `35` | Rewards a large uncapped total anomaly score |
| Protocol breadth | `25` | Rewards independent corroborating protocols |
| Reason breadth | `20` | Rewards multiple anomalous features |
| Threshold excess | `20` | Rewards z-scores far beyond their thresholds |

Importance levels are:

| Level | Score |
| ----- | ----- |
| `low` | Below `35` |
| `medium` | `35` to below `60` |
| `high` | `60` to below `80` |
| `critical` | `80` to `100` |

The dashboard sorts SSL-flow and protocol-window anomalies by `total_score`
descending. Global anomalies default to `importance_score` descending because
that ranking preserves deviation magnitude, protocol corroboration, and
reason breadth even when several `global_score` values equal `1.0`. The user
can instead rank by total score, threshold excess, protocol count, or reason
count and can filter by minimum importance level.

## 🔄 Post-detection adaptation

After scoring, non-training models use EWMA:

$$
\delta = y-\mu,
$$

$$
\mu \leftarrow \mu+\alpha\delta,
$$

$$
s^2 \leftarrow
(1-\alpha)(s^2+\alpha\delta^2).
$$

Larger \(\alpha\) adapts faster. Smaller \(\alpha\) reduces how quickly
anomalous behavior enters the baseline.

### SSL flow adaptation

| Outcome | Alpha |
| ------- | ----- |
| No anomaly reason | `ssl_baseline_alpha`, default `0.10` |
| Reasons no greater than `ssl_max_small_anomalies` | `drift_alpha`, default `0.05` |
| More reasons | `suspicious_alpha`, default `0.005` |

### SSL window adaptation

An SSL window is small drift when:

$$
A_{\mathrm{window}} \le \mathrm{adaptationScore}.
$$

Small drift uses `drift_alpha`; other windows use `suspicious_alpha`.

Individual `ssl-flow` anomalies do not enter the window feature vector,
window score, window adaptation decision, or global ensemble. This prevents
the same evidence from being counted at multiple detection levels.

### Multi-protocol adaptation

A protocol window uses `drift_alpha` when:

$$
A_p \le \mathrm{adaptationScore}.
$$

Otherwise it uses `suspicious_alpha`.

Sensitivity does not directly rescale alpha values or `adaptation_score`. It
can affect adaptation indirectly because thresholds determine which z-scores
enter an anomaly-score sum.

## ⚙️ Configuration value reference

Command-line `--sensitivity` and `--training-windows` override `[common]`.
Explicit command-line options for other settings override their configured
values.

The values in the following tables are built-in fallbacks used when a setting
is absent. Values explicitly present in `anomaly_detector.conf`, a selected
configuration file, or command-line overrides are the effective values for a
run. The dashboard displays and snapshots those effective configured values.

### Common and output settings (`[common]`, `[output]`)

| Setting | Built-in fallback | Exact role |
| ------- | ------: | ---------- |
| `training_windows` | `3` | Number of `window_seconds` units in the one capture-wide trusted interval beginning at the first analyzed record; zero selects adaptive cold start |
| `window_seconds` | `3600` | Width of every aggregation window; `300` selects five-minute windows |
| `normal_dirs` | empty | Comma-separated known-normal Zeek folders fitted before the selected input |
| `sensitivity` | `1.0` | Divisor applied to anomaly thresholds and global protocol-count gate |
| `color` | `auto` | `auto`, `always`, or `never` terminal ANSI colors; does not affect detection |
| `show_terminal_data` | `true` | Prints window-level `DATA` rows; logs are written regardless |
| `quiet` | `false` | Suppresses per-event terminal rows while retaining the summary |

### SSL-specific settings (inside `[multi_protocol]`)

| Setting | Built-in fallback | Exact role |
| ------- | ------: | ---------- |
| `minimum_points` | `3` | Required model count before a nonzero z-score can be returned |
| `ssl_hourly_threshold` | `3.5` | Legacy key: fallback \(T\) for specialized SSL window features |
| `ssl_flow_threshold` | `3.5` | Fallback \(T\) for per-server byte z-scores |
| `ssl_novelty_threshold` | `1.5` | Base gate compared with implicit novelty evidence `2.0` |
| `ssl_baseline_alpha` | `0.10` | EWMA \(\alpha\) for a post-training SSL flow with no anomaly reason |
| `ssl_max_small_anomalies` | `2` | Maximum reasons on one SSL flow still classified as small for that flow's byte-model update |

### Multi-protocol and ensemble settings (`[multi_protocol]`)

| Setting | Built-in fallback | Exact role |
| ------- | ------: | ---------- |
| `minimum_points` | `3` | Required model count before a nonzero feature z-score |
| `threshold` | `3.5` | Fallback \(T\) for every protocol-window feature |
| `threshold_quantile` | `0.995` | \(q\) used for empirical benign threshold calibration |
| `drift_alpha` | `0.05` | EWMA \(\alpha\) when protocol score is at most `adaptation_score` |
| `suspicious_alpha` | `0.005` | EWMA \(\alpha\) when protocol score exceeds `adaptation_score` |
| `adaptation_score` | `8.0` | Boundary between drift and suspicious protocol-window updates |
| `protocol_score_cap` | `10.0` | \(K\), maximum protocol score counted by the ensemble |
| `global_threshold` | `0.65` | \(T_G\), global score gate before sensitivity |
| `minimum_protocols` | `2` | \(P_{\min}\), corroborating protocol-count gate before sensitivity |
| `corroboration_bonus` | `0.15` | \(B_{\mathrm{step}}\), bonus per additional anomalous protocol |
| `corroboration_bonus_cap` | `0.30` | \(B_{\max}\), maximum corroboration bonus |
| `uid_corroboration_bonus` | `0.10` | \(B_{U,\mathrm{step}}\), bonus per exact UID shared by anomalous components |
| `uid_corroboration_bonus_cap` | `0.20` | \(B_{U,\max}\), maximum exact-UID bonus |
| `max_responsible_flows` | `10` | Maximum representative Zeek records embedded in each protocol or global anomaly |
| `output_dir` | `multi_protocol_ad_output` | Destination directory; does not affect detection |

### Optional detector settings

Every real optional detector has an `experimental_*_mode` setting with values
`off`, `shadow`, or `active`. Off does not run. Shadow records candidates but
does not alter official output. Active may add candidates; it never removes or
reduces a core anomaly.

| Detector | Mode key | Main decision |
| -------- | -------- | ------------- |
| Robust multivariate | `experimental_multivariate_mode` | dimension-normalized robust Mahalanobis distance ≥ `multivariate_threshold` |
| PCA reconstruction | `experimental_pca_mode` | reconstruction error ≥ `pca_threshold` |
| Isolation Forest | `experimental_isolation_mode` | isolation score ≥ `isolation_threshold` |
| Empirical rarity | `experimental_rarity_mode` | −log10 empirical tail probability ≥ `rarity_threshold` |
| Time-series change | `experimental_change_mode` | robust recent-level shift ≥ `change_threshold` |
| Communication graph | `experimental_graph_mode` | weighted new-destination/fan-out score ≥ `graph_threshold` |

Each method also has `*_minimum_points` and `*_history_limit`. PCA adds
`pca_components`, Isolation Forest adds `isolation_trees`, time-series change
adds `change_recent_windows`, and multivariate detection adds
`multivariate_shrinkage`. Numeric methods analyze source-IP/protocol converted
features and the different destination-IP converted features independently.
The graph method instead unions all destination IPs contacted by one source IP
across protocols in each window.

Active integration is set union, not voting against the core:

```text
official IDs = core IDs union all Active-module candidate IDs
```

## 🔎 Responsible-flow attribution

Every emitted anomaly contains `responsible_flow_count` and
`responsible_flows`.

- A flow-level SSL anomaly contains the exact SSL record that triggered it.
- A new-peer or new-field reason selects records containing that new value.
- A failure-ratio reason selects records satisfying the protocol's failure
  predicate.
- A numeric total or average reason ranks records by that numeric field in the
  anomalous direction.
- A unique-value reason selects representative records for distinct values.
- An event-count reason attributes all records in the anomalous window.
- A global anomaly carries representative flows from every contributing
  protocol anomaly.

`responsible_flow_count` is the number of matching records before display
truncation. `responsible_flows` contains at most `max_responsible_flows`.
Selection is balanced across reasons so one high-cardinality reason does not
consume every representative slot.

Each responsible-flow object contains:

| Field | Meaning |
| ----- | ------- |
| `log` | Source Zeek log name, such as `conn`, `dns`, or `ssl` |
| `ts` | Original Zeek traffic timestamp |
| `uid` / `fuid` | Zeek identifier used to locate the original record |
| `src`, `src_port` | Origin endpoint when available |
| `dst`, `dst_port` | Response endpoint when available |
| `details` | Protocol fields relevant to the anomaly computation |
| `matched_features` | Anomaly reasons for which this record was selected |

For example, a UID can be located directly with:

```bash
rg 'C8wotk4mofjXC7W5uc' bro/conn.log
```

For a lower-than-baseline count, the missing expected records do not exist and
cannot have UIDs. In that case, the anomaly explanation states that the value
decreased and `responsible_flows` shows the records that were present; the
absence relative to the baseline is itself the evidence.

## 📝 Reading output fields

| Output field | Exact meaning |
| ------------ | ------------- |
| `value` | Raw feature value before `log1p` |
| `mean` | Model mean transformed back with `expm1` |
| `zscore` | Absolute standardized deviation in transformed space |
| `threshold` | Effective threshold after calibration and sensitivity |
| Protocol `score` | Sum of anomalous feature z-scores |
| `normalized_score` | Capped protocol score divided by its cap |
| SSL `anomaly_score` | Sum of anomalous window-feature z-scores |
| SSL `confidence.score` | Weighted confidence equation bounded to `[0,1]` |
| `global_score` | Contributions plus corroboration, bounded to `[0,1]` |
| `phase` | `training` when the window contains only selected-capture records before the global training cutoff; otherwise `detection` |
| `trained_windows` | Number of this model's window values fitted from trusted training traffic |
| `window_start` | Timestamp at the start of the aggregation window; selected-capture windows are anchored at the first analyzed record |
| `window_seconds` | Configured width of the aggregation window |
| `hour_start` | Compatibility alias for `window_start`; retained for existing consumers |
| `responsible_flow_count` | Total matching Zeek records before representative-flow truncation |
| `responsible_flows` | Traceable representative records with UID, endpoints, details, and matched reasons |

JSONL is the authoritative machine-readable output. Human logs and colored
terminal lines render the same decisions for inspection.
