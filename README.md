# GuardDuty Malware Protection for S3 Benchmark

Small benchmark harness for measuring end-to-end scan result latency from
Amazon GuardDuty Malware Protection for S3.

The benchmark uploads test objects to S3 and waits for the corresponding
`GuardDuty Malware Protection Object Scan Result` EventBridge events delivered
to SQS. Results are written to CSV and summarized on stdout.

## What This Measures

Latency is measured as:

```text
EventBridge event time - upload completion time
```

The current benchmark matrix covers:

| Config | Object | Upload mode |
| --- | ---: | --- |
| `size_1KB` | 1 KB clean object | sequential |
| `size_256KB` | 256 KB clean object | sequential |
| `size_1MB` | 1 MB clean object | sequential |
| `size_5MB` | 5 MB clean object | sequential |
| `size_10MB` | 10 MB clean object | sequential |
| `size_25MB` | 25 MB clean object | sequential |
| `size_50MB` | 50 MB clean object | sequential |
| `type_zip` | 5 MB payload inside a zip | sequential |
| `type_eicar` | EICAR antivirus test string | sequential |
| `concur_burst` | 5 MB clean objects | burst |

By default, each config uploads 15 objects (150 objects across 10 configs).
Sizes use binary units: 1 MB in the config labels is 1 MiB (1,048,576 bytes).

## Files

| File | Purpose |
| --- | --- |
| `gd_config.sh` | Shared AWS resource names and region/account config |
| `gd_setup.sh` | Creates the S3 bucket, IAM role, GuardDuty plan, SQS queue, and EventBridge rule |
| `gd_scan_benchmark.py` | Uploads benchmark objects, drains scan events, writes CSV output |
| `gd_cleanup.sh` | Deletes resources created by setup using the configured names |
| `gd_scan_results.csv` | Example benchmark output from a run |

## Prerequisites

- AWS CLI v2
- `jq`
- Python 3.9+
- `boto3`
- AWS credentials with permission to create and delete:
  - S3 bucket and objects
  - IAM role and inline policy
  - GuardDuty Malware Protection plan
  - SQS queue and queue policy
  - EventBridge rule and target

Install Python dependency:

```bash
python3 -m pip install boto3
```

## Configure

Edit `gd_config.sh` before setup:

```bash
REGION
ACCOUNT_ID
BUCKET
QUEUE
RULE
TARGET_ID
ROLE
SCAN_PREFIX
```

`ACCOUNT_ID` must be your 12-digit AWS account ID. `SCAN_PREFIX` must match
`KEY_PREFIX` in `gd_scan_benchmark.py`.

## Setup

Run:

```bash
bash gd_setup.sh
```

The script prints the values to copy into `gd_scan_benchmark.py`:

```python
REGION = "..."
BUCKET = "..."
SQS_QUEUE_URL = "..."
KEY_PREFIX = "..."
```

If setup fails after creating the GuardDuty plan, rerunning the script should
reuse the existing plan for the configured bucket and role.

## Run Benchmark

Run:

```bash
python3 gd_scan_benchmark.py
```

The script:

1. Uploads objects under `KEY_PREFIX/RUN_ID/...`
2. Waits for matching GuardDuty scan result events from SQS
3. Writes `gd_scan_results.csv`
4. Prints latency percentiles by config

CSV columns:

```text
config,key,size_bytes,kind,concurrency,upload_ts,event_ts,latency_s,scan_result
```

## Results

The latest run (`640a1d65`) is included in `gd_scan_results.csv`, with 150
results across all 10 configs (15 objects each). All 135 clean and ZIP objects
returned `NO_THREATS_FOUND`; all 15 EICAR objects returned `THREATS_FOUND`.

Console summary, recalculated from the CSV using the harness's percentile and
rounding logic:

```text
=== Latency summary (seconds) ===
config           n     p50     p90     p99     min     max    mean  result
size_1KB        15     0.9     1.3     1.4     0.5     1.4     0.9  NO_THREATS_FOUND
size_256KB      15     1.1     1.5     1.6     0.6     1.6     1.1  NO_THREATS_FOUND
size_1MB        15     0.9     1.3     2.1     0.1     2.3     0.9  NO_THREATS_FOUND
size_5MB        15     1.0     1.5     1.5     0.6     1.5     1.0  NO_THREATS_FOUND
size_10MB       15     1.1     1.7     1.9     0.5     1.9     1.1  NO_THREATS_FOUND
size_25MB       15     1.6     2.0     2.4     0.9     2.4     1.6  NO_THREATS_FOUND
size_50MB       15     2.2     2.6     2.6     1.2     2.6     2.1  NO_THREATS_FOUND
type_zip        15     1.2     1.6     1.7     0.8     1.7     1.2  NO_THREATS_FOUND
type_eicar      15     0.9     1.4     1.5     0.4     1.5     1.0  THREATS_FOUND
concur_burst    15     0.8     1.1     1.2     0.3     1.2     0.8  NO_THREATS_FOUND
```

In this run, median latency increased from 1.1 seconds at 10 MiB to 1.6 seconds
at 25 MiB and 2.2 seconds at 50 MiB. Event timestamps in the CSV have whole-second
precision, and each config has only 15 samples, so small differences and p99
estimates should be interpreted cautiously.

## Cleanup

Run:

```bash
bash gd_cleanup.sh
```

Cleanup deletes the configured GuardDuty plan, EventBridge target/rule, SQS
queue, IAM role/policy, and S3 bucket. It assumes the configured resource names
belong to this benchmark run.

## Notes

- The EICAR sample is a harmless standard antivirus test string. Security tools
  may still flag it by design.
- GuardDuty, S3, SQS, EventBridge, and data transfer may incur AWS charges.
- The benchmark uses EventBridge event timestamps, not the local time when SQS
  receives the message.
- Results can vary by region, account state, object size, service load, and
  queue/event delivery timing.
