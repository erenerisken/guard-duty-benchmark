#!/usr/bin/env python3
"""
GuardDuty Malware Protection for S3 — scan-latency benchmark harness.

Measures end-to-end latency: time from upload completion to the
`GuardDuty Malware Protection Object Scan Result` EventBridge event
(captured via an SQS queue subscribed to that rule).

Prereqs (one-time, see README/setup):
  - Bucket has Malware Protection for S3 enabled, tagging ON.
  - EventBridge rule for "GuardDuty Malware Protection Object Scan Result"
    targeting an SQS queue.

Usage:
  pip install boto3
  python gd_scan_benchmark.py
"""

import io
import csv
import json
import time
import uuid
import zipfile
import statistics
import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import boto3

# ----------------------------- CONFIG -------------------------------------
REGION        = "us-east-2"
BUCKET        = "eren-gd-test-bucket-1"
SQS_QUEUE_URL = "https://sqs.us-east-2.amazonaws.com/000000000000/eren-gd-test-queue"
KEY_PREFIX    = "gd-bench/"            # uploaded under this prefix
PER_CONFIG    = 15                     # objects per configuration (10-20)
DRAIN_TIMEOUT = 1800                   # seconds to wait for all results
OUTPUT_CSV    = "gd_scan_results.csv"

# EICAR standard antivirus test string (harmless; AV engines flag by agreement)
EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

# One-factor-at-a-time matrix around a 5MB / clean / sequential baseline.
# Each tuple: (config_label, size_bytes, kind, concurrency)
KB = 1024
MB = 1024 * 1024
CONFIGS = [
    ("size_1KB",     KB,       "clean", "sequential"),
    ("size_256KB",   256 * KB, "clean", "sequential"),
    ("size_1MB",     MB,       "clean", "sequential"),
    ("size_5MB",     5 * MB,   "clean", "sequential"),   # baseline
    ("type_zip",     5 * MB,   "zip",   "sequential"),
    ("type_eicar",   len(EICAR), "eicar", "sequential"),
    ("concur_burst", 5 * MB,   "clean", "burst"),
]
# --------------------------------------------------------------------------

s3  = boto3.client("s3", region_name=REGION)
sqs = boto3.client("sqs", region_name=REGION)

RUN_ID = uuid.uuid4().hex[:8]


def make_body(size_bytes: int, kind: str) -> bytes:
    if kind == "eicar":
        return EICAR
    payload = b"\x00" * size_bytes  # zero-fill keeps generation fast & deterministic
    if kind == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("payload.bin", payload)
        return buf.getvalue()
    return payload


def upload_one(label: str, size_bytes: int, kind: str, idx: int) -> dict:
    key = f"{KEY_PREFIX}{RUN_ID}/{label}/{idx:03d}"
    body = make_body(size_bytes, kind)
    s3.put_object(Bucket=BUCKET, Key=key, Body=body)
    upload_ts = time.time()  # wall clock immediately after PutObject returns
    return {"key": key, "config": label, "size_bytes": size_bytes,
            "kind": kind, "upload_ts": upload_ts}


def run_uploads() -> dict:
    pending = {}
    for label, size_bytes, kind, concurrency in CONFIGS:
        print(f"[upload] {label}: {PER_CONFIG} objects ({concurrency})")
        if concurrency == "burst":
            with ThreadPoolExecutor(max_workers=PER_CONFIG) as ex:
                recs = list(ex.map(
                    lambda i: upload_one(label, size_bytes, kind, i),
                    range(PER_CONFIG)))
        else:
            recs = [upload_one(label, size_bytes, kind, i)
                    for i in range(PER_CONFIG)]
        for r in recs:
            r["concurrency"] = concurrency
            pending[r["key"]] = r
    return pending


def parse_event_time(s: str) -> float:
    # EventBridge "time" field, e.g. "2024-02-28T01:01:01Z"
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def drain_results(pending: dict) -> list:
    results = []
    deadline = time.time() + DRAIN_TIMEOUT
    remaining = set(pending)
    while remaining and time.time() < deadline:
        resp = sqs.receive_message(
            QueueUrl=SQS_QUEUE_URL, MaxNumberOfMessages=10,
            WaitTimeSeconds=20, VisibilityTimeout=30)
        for msg in resp.get("Messages", []):
            try:
                event = json.loads(msg["Body"])
                detail = event["detail"]
                key = detail["s3ObjectDetails"]["objectKey"]
                status = detail["scanResultDetails"]["scanResultStatus"]
                event_ts = parse_event_time(event["time"])
            except (KeyError, ValueError, json.JSONDecodeError):
                continue
            if key in pending and key in remaining:
                rec = dict(pending[key])
                rec["scan_result"] = status
                rec["event_ts"] = event_ts
                rec["latency_s"] = round(event_ts - rec["upload_ts"], 3)
                results.append(rec)
                remaining.discard(key)
            sqs.delete_message(QueueUrl=SQS_QUEUE_URL,
                               ReceiptHandle=msg["ReceiptHandle"])
        if remaining:
            print(f"  ...waiting on {len(remaining)} results")
    if remaining:
        print(f"[warn] timed out; {len(remaining)} objects never returned a result")
    return results


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    lo = int(k)
    return round(s[lo] + (s[min(lo + 1, len(s) - 1)] - s[lo]) * (k - lo), 1)


def summarize(results):
    print("\n=== Latency summary (seconds) ===")
    print(f"{'config':<14}{'n':>4}{'p50':>8}{'p90':>8}{'p99':>8}"
          f"{'min':>8}{'max':>8}{'mean':>8}  result")
    by_cfg = {}
    for r in results:
        by_cfg.setdefault(r["config"], []).append(r)
    for cfg, _, _, _ in CONFIGS:
        rs = by_cfg.get(cfg, [])
        lat = [r["latency_s"] for r in rs]
        if not lat:
            print(f"{cfg:<14}{0:>4}   (no results)")
            continue
        outcome = ",".join(sorted({r["scan_result"] for r in rs}))
        print(f"{cfg:<14}{len(lat):>4}{percentile(lat,50):>8}"
              f"{percentile(lat,90):>8}{percentile(lat,99):>8}"
              f"{min(lat):>8.1f}{max(lat):>8.1f}"
              f"{statistics.mean(lat):>8.1f}  {outcome}")


def write_csv(results):
    cols = ["config", "key", "size_bytes", "kind", "concurrency",
            "upload_ts", "event_ts", "latency_s", "scan_result"]
    with open(OUTPUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in sorted(results, key=lambda x: (x["config"], x["key"])):
            w.writerow(r)
    print(f"\n[csv] wrote {len(results)} rows -> {OUTPUT_CSV}")


def main():
    print(f"Run ID: {RUN_ID}  Bucket: {BUCKET}")
    pending = run_uploads()
    print(f"\n[uploaded] {len(pending)} objects; draining scan results...")
    results = drain_results(pending)
    write_csv(results)
    summarize(results)


if __name__ == "__main__":
    main()
