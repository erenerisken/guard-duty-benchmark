#!/usr/bin/env bash

# Shared config for GuardDuty benchmark setup/cleanup scripts.
: "${REGION:=us-east-2}"
: "${ACCOUNT_ID:=0000000000000}"
: "${BUCKET:=eren-gd-test-bucket-1}"
: "${QUEUE:=eren-gd-test-queue}"
: "${RULE:=eren-gd-test-rule}"
: "${TARGET_ID:=eren-gd-test-sqs-target}"
: "${ROLE:=eren-gd-test-mp-role}"
: "${SCAN_PREFIX:=gd-bench/}"   # MUST match KEY_PREFIX in the Python harness

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE}"
RULE_ARN="arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${RULE}"
