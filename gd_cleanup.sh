#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/gd_config.sh"

PLAN_ID="${PLAN_ID:-}"
if [ -z "$PLAN_ID" ]; then
  for candidate in $(aws guardduty list-malware-protection-plans \
      --region "$REGION" \
      --query 'MalwareProtectionPlans[].MalwareProtectionPlanId' \
      --output text); do
    plan_bucket=$(aws guardduty get-malware-protection-plan \
      --region "$REGION" \
      --malware-protection-plan-id "$candidate" \
      --query 'ProtectedResource.S3Bucket.BucketName' \
      --output text 2>/dev/null || true)
    plan_role=$(aws guardduty get-malware-protection-plan \
      --region "$REGION" \
      --malware-protection-plan-id "$candidate" \
      --query 'Role' \
      --output text 2>/dev/null || true)

    if [ "$plan_bucket" = "$BUCKET" ] && [ "$plan_role" = "$ROLE_ARN" ]; then
      PLAN_ID="$candidate"
      break
    fi
  done
fi

[ -n "$PLAN_ID" ] || { echo "ERROR: could not find malware protection plan for bucket $BUCKET"; exit 1; }

QUEUE_URL=$(aws sqs get-queue-url \
  --region "$REGION" \
  --queue-name "$QUEUE" \
  --query 'QueueUrl' \
  --output text)

aws guardduty delete-malware-protection-plan --region "$REGION" \
   --malware-protection-plan-id "$PLAN_ID"
aws events remove-targets --region "$REGION" --rule "$RULE" --ids "$TARGET_ID"
aws events delete-rule --region "$REGION" --name "$RULE"
aws sqs delete-queue --region "$REGION" --queue-url "$QUEUE_URL"
aws iam delete-role-policy --role-name "$ROLE" --policy-name "${ROLE}-policy"
aws iam delete-role --role-name "$ROLE"
aws s3 rm "s3://$BUCKET" --recursive
aws s3api delete-bucket --bucket "$BUCKET" --region "$REGION"
