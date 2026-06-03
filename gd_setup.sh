#!/usr/bin/env bash
#
# One-time infra for the GuardDuty Malware Protection for S3 scan benchmark.
# Creates: S3 bucket, IAM service role, GuardDuty Malware Protection plan
# (tagging ON), SQS queue, and an EventBridge rule -> SQS for scan results.
#
# Assumes: default SSE-S3 encryption (no customer-managed KMS key).
# Requires: awscli v2 configured with credentials for the target account.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/gd_config.sh"

echo ">> [1/7] Creating S3 bucket: $BUCKET"
if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
  echo "   bucket already exists, skipping"
else
  aws s3api create-bucket \
    --bucket "$BUCKET" \
    --region "$REGION" \
    --create-bucket-configuration LocationConstraint="$REGION" >/dev/null
fi

echo ">> [2/7] Creating IAM service role: $ROLE"
TRUST=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "malware-protection-plan.guardduty.amazonaws.com" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "aws:SourceAccount": "${ACCOUNT_ID}" },
      "ArnLike": { "aws:SourceArn": "arn:aws:guardduty:${REGION}:${ACCOUNT_ID}:malware-protection-plan/*" }
    }
  }]
}
EOF
)
if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE" --policy-document "$TRUST"
else
  aws iam create-role --role-name "$ROLE" \
    --assume-role-policy-document "$TRUST" >/dev/null
fi

echo ">> [3/7] Attaching permissions policy"
PERMS=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "AllowManagedRuleToSendS3EventsToGuardDuty", "Effect": "Allow",
      "Action": ["events:PutRule","events:DeleteRule","events:PutTargets","events:RemoveTargets"],
      "Resource": ["arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"],
      "Condition": { "StringLike": { "events:ManagedBy": "malware-protection-plan.guardduty.amazonaws.com" } } },
    { "Sid": "AllowGuardDutyToMonitorEventBridgeManagedRule", "Effect": "Allow",
      "Action": ["events:DescribeRule","events:ListTargetsByRule"],
      "Resource": ["arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"] },
    { "Sid": "AllowPostScanTag", "Effect": "Allow",
      "Action": ["s3:PutObjectTagging","s3:GetObjectTagging","s3:PutObjectVersionTagging","s3:GetObjectVersionTagging"],
      "Resource": ["arn:aws:s3:::${BUCKET}/*"] },
    { "Sid": "AllowEnableS3EventBridgeEvents", "Effect": "Allow",
      "Action": ["s3:PutBucketNotification","s3:GetBucketNotification"],
      "Resource": ["arn:aws:s3:::${BUCKET}"] },
    { "Sid": "AllowPutValidationObject", "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": ["arn:aws:s3:::${BUCKET}/malware-protection-resource-validation-object"] },
    { "Sid": "AllowCheckBucketOwnership", "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::${BUCKET}"] },
    { "Sid": "AllowMalwareScan", "Effect": "Allow",
      "Action": ["s3:GetObject","s3:GetObjectVersion"],
      "Resource": ["arn:aws:s3:::${BUCKET}/*"] }
  ]
}
EOF
)
aws iam put-role-policy --role-name "$ROLE" \
  --policy-name "${ROLE}-policy" --policy-document "$PERMS"

echo ">> [4/7] Waiting for IAM role to propagate"
sleep 15

echo ">> [5/7] Creating GuardDuty Malware Protection plan (tagging ON, prefix '${SCAN_PREFIX}')"
PROTECTED="{\"S3Bucket\":{\"BucketName\":\"${BUCKET}\",\"ObjectPrefixes\":[\"${SCAN_PREFIX}\"]}}"
PLAN_ID=""
find_existing_plan() {
  local candidate
  local plan_bucket
  local plan_role

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
      return 0
    fi
  done

  return 1
}

for attempt in 1 2 3 4 5; do
  if PLAN_ID=$(aws guardduty create-malware-protection-plan \
        --region "$REGION" \
        --role "$ROLE_ARN" \
        --protected-resource "$PROTECTED" \
        --actions '{"Tagging":{"Status":"ENABLED"}}' \
        --query 'MalwareProtectionPlanId' --output text 2>/tmp/gderr); then
    break
  fi
  if grep -q "provided S3 bucket is already protected" /tmp/gderr && find_existing_plan; then
    echo "   bucket is already protected by plan $PLAN_ID, reusing it"
    break
  fi
  echo "   attempt ${attempt} failed (IAM likely not propagated yet); retrying in 20s..."
  cat /tmp/gderr
  PLAN_ID=""
  sleep 20
done
[ -n "$PLAN_ID" ] || { echo "ERROR: could not create plan"; exit 1; }
echo "   plan id: $PLAN_ID"

echo ">> [6/7] Creating SQS queue: $QUEUE"
QUEUE_URL=$(aws sqs create-queue --region "$REGION" --queue-name "$QUEUE" \
  --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --region "$REGION" \
  --queue-url "$QUEUE_URL" --attribute-names QueueArn \
  --query 'Attributes.QueueArn' --output text)

QPOLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowEventBridgeToSend",
    "Effect": "Allow",
    "Principal": { "Service": "events.amazonaws.com" },
    "Action": "sqs:SendMessage",
    "Resource": "${QUEUE_ARN}",
    "Condition": { "ArnEquals": { "aws:SourceArn": "${RULE_ARN}" } }
  }]
}
EOF
)
QATTRS=$(jq -cn --arg policy "$QPOLICY" '{Policy: $policy}')
aws sqs set-queue-attributes --region "$REGION" \
  --queue-url "$QUEUE_URL" --attributes "$QATTRS"

echo ">> [7/7] Creating EventBridge rule + SQS target"
# Matching only source + detail-type is robust; this is the only scan source
# in the account. Add a detail.s3ObjectDetails.bucketName filter if you later
# protect multiple buckets.
aws events put-rule --region "$REGION" --name "$RULE" \
  --event-pattern '{"source":["aws.guardduty"],"detail-type":["GuardDuty Malware Protection Object Scan Result"]}' >/dev/null
aws events put-targets --region "$REGION" --rule "$RULE" \
  --targets "Id=${TARGET_ID},Arn=${QUEUE_ARN}" >/dev/null

echo ""
echo "=========================================================="
echo "Setup complete."
echo "  Bucket    : $BUCKET"
echo "  Plan ID   : $PLAN_ID"
echo "  Queue URL : $QUEUE_URL"
echo ""
echo "Put these into gd_scan_benchmark.py:"
echo "  REGION        = \"$REGION\""
echo "  BUCKET        = \"$BUCKET\""
echo "  SQS_QUEUE_URL = \"$QUEUE_URL\""
echo "  KEY_PREFIX    = \"$SCAN_PREFIX\"   # must match SCAN_PREFIX above"
echo "=========================================================="
