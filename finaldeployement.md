# Final Deployment — CloudTrail Non-IaC Change Alerting POC

**File:** `finaldeployement.md`  
**Deployment:** AWS Console, without Terraform  
**Storage:** No database  
**Invocation:** Manual Lambda test or AWS CLI; no EventBridge  
**Diagnostics:** CloudWatch Logs enabled  
**Notifications:** Standard SNS topic → confirmed email subscription

## 1. Final architecture and behavior

```text
Manual Lambda Test / AWS CLI
              ↓
       Lambda detector
              ↓ read-only
Existing CloudTrail S3 bucket
              ↓ analyze selected UTC day's events
   Successful non-IaC write activity
              ├── HIGH / CRITICAL → SNS → Email
              └── Diagnostic messages → CloudWatch Logs
```

Default behavior scans **yesterday in UTC**, using `DAYS_BACK=1`. A test input such as `{"date":"2026-10-30"}` overrides that setting for historical replay.

This is heuristic **non-IaC change detection**, not a comparison against Terraform state. Console, CLI and SDK changes can all qualify. User agents/role names are classification hints, not proof of authorization or human activity. Failed API calls and selected AWS-service activity are skipped.

The final code emails only **HIGH/CRITICAL** findings. LOW/MEDIUM findings are counted and logged but do not generate email. There is no database, durable deduplication, or automatic remediation. Replaying a date can send duplicate emails.

## 2. Values used in this working POC

| Setting | Value |
|---|---|
| Deployment account | `804266303347` |
| Deployment region | `us-east-1` |
| Existing bucket | `non-iac-poc-test-804266303347-us-east-1` |
| Function | `non-iac-detector-poc` |
| Execution role | `non-iac-detector-lambda-role` |
| SNS Standard topic | `non-iac-detector-alerts` |
| Existing diagnostic log group | `/aws/lambda/iac-drift-detector` |
| Source file / handler | `index.py` / `index.lambda_handler` |

For another environment, replace account IDs, bucket names, topic ARN and region consistently. Do not provide or embed access keys.

Source basis: https://github.com/mahesh2121/iac-drift-detection-terraform- , reviewed commit `165480732b7f43283262cafb6cf916ea02ae5787`. The complete adapted email-only code is included in Section 13.

## 3. Verify existing CloudTrail logs

Do **not** create a new trail or bucket. In S3, confirm actual files follow:

```text
s3://non-iac-poc-test-804266303347-us-east-1/
  AWSLogs/804266303347/CloudTrail/us-east-1/YYYY/MM/DD/<file>.json.gz
```

The bucket may also contain other account folders and regions. The code discovers region folders only beneath each configured account's `CloudTrail/` path.

Confirm:
- Existing trail captures write management events for the required accounts/regions.
- The chosen date contains actual `.json.gz` files, not just empty folders.
- The records inside have `eventTime` matching the UTC date and `recipientAccountId` matching an allowed account.
- You have approval to read those audit logs.

The sample historical `CreateUser` email had **event time 30 October 2026**, even though the email was received on 31 October. For replay, use **the event date**, not the email receipt date.

## 4. Create or update the Lambda execution role

IAM → Roles → Create role:
1. Trusted entity: **AWS service**.
2. Service/use case: **Lambda**, not `AWSServiceRoleForLambda`.
3. Attach managed policy **AWSLambdaBasicExecutionRole** for diagnostic logs.
4. Name: `non-iac-detector-lambda-role`.

If the role already exists, update it rather than creating another.

### 4.1 Trust policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### 4.2 Combined S3 + SNS inline policy

Role → Permissions → Add permissions → Create inline policy → JSON. For an existing inline policy, select Edit instead.

Name: `NonIaCDetectorS3SNSAccess`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListAllAccountCloudTrailLogs",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::non-iac-poc-test-804266303347-us-east-1",
      "Condition": {
        "StringLike": {
          "s3:prefix": ["AWSLogs/*/CloudTrail/*"]
        }
      }
    },
    {
      "Sid": "ReadAllAccountCloudTrailLogs",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::non-iac-poc-test-804266303347-us-east-1/AWSLogs/*/CloudTrail/*"
    },
    {
      "Sid": "PublishNonIaCAlerts",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-1:804266303347:non-iac-detector-alerts"
    }
  ]
}
```

This wildcard is for **approved all-account access** in the central bucket, including future matching folders. For a restricted POC, replace it with explicit approved account paths. `ACCOUNT_IDS` controls code behavior but is not an IAM security boundary.

Keep `AWSLambdaBasicExecutionRole` attached separately; the inline policy above has no logging grants. Allow a short time for IAM propagation after policy changes. IAM-only changes do not require Lambda code deployment.

### 4.3 Optional existing SSE-KMS encryption

If CloudTrail objects use a customer-managed KMS key, add a role statement scoped to that existing key:

```json
{
  "Sid": "DecryptExistingCloudTrailLogs",
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "arn:aws:kms:KEY_REGION:KEY_OWNER_ACCOUNT_ID:key/KEY_ID"
}
```

Replace the placeholder key ARN. The key policy must also permit the role or enable applicable IAM grants. SSE-S3 does not require this permission.

For a bucket in a different account, its owner must also grant this role `s3:ListBucket` and `s3:GetObject` on the same approved paths. Cross-account KMS requires corresponding customer-managed key permissions. Preserve all existing CloudTrail delivery statements; never replace bucket/key policies wholesale.

## 5. Create or verify SNS email delivery

Use **SNS → Topics → Create topic**:
1. Type: **Standard**, not FIFO. Direct email subscriptions require Standard.
2. Name: `non-iac-detector-alerts`.
3. Copy the ARN:

```text
arn:aws:sns:us-east-1:804266303347:non-iac-detector-alerts
```

4. Create subscription → Protocol **Email** → your email address.
5. Confirm using the link in the subscription email.
6. Verify the subscription is not `PendingConfirmation`.
7. Use **Publish message** in SNS to test delivery independently.

The subscription must be on the **exact topic configured in Lambda**; an older email from another topic does not confirm this topic's setup.

For this baseline, optional SNS server-side encryption is not configured. If organizational policy requires it, enable the approved key and configure publisher/key permissions before testing. Avoid broad `sns:*` grants.

## 6. Create or update Lambda

Lambda → Create function → Author from scratch:

| Setting | Value |
|---|---|
| Name | `non-iac-detector-poc` |
| Runtime | Python 3.14, matching the runtime used during troubleshooting |
| Architecture | x86_64 |
| Execution role | Existing `non-iac-detector-lambda-role` |
| VPC | Leave unattached for this POC |
| Memory | 512 MB |
| Timeout | 5 minutes initially |

The code uses standard Python features and runtime-provided boto3. For production, pin/package dependencies and test against the selected runtime.

1. Open Code and create/replace **`index.py`** with Section 13.
2. Set Runtime settings → Handler:

```text
index.lambda_handler
```

3. Click **Deploy**.

If uploading a ZIP, place `index.py` at the ZIP root. A handler of `lambda_function.lambda_handler` will fail if that file does not exist.

## 7. Configure environment variables

Configuration → Environment variables → Edit:

| Key | Value |
|---|---|
| `CLOUDTRAIL_BUCKET` | `non-iac-poc-test-804266303347-us-east-1` |
| `ACCOUNT_IDS` | `804266303347` for the first test |
| `DAYS_BACK` | `1` |
| `INCLUDE_NEXT_DAY_FOLDER` | `true` |
| `STRICT_IAC` | `false` |
| `DRY_RUN` | `true` initially, then `false` for email testing |
| `SNS_TOPIC_ARN` | `arn:aws:sns:us-east-1:804266303347:non-iac-detector-alerts` |
| `DETECTOR_CONFIG` | Exact JSON below |

For the demonstrated bucket layout, omit or leave empty:

```text
ORG_ID
CLOUDTRAIL_PREFIX
```

Do not set database or Teams variables; neither service is used by the final code.

### 7.1 Detector configuration

Paste this plain JSON as the single environment-variable value. Do not paste Markdown links around service names.

```json
{"iac_user_agents":["terraform","cloudformation","pulumi"],"iac_role_patterns":["terraform-*","github-actions-*"],"iac_source_ips":[],"excluded_event_sources":[],"excluded_event_names":[],"critical_services":["iam.amazonaws.com"],"high_event_names":["AuthorizeSecurityGroupIngress","PutBucketPolicy","CreateAccessKey","CreateUser","ScheduleKeyDeletion"]}
```

Severity behavior:

| Match | Severity | Email in live mode |
|---|---|---|
| Action in `high_event_names` | CRITICAL | Yes |
| Service in `critical_services` | HIGH | Yes |
| Other Delete/Terminate action | MEDIUM | No |
| Other qualifying write | LOW | No |

For example, `ModifyInstanceAttribute` is LOW with this config. Add it to `high_event_names` if you intentionally want it treated as CRITICAL. A severity label is a configured rule, not an independent risk assessment.

IaC rules: with `STRICT_IAC=false`, any configured user-agent substring, role/user/session-name pattern or exact source-IP match suppresses the finding. With `STRICT_IAC=true`, both user-agent and role/name must match; IP matching is not used. IPs are exact strings, not CIDRs. Adapt patterns to actual deployment identities and avoid allow-listing roles used for manual administration.

### 7.2 Multiple accounts

```text
ACCOUNT_IDS = 804266303347,111111111111,999999999999
```

Use real approved 12-digit account IDs whose folders and log contents match. The last two IDs above are examples, not a recommendation to monitor those accounts. Do not use brackets, quotes, folder paths, short test IDs or `*`. The current code does not automatically discover accounts.

A bucket name is **not an ARN**. Never use `arn:aws:s3:::.../AWSLogs/` as `CLOUDTRAIL_BUCKET`.

### 7.3 Other path layouts

For `AWSLogs/o-example/ACCOUNT_ID/CloudTrail/...`, set `ORG_ID=o-example`.
For `audit/AWSLogs/ACCOUNT_ID/CloudTrail/...`, set `CLOUDTRAIL_PREFIX=audit`.
Do not include `AWSLogs` in the custom prefix. Update IAM paths accordingly for a different layout.

## 8. Configure CloudWatch diagnostic logs

Lambda → Configuration → Monitoring and operations tools → Edit:
1. Choose the existing log group `/aws/lambda/iac-drift-detector`.
2. The group must be in the Lambda's region (`us-east-1`).
3. If application log level is configurable, select **INFO**.
4. Save.

If your UI does not offer a custom group, the default is `/aws/lambda/non-iac-detector-poc`; use that rather than confusing it with an older group's streams. The attached logging policy permits stream creation and writes.

Run a test, then open the latest stream by **Last event time**. Set an approved short retention period, such as 7 days, for POC diagnostics. Logged paths/account IDs can be sensitive; restrict log access. The final code logs metadata and counters, not full CloudTrail event bodies or secrets.

Expected messages:

```text
SCAN_START ...
LIST_REGIONS ...
REGION_FOUND ...
LIST_DAY ...
DAY_FILES ...
NON_IAC ...
SNS_SENT ...
SCAN_COMPLETE ...
```

`START`/`END`/`REPORT` alone are platform logs; they do not prove the scan found files. Ensure the logging-enabled source was deployed and INFO is allowed.

## 9. Manual dry run

Set `DRY_RUN=true`. Lambda → Test → create event:

```json
{"date":"2026-10-30"}
```

Use that date only if the historical files still exist; otherwise choose another known event date.

Expected:
- `files > 0` for matching existing log files.
- `total > 0` for files with records.
- `NON_IAC` diagnostic entries for qualifying writes.
- No email in dry-run mode.

Response counters:

| Field | Meaning |
|---|---|
| `files` | Matching compressed log files processed |
| `total` | Records examined, including out-of-window records |
| `out_of_window` | Records whose event date differs from the target UTC day |
| `skipped` | Account mismatches, reads, failed calls or other excluded activity |
| `iac` | Records matched by IaC classification rules |
| `non_iac` | Remaining qualifying writes, including non-alerting severities |

The code also reads the next day's folder when enabled, but still accepts only target-day event timestamps. This helps with some delivery boundaries; it does not guarantee capture of all late deliveries.

## 10. Live historical replay and email verification

1. Confirm the SNS subscription and exact topic ARN.
2. Set `DRY_RUN=false`; save.
3. Invoke:

```json
{"date":"2026-10-30"}
```

4. Look for `NON_IAC ... action=CreateUser ... severity=CRITICAL` and `SNS_SENT`.
5. Check the email inbox/spam folder.

Example format (values come from the actual record):

```text
🔴 NON-IAC CHANGE DETECTED

Severity:   CRITICAL
Account:    804266303347
Region:     us-east-1
Service:    iam.amazonaws.com
Action:     CreateUser
Via:        console
User:       <original principal>
User ARN:   <original ARN>
Source IP:  <original source IP>
User Agent: <original user agent>
Resource:   <original resource>
Time (UTC): 2026-10-30T07:19:25Z
```

A replay sends the email now but preserves the original event timestamp. It does not perform the logged action or create a user. All qualifying findings for that account/day can alert, not just one selected historical file. `SNS_SENT` means SNS accepted the publish, not proof of inbox delivery.

## 11. Normal operation: yesterday only, no EventBridge

Set `DAYS_BACK=1` and invoke with:

```json
{}
```

Do not leave a historical `date` in the saved event if you want yesterday's scan. On 3 November UTC, this selects 2 November, 00:00–23:59:59 UTC. An IST midnight-to-midnight window would require a code change.

### Optional synchronous CLI invocation

Use an authorized CLI identity (prefer an IAM role rather than long-lived keys):

```bash
aws lambda invoke \
  --region us-east-1 \
  --function-name non-iac-detector-poc \
  --invocation-type RequestResponse \
  --cli-binary-format raw-in-base64-out \
  --payload '{}' \
  --cli-read-timeout 1000 \
  response.json

cat response.json
```

Inspect the CLI response for `FunctionError`; HTTP 200 alone is not proof of function success. The caller, separately from the function's execution role, needs:

```json
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Action":"lambda:InvokeFunction",
    "Resource":"arn:aws:lambda:us-east-1:804266303347:function:non-iac-detector-poc"
  }]
}
```

No automatic schedule is created by this guide. Someone or an approved external scheduler must invoke the function each day.

## 12. Troubleshooting, limits and cleanup

| Issue | Action |
|---|---|
| Cannot import `lambda_function` | Set handler `index.lambda_handler`; file at root |
| Invalid bucket name | Use bucket name only, not ARN/URI/path |
| Invalid `ACCOUNT_IDS` | Comma-separated real 12-digit IDs, no wildcard |
| ListBucket denied | Role needs bucket-level permission plus matching list-prefix condition |
| GetObject denied | Check object path, bucket grants and existing explicit denies |
| KMS denied | Role decrypt grant and existing key policy |
| SNS Publish denied | Combined policy must match exact topic ARN in environment |
| `files: 0` | Compare `LIST_DAY` prefix to an actual object key/date |
| `out_of_window > 0` | Expected when records have different UTC dates; filters use event time |
| `non_iac > 0`, no email | Check severity, DRY_RUN, SNS errors and subscription |
| Markdown service value | Use `iam.amazonaws.com`, not a Markdown link |
| Old logs only | Correct group/region, latest stream, deploy code and allow INFO |
| Duplicate alerts | Expected on replay/retry; no durable deduplication |

**Scaling:** The current function scans accounts sequentially. Lambda's maximum timeout is 15 minutes; increasing memory or timeout does not guarantee a 200-account daily scan will fit. Compressed files expand in memory. The code no longer accumulates findings, but each file is still downloaded/decompressed in memory. Test a few accounts first; busy environments need per-account/region/file work partitioning.

**Failure semantics:** S3 or SNS errors fail the invocation. Earlier publishes may already have succeeded, so a retry can duplicate alerts. Some skipped service/failed events may matter to security; this POC does not replace monitoring of those activities. No custom CloudWatch metrics, alarms or durable notification retry are provided. CloudTrail delivery delay can require backfills.

**Acceptance checks**
- [ ] Existing CloudTrail and bucket remain intact.
- [ ] Approved S3 scope, SNS publish and log permissions configured.
- [ ] Dry run processes known files.
- [ ] Live CRITICAL event results in SNS acceptance and received email.
- [ ] Saved normal-operation input is `{}` with `DAYS_BACK=1`.
- [ ] Duplicate, late-delivery and scaling limitations accepted.

**Cleanup**
Delete only POC resources when approved: Lambda, SNS subscription/topic, role policies/role and POC-only logs after retention requirements are met. The diagnostic group may be shared with older functions—do not delete it blindly. Remove only owner-approved POC grants from shared bucket/key policies. Do not delete the existing CloudTrail trail, bucket, encryption keys or audit logs. There is no database or EventBridge rule to clean up in this final design.

---

## 13. Complete Lambda source — `index.py`

Paste the following into `index.py`, set handler `index.lambda_handler`, and Deploy.

```python
"""
"""
CloudTrail Non-IaC Change Detector
- Manually invoked scan of the previous UTC day, with optional date override
- Reads only allow-listed AWS accounts (POC)
- Scans only the regions listed in SCAN_REGIONS (all regions if empty)
- Read-only on the CloudTrail bucket (list + get)
- SNS email alerts; no database; diagnostic CloudWatch logging enabled
"""
import json
import gzip
import os
import fnmatch
import hashlib
from datetime import datetime, timezone, timedelta
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3 = boto3.client('s3')
sns = boto3.client('sns')
CONFIG = json.loads(os.environ.get('DETECTOR_CONFIG', '{}'))
CT_BUCKET = os.environ.get('CLOUDTRAIL_BUCKET', '')
CT_PREFIX = os.environ.get('CLOUDTRAIL_PREFIX', '').strip('/')
ACCOUNT_IDS = [a.strip() for a in os.environ.get('ACCOUNT_IDS', '').split(',') if a.strip()]
ORG_ID = os.environ.get('ORG_ID', '').strip()
# Comma-separated list, e.g. "eu-central-1" or "eu-central-1,us-east-1". Empty = scan all regions.
SCAN_REGIONS = [r.strip() for r in os.environ.get('SCAN_REGIONS', '').split(',') if r.strip()]
DAYS_BACK = int(os.environ.get('DAYS_BACK', '1'))
INCLUDE_NEXT_DAY_FOLDER = os.environ.get('INCLUDE_NEXT_DAY_FOLDER', 'true').lower() == 'true'
STRICT_IAC = os.environ.get('STRICT_IAC', 'false').lower() == 'true'
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'
SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN', '')
IAC_USER_AGENTS = [ua.lower() for ua in CONFIG.get('iac_user_agents', [])]
IAC_ROLE_PATTERNS = CONFIG.get('iac_role_patterns', [])
IAC_SOURCE_IPS = CONFIG.get('iac_source_ips', [])
EXCLUDED_SOURCES = CONFIG.get('excluded_event_sources', [])
EXCLUDED_EVENTS = CONFIG.get('excluded_event_names', [])
CRITICAL_SERVICES = CONFIG.get('critical_services', [])
HIGH_EVENTS = CONFIG.get('high_event_names', [])
WRITE_PREFIXES = ['Create', 'Delete', 'Update', 'Put', 'Modify', 'Add', 'Remove', 'Attach', 'Detach', 'Enable', 'Disable', 'Start', 'Stop', 'Terminate', 'Run', 'Register', 'Deregister', 'Set', 'Revoke', 'Grant', 'Tag', 'Untag', 'Authorize', 'Import', 'Allocate', 'Release', 'Reboot', 'Apply', 'Associate', 'Disassociate']


def is_write_event(event):
    """True if the event mutates resources."""
    if event.get('readOnly') is True:
        return False
    if event.get('readOnly') is False:
        return True
    name = event.get('eventName', '')
    return any((name.startswith(p) for p in WRITE_PREFIXES))


def should_skip(event):
    """True if the event should be ignored entirely."""
    identity = event.get('userIdentity', {})
    if identity.get('type') == 'AWSService':
        return True
    if identity.get('invokedBy', '').endswith('.amazonaws.com'):
        return True
    arn = identity.get('sessionContext', {}).get('sessionIssuer', {}).get('arn', '')
    if 'aws-service-role' in arn:
        return True
    if event.get('eventSource', '') in EXCLUDED_SOURCES:
        return True
    if event.get('eventName', '') in EXCLUDED_EVENTS:
        return True
    if event.get('errorCode'):
        return True
    return False


def name_matches(name, patterns):
    """Case-insensitive wildcard match against the whole name."""
    name = (name or '').lower()
    return any((fnmatch.fnmatchcase(name, p.lower()) for p in patterns))


def is_iac_change(event):
    """Return (is_iac, method). Default is lenient: any one check matching = IaC."""
    ua = event.get('userAgent', '').lower()
    ua_ok = any((iac_ua in ua for iac_ua in IAC_USER_AGENTS))
    identity = event.get('userIdentity', {})
    issuer = identity.get('sessionContext', {}).get('sessionIssuer', {})
    role_name = issuer.get('userName', '')
    user_name = identity.get('userName', '')
    principal = identity.get('principalId', '')
    session_name = principal.split(':')[-1] if ':' in principal else ''
    role_hit = next((n for n in (role_name, user_name, session_name) if n and name_matches(n, IAC_ROLE_PATTERNS)), None)
    role_ok = role_hit is not None
    src_ip = event.get('sourceIPAddress', '')
    ip_ok = src_ip in IAC_SOURCE_IPS
    if STRICT_IAC:
        if ua_ok and role_ok:
            return (True, f'strict:user_agent+role={role_hit}')
        return (False, 'none')
    if ua_ok:
        return (True, 'user_agent')
    if role_ok:
        return (True, f'role_match={role_hit}')
    if ip_ok:
        return (True, f'source_ip={src_ip}')
    return (False, 'none')


def change_source(event):
    """Label how the change was made."""
    ua = event.get('userAgent', '').lower()
    if 'console.amazonaws.com' in ua or 'mozilla' in ua:
        return 'console'
    if 'aws-cli' in ua:
        return 'cli'
    if 'boto' in ua or 'aws-sdk' in ua:
        return 'sdk'
    return 'other'


def get_severity(event):
    name = event.get('eventName', '')
    source = event.get('eventSource', '')
    if name in HIGH_EVENTS:
        return 'CRITICAL'
    if source in CRITICAL_SERVICES:
        return 'HIGH'
    if name.startswith('Delete') or name.startswith('Terminate'):
        return 'MEDIUM'
    return 'LOW'


def get_resource_name(event):
    params = event.get('requestParameters') or {}
    if not isinstance(params, dict):
        return ''
    for key in ['instanceId', 'bucketName', 'functionName', 'tableName', 'roleName', 'userName', 'groupName', 'policyName', 'name', 'dbInstanceIdentifier', 'securityGroupId', 'groupId']:
        if key in params:
            val = params[key]
            if isinstance(val, list):
                return str(val[0]) if val else ''
            return str(val)
    return ''


def send_sns_alert(finding):
    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
    message = f"{emoji.get(finding['severity'], '⚪')} NON-IAC CHANGE DETECTED\n\nSeverity:   {finding['severity']}\nAccount:    {finding['account_id']}\nRegion:     {finding['region']}\nService:    {finding['event_source']}\nAction:     {finding['event_name']}\nVia:        {finding['change_source']}\nUser:       {finding['user_name']}\nUser ARN:   {finding['user_arn']}\nSource IP:  {finding['source_ip']}\nUser Agent: {finding['user_agent'][:100]}\nResource:   {finding['resource_name']}\nTime (UTC): {finding['event_time']}\n"
    sns.publish(TopicArn=SNS_TOPIC, Subject=f"[{finding['severity']}] Non-IaC: {finding['event_name']}"[:100], Message=message)


def account_prefix(account_id):
    base = f'{CT_PREFIX}/' if CT_PREFIX else ''
    if ORG_ID:
        return f'{base}AWSLogs/{ORG_ID}/{account_id}/'
    return f'{base}AWSLogs/{account_id}/'


def list_regions(account_id):
    """Yield region prefixes to scan.
    If SCAN_REGIONS is set, only those regions are scanned (no S3 listing needed).
    Otherwise every region folder found under CloudTrail/ is scanned.
    """
    base = f"{account_prefix(account_id)}CloudTrail/"
    if SCAN_REGIONS:
        for region in SCAN_REGIONS:
            prefix = f"{base}{region}/"
            logger.info("REGION_CONFIGURED account=%s prefix=%s", account_id, prefix)
            yield prefix
        return
    logger.info("LIST_REGIONS bucket=%s account=%s prefix=%s", CT_BUCKET, account_id, base)
    found = 0
    for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=CT_BUCKET, Prefix=base, Delimiter="/"
    ):
        for cp in page.get("CommonPrefixes", []):
            found += 1
            logger.info("REGION_FOUND prefix=%s", cp["Prefix"])
            yield cp["Prefix"]
    if not found:
        logger.warning("NO_REGIONS account=%s prefix=%s; check account/path", account_id, base)


def list_keys_for_day(region_prefix, day):
    prefix = f"{region_prefix}{day:%Y/%m/%d}/"
    logger.info("LIST_DAY bucket=%s prefix=%s", CT_BUCKET, prefix)
    objects = 0
    matched = 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=CT_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            objects += 1
            if obj["Key"].endswith(".json.gz"):
                matched += 1
                logger.debug("FILE key=%s bytes=%s", obj["Key"], obj.get("Size"))
                yield obj["Key"]
    logger.info("DAY_FILES prefix=%s objects=%s matching_logs=%s", prefix, objects, matched)


def dedupe_finding_key(event):
    """Stable identifier only; this implementation does not deduplicate alerts."""
    account_id = event.get('recipientAccountId', 'unknown')
    event_id = event.get('eventID', '')
    event_time = event.get('eventTime', '')
    return hashlib.sha256(f'{account_id}:{event_id}:{event_time}'.encode()).hexdigest()[:32]


def process_event(ct_event, stats, findings, target):
    stats['total'] += 1
    if ct_event.get('eventTime', '')[:10] != target.isoformat():
        stats['out_of_window'] += 1
        return
    if ct_event.get('recipientAccountId') not in ACCOUNT_IDS:
        stats['skipped'] += 1
        return
    if not is_write_event(ct_event) or should_skip(ct_event):
        stats['skipped'] += 1
        return
    is_iac, method = is_iac_change(ct_event)
    if is_iac:
        stats['iac'] += 1
        return
    stats['non_iac'] += 1
    severity = get_severity(ct_event)
    identity = ct_event.get('userIdentity', {})
    finding = {'finding_id': dedupe_finding_key(ct_event), 'event_time': ct_event.get('eventTime', ''), 'account_id': ct_event.get('recipientAccountId', 'unknown'), 'region': ct_event.get('awsRegion', ''), 'event_source': ct_event.get('eventSource', ''), 'event_name': ct_event.get('eventName', ''), 'severity': severity, 'change_source': change_source(ct_event), 'user_arn': identity.get('arn', ''), 'user_name': identity.get('userName', identity.get('principalId', 'unknown')), 'user_type': identity.get('type', ''), 'source_ip': ct_event.get('sourceIPAddress', ''), 'user_agent': ct_event.get('userAgent', '')[:200], 'resource_name': get_resource_name(ct_event), 'is_iac': False}
    logger.info("NON_IAC account=%s action=%s region=%s severity=%s source=%s", finding["account_id"], finding["event_name"], finding["region"], severity, finding["change_source"])
    if DRY_RUN:
        return
    if severity in ('CRITICAL', 'HIGH'):
        try:
            send_sns_alert(finding)
            logger.info("SNS_SENT finding_id=%s", finding["finding_id"])
        except Exception:
            logger.exception("SNS_FAILED finding_id=%s", finding["finding_id"])
            raise


def lambda_handler(event, context):
    if isinstance(event, dict) and event.get('date'):
        target = datetime.strptime(event['date'], '%Y-%m-%d').date()
    else:
        target = (datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)).date()
    logger.info("SCAN_START target_date=%s bucket=%s accounts=%s org_id=%s custom_prefix=%s regions=%s dry_run=%s", target.isoformat(), CT_BUCKET, ACCOUNT_IDS, ORG_ID, CT_PREFIX, SCAN_REGIONS or 'ALL', DRY_RUN)
    if not CT_BUCKET or not ACCOUNT_IDS:
        raise ValueError('CLOUDTRAIL_BUCKET and ACCOUNT_IDS must be set')
    if CT_BUCKET.startswith(("arn:", "s3://")) or "/" in CT_BUCKET:
        raise ValueError("CLOUDTRAIL_BUCKET must be the bucket name only")
    if any(len(a) != 12 or not a.isdigit() for a in ACCOUNT_IDS):
        raise ValueError("ACCOUNT_IDS must contain comma-separated 12-digit AWS account IDs, not a wildcard")
    if not DRY_RUN and (not SNS_TOPIC):
        raise ValueError('SNS_TOPIC_ARN is required when DRY_RUN=false')
    folders = [target]
    if INCLUDE_NEXT_DAY_FOLDER:
        folders.append(target + timedelta(days=1))
    findings = []
    stats = {'total': 0, 'skipped': 0, 'iac': 0, 'non_iac': 0, 'out_of_window': 0, 'files': 0}
    for account_id in ACCOUNT_IDS:
        for region_prefix in list_regions(account_id):
            for day in folders:
                for key in list_keys_for_day(region_prefix, day):
                    stats['files'] += 1
                    try:
                        obj = s3.get_object(Bucket=CT_BUCKET, Key=key)
                        data = json.loads(gzip.decompress(obj['Body'].read()))
                    except Exception:
                        logger.exception("FILE_READ_FAILED bucket=%s key=%s", CT_BUCKET, key)
                        raise
                    for ct_event in data.get('Records', []):
                        process_event(ct_event, stats, findings, target)
    logger.info("SCAN_COMPLETE target_date=%s stats=%s", target.isoformat(), json.dumps(stats))
    if stats["files"] == 0:
        logger.warning("NO_FILES: verify logged S3 prefixes and target date against an actual object key")
    return stats
```
