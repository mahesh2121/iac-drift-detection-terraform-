"""
CloudTrail Non-IaC Change Detector
- Scheduled (EventBridge) batch run on the PREVIOUS day's CloudTrail logs (UTC)
- Reads only allow-listed AWS accounts (POC)
- Read-only on the CloudTrail bucket (list + get)
- Alerts: SNS + Microsoft Teams (Workflows webhook), storage: DynamoDB
"""

import json
import gzip
import os
import fnmatch
import hashlib
import urllib3
from datetime import datetime, timezone, timedelta

import boto3

# ═══════════════════════════════════════
# CLIENTS
# ═══════════════════════════════════════

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')
cw = boto3.client('cloudwatch')
http = urllib3.PoolManager()

# ═══════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════

CONFIG = json.loads(os.environ.get('DETECTOR_CONFIG', '{}'))

CT_BUCKET = os.environ.get('CLOUDTRAIL_BUCKET', '')
# Comma-separated allow-list, e.g. "111111111111,222222222222"
ACCOUNT_IDS = [a.strip() for a in os.environ.get('ACCOUNT_IDS', '').split(',') if a.strip()]
# Leave empty for a normal trail; "o-xxxxxxxxxx" for an organization trail
ORG_ID = os.environ.get('ORG_ID', '').strip()

DAYS_BACK = int(os.environ.get('DAYS_BACK', '1'))            # 1 = yesterday
INCLUDE_NEXT_DAY_FOLDER = os.environ.get('INCLUDE_NEXT_DAY_FOLDER', 'true').lower() == 'true'
STRICT_IAC = os.environ.get('STRICT_IAC', 'false').lower() == 'true'   # true = user agent AND role must match
DRY_RUN = os.environ.get('DRY_RUN', 'false').lower() == 'true'

TABLE_NAME = os.environ.get('DYNAMODB_TABLE', '')
SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN', '')
TEAMS_WEBHOOK_URL = os.environ.get('TEAMS_WEBHOOK_URL', '')
TTL_DAYS = int(os.environ.get('TTL_DAYS', '90'))

IAC_USER_AGENTS = [ua.lower() for ua in CONFIG.get('iac_user_agents', [])]
IAC_ROLE_PATTERNS = CONFIG.get('iac_role_patterns', [])
IAC_SOURCE_IPS = CONFIG.get('iac_source_ips', [])
EXCLUDED_SOURCES = CONFIG.get('excluded_event_sources', [])
EXCLUDED_EVENTS = CONFIG.get('excluded_event_names', [])
CRITICAL_SERVICES = CONFIG.get('critical_services', [])
HIGH_EVENTS = CONFIG.get('high_event_names', [])

WRITE_PREFIXES = [
    'Create', 'Delete', 'Update', 'Put', 'Modify',
    'Add', 'Remove', 'Attach', 'Detach', 'Enable',
    'Disable', 'Start', 'Stop', 'Terminate', 'Run',
    'Register', 'Deregister', 'Set', 'Revoke', 'Grant',
    'Tag', 'Untag', 'Authorize', 'Import', 'Allocate',
    'Release', 'Reboot', 'Apply', 'Associate', 'Disassociate',
]


# ═══════════════════════════════════════
# DETECTION
# ═══════════════════════════════════════

def is_write_event(event):
    """True if the event mutates resources."""
    if event.get('readOnly') is True:
        return False
    if event.get('readOnly') is False:
        return True
    name = event.get('eventName', '')
    return any(name.startswith(p) for p in WRITE_PREFIXES)


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
    return any(fnmatch.fnmatchcase(name, p.lower()) for p in patterns)


def is_iac_change(event):
    """Return (is_iac, method). Default is lenient: any one check matching = IaC."""
    ua = event.get('userAgent', '').lower()
    ua_ok = any(iac_ua in ua for iac_ua in IAC_USER_AGENTS)

    identity = event.get('userIdentity', {})
    issuer = identity.get('sessionContext', {}).get('sessionIssuer', {})
    role_name = issuer.get('userName', '')
    user_name = identity.get('userName', '')
    principal = identity.get('principalId', '')
    session_name = principal.split(':')[-1] if ':' in principal else ''

    role_hit = next((n for n in (role_name, user_name, session_name)
                     if n and name_matches(n, IAC_ROLE_PATTERNS)), None)
    role_ok = role_hit is not None

    src_ip = event.get('sourceIPAddress', '')
    ip_ok = src_ip in IAC_SOURCE_IPS

    if STRICT_IAC:
        if ua_ok and role_ok:
            return True, f"strict:user_agent+role={role_hit}"
        return False, "none"

    if ua_ok:
        return True, "user_agent"
    if role_ok:
        return True, f"role_match={role_hit}"
    if ip_ok:
        return True, f"source_ip={src_ip}"
    return False, "none"


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
    for key in ['instanceId', 'bucketName', 'functionName',
                'tableName', 'roleName', 'userName', 'groupName',
                'policyName', 'name', 'dbInstanceIdentifier',
                'securityGroupId', 'groupId']:
        if key in params:
            val = params[key]
            if isinstance(val, list):
                return str(val[0]) if val else ''
            return str(val)
    return ''


# ═══════════════════════════════════════
# STORAGE & ALERTING
# ═══════════════════════════════════════

def store_finding(finding):
    """Store a finding once and return whether it was newly stored."""
    table = dynamodb.Table(TABLE_NAME)
    try:
        table.put_item(
            Item=finding,
            ConditionExpression='attribute_not_exists(finding_id)',
        )
        return True
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def send_sns_alert(finding):
    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}
    message = (
        f"{emoji.get(finding['severity'], '⚪')} NON-IAC CHANGE DETECTED\n\n"
        f"Severity:   {finding['severity']}\n"
        f"Account:    {finding['account_id']}\n"
        f"Region:     {finding['region']}\n"
        f"Service:    {finding['event_source']}\n"
        f"Action:     {finding['event_name']}\n"
        f"Via:        {finding['change_source']}\n"
        f"User:       {finding['user_name']}\n"
        f"User ARN:   {finding['user_arn']}\n"
        f"Source IP:  {finding['source_ip']}\n"
        f"User Agent: {finding['user_agent'][:100]}\n"
        f"Resource:   {finding['resource_name']}\n"
        f"Time (UTC): {finding['event_time']}\n"
    )
    sns.publish(
        TopicArn=SNS_TOPIC,
        Subject=f"[{finding['severity']}] Non-IaC: {finding['event_name']}"[:100],
        Message=message,
    )


def send_teams_alert(finding):
    """Post an Adaptive Card to a Microsoft Teams Workflows webhook."""
    if not TEAMS_WEBHOOK_URL:
        return

    sev = finding['severity']
    color = {'CRITICAL': 'Attention', 'HIGH': 'Warning',
             'MEDIUM': 'Warning', 'LOW': 'Accent'}.get(sev, 'Default')
    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(sev, '⚪')

    facts = [
        {'title': 'Account',    'value': finding['account_id']},
        {'title': 'Region',     'value': finding['region']},
        {'title': 'Service',    'value': finding['event_source']},
        {'title': 'Action',     'value': finding['event_name']},
        {'title': 'Via',        'value': finding['change_source']},
        {'title': 'User',       'value': finding['user_name']},
        {'title': 'Source IP',  'value': finding['source_ip']},
        {'title': 'Resource',   'value': finding['resource_name'] or 'N/A'},
        {'title': 'User Agent', 'value': finding['user_agent'][:80]},
        {'title': 'Time (UTC)', 'value': finding['event_time']},
    ]

    payload = {
        'type': 'message',
        'attachments': [{
            'contentType': 'application/vnd.microsoft.card.adaptive',
            'contentUrl': None,
            'content': {
                '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'type': 'AdaptiveCard',
                'version': '1.4',
                'body': [
                    {'type': 'TextBlock', 'size': 'Medium', 'weight': 'Bolder',
                     'color': color, 'wrap': True,
                     'text': f"{emoji} Non-IaC Change [{sev}]"},
                    {'type': 'FactSet', 'facts': facts},
                ],
            },
        }],
    }

    try:
        resp = http.request(
            'POST', TEAMS_WEBHOOK_URL,
            body=json.dumps(payload).encode(),
            headers={'Content-Type': 'application/json'},
            timeout=10.0,
        )
        if resp.status not in (200, 202):
            print(f"Teams error: HTTP {resp.status} {resp.data[:200]}")
    except Exception as e:
        print(f"Teams error: {e}")


def publish_metrics(findings):
    if not findings:
        return
    now = datetime.now(timezone.utc)
    metrics = [{
        'MetricName': 'NonIaCChanges',
        'Value': len(findings),
        'Unit': 'Count',
        'Timestamp': now,
    }]
    sev_counts = {}
    for f in findings:
        sev_counts[f['severity']] = sev_counts.get(f['severity'], 0) + 1
    for sev, count in sev_counts.items():
        metrics.append({
            'MetricName': 'NonIaCChanges',
            'Dimensions': [{'Name': 'Severity', 'Value': sev}],
            'Value': count,
            'Unit': 'Count',
            'Timestamp': now,
        })
    cw.put_metric_data(Namespace='NonIaCDetector', MetricData=metrics)


# ═══════════════════════════════════════
# S3 LISTING (read-only, allow-listed accounts, one day)
# ═══════════════════════════════════════

def account_prefix(account_id):
    if ORG_ID:
        return f"AWSLogs/{ORG_ID}/{account_id}/"
    return f"AWSLogs/{account_id}/"


def list_regions(account_id):
    """Regions with CloudTrail logs for ONE allow-listed account."""
    prefix = f"{account_prefix(account_id)}CloudTrail/"
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=CT_BUCKET, Prefix=prefix, Delimiter='/'):
        for cp in page.get('CommonPrefixes', []):
            yield cp['Prefix']


def list_keys_for_day(region_prefix, day):
    """Only the given day's folder is listed."""
    prefix = f"{region_prefix}{day:%Y/%m/%d}/"
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=CT_BUCKET, Prefix=prefix):
        for obj in page.get('Contents', []):
            if obj['Key'].endswith('.json.gz'):
                yield obj['Key']


# ═══════════════════════════════════════
# EVENT PROCESSING
# ═══════════════════════════════════════

def dedupe_finding_key(event):
    """Unique per account+event so duplicates are only skipped within the same account."""
    account_id = event.get('recipientAccountId', 'unknown')
    event_id = event.get('eventID', '')
    event_time = event.get('eventTime', '')
    return hashlib.sha256(f"{account_id}:{event_id}:{event_time}".encode()).hexdigest()[:32]


def process_event(ct_event, stats, findings, target):
    stats['total'] += 1

    # Exact day check on the event's own UTC timestamp
    if ct_event.get('eventTime', '')[:10] != target.isoformat():
        stats['out_of_window'] += 1
        return

    # Safety net: only allow-listed accounts
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

    finding = {
        'finding_id': dedupe_finding_key(ct_event),
        'event_time': ct_event.get('eventTime', ''),
        'account_id': ct_event.get('recipientAccountId', 'unknown'),
        'region': ct_event.get('awsRegion', ''),
        'event_source': ct_event.get('eventSource', ''),
        'event_name': ct_event.get('eventName', ''),
        'severity': severity,
        'change_source': change_source(ct_event),
        'user_arn': identity.get('arn', ''),
        'user_name': identity.get('userName', identity.get('principalId', 'unknown')),
        'user_type': identity.get('type', ''),
        'source_ip': ct_event.get('sourceIPAddress', ''),
        'user_agent': ct_event.get('userAgent', '')[:200],
        'resource_name': get_resource_name(ct_event),
        'is_iac': False,
        'ttl': int((datetime.now(timezone.utc) + timedelta(days=TTL_DAYS)).timestamp()),
    }
    findings.append(finding)

    print(f"NON-IAC [{severity}] {finding['event_name']} by {finding['user_name']} "
          f"via {finding['change_source']} from {finding['source_ip']}")

    if DRY_RUN:
        return

    try:
        store_finding(finding)
    except Exception as e:
        print(f"DynamoDB error: {e}")

    if severity in ('CRITICAL', 'HIGH'):
        try:
            send_sns_alert(finding)
        except Exception as e:
            print(f"SNS error: {e}")
        send_teams_alert(finding)   # handles its own errors


# ═══════════════════════════════════════
# LAMBDA HANDLER (EventBridge schedule)
# ═══════════════════════════════════════

def lambda_handler(event, context):
    # Optional manual override for testing/backfill: {"date": "2026-10-11"}
    if isinstance(event, dict) and event.get('date'):
        target = datetime.strptime(event['date'], '%Y-%m-%d').date()
    else:
        target = (datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)).date()

    print(f"Run day: {datetime.now(timezone.utc):%A %Y-%m-%d} -> scanning "
          f"{target:%A %Y-%m-%d} (UTC), accounts={ACCOUNT_IDS}, "
          f"dry_run={DRY_RUN}, strict_iac={STRICT_IAC}")

    if not CT_BUCKET or not ACCOUNT_IDS:
        raise ValueError("CLOUDTRAIL_BUCKET and ACCOUNT_IDS must be set")

    # Late-delivered files for the target day can sit in the next day's folder;
    # the eventTime check in process_event discards anything not on the target day.
    folders = [target]
    if INCLUDE_NEXT_DAY_FOLDER:
        folders.append(target + timedelta(days=1))

    findings = []
    stats = {'total': 0, 'skipped': 0, 'iac': 0, 'non_iac': 0,
             'out_of_window': 0, 'files': 0}

    for account_id in ACCOUNT_IDS:
        for region_prefix in list_regions(account_id):
            for day in folders:
                for key in list_keys_for_day(region_prefix, day):
                    stats['files'] += 1
                    try:
                        obj = s3.get_object(Bucket=CT_BUCKET, Key=key)   # read only
                        data = json.loads(gzip.decompress(obj['Body'].read()))
                    except Exception as e:
                        print(f"Error reading {key}: {e}")
                        continue
                    for ct_event in data.get('Records', []):
                        process_event(ct_event, stats, findings, target)

    if not DRY_RUN:
        try:
            publish_metrics(findings)
        except Exception as e:
            print(f"Metrics error: {e}")

    print(f"Stats: {json.dumps(stats)}")
    return stats