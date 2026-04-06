"""
CloudTrail Non-IaC Change Detector
Single Account Version - Simplified for Testing
"""

import json
import gzip
import os
import re
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
TABLE_NAME = os.environ.get('DYNAMODB_TABLE', '')
SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN', '')
TTL_DAYS = int(os.environ.get('TTL_DAYS', '90'))

IAC_USER_AGENTS = [ua.lower() for ua in CONFIG.get('iac_user_agents', [])]
IAC_ROLE_PATTERNS = CONFIG.get('iac_role_patterns', [])
IAC_SOURCE_IPS = CONFIG.get('iac_source_ips', [])
EXCLUDED_SOURCES = CONFIG.get('excluded_event_sources', [])
EXCLUDED_EVENTS = CONFIG.get('excluded_event_names', [])
CRITICAL_SERVICES = CONFIG.get('critical_services', [])
HIGH_EVENTS = CONFIG.get('high_event_names', [])
SLACK_URL = CONFIG.get('slack_webhook_url', '')

# Write event prefixes
WRITE_PREFIXES = [
    'Create', 'Delete', 'Update', 'Put', 'Modify',
    'Add', 'Remove', 'Attach', 'Detach', 'Enable',
    'Disable', 'Start', 'Stop', 'Terminate', 'Run',
    'Register', 'Deregister', 'Set', 'Revoke', 'Grant',
    'Tag', 'Untag', 'Authorize', 'Import', 'Allocate',
    'Release', 'Reboot', 'Apply', 'Associate', 'Disassociate',
]


# ═══════════════════════════════════════
# DETECTION FUNCTIONS
# ═══════════════════════════════════════

def is_write_event(event):
    """Check if event mutates resources."""
    if event.get('readOnly') is True:
        return False
    if event.get('readOnly') is False:
        return True
    name = event.get('eventName', '')
    return any(name.startswith(p) for p in WRITE_PREFIXES)


def should_skip(event):
    """Check if event should be skipped entirely."""
    # AWS internal
    identity = event.get('userIdentity', {})
    if identity.get('type') == 'AWSService':
        return True
    invoked = identity.get('invokedBy', '')
    if invoked.endswith('.amazonaws.com'):
        return True
    # Service-linked roles
    arn = identity.get('sessionContext', {}).get(
        'sessionIssuer', {}).get('arn', '')
    if 'aws-service-role' in arn:
        return True
    # Excluded source
    if event.get('eventSource', '') in EXCLUDED_SOURCES:
        return True
    # Excluded event name
    if event.get('eventName', '') in EXCLUDED_EVENTS:
        return True
    # Failed calls
    if event.get('errorCode'):
        return True
    return False


def is_iac_change(event):
    """
    Determine if event was made by IaC tool.
    Returns (is_iac, method)
    """
    # ── CHECK 1: User Agent ──
    ua = event.get('userAgent', '').lower()
    for iac_ua in IAC_USER_AGENTS:
        if iac_ua in ua:
            return True, f"user_agent:{iac_ua}"

    # ── CHECK 2: IAM Role Name ──
    identity = event.get('userIdentity', {})
    session = identity.get('sessionContext', {})
    issuer = session.get('sessionIssuer', {})
    role_name = issuer.get('userName', '')
    user_name = identity.get('userName', '')

    # Session name (assumed role session)
    principal = identity.get('principalId', '')
    session_name = principal.split(':')[-1] if ':' in principal else ''

    names_to_check = [role_name, user_name, session_name]
    for pattern in IAC_ROLE_PATTERNS:
        regex = pattern.replace('*', '.*')
        for name in names_to_check:
            if name and re.match(regex, name, re.IGNORECASE):
                return True, f"role_match:{pattern}={name}"

    # ── CHECK 3: Source IP ──
    src_ip = event.get('sourceIPAddress', '')
    if src_ip in IAC_SOURCE_IPS:
        return True, f"source_ip:{src_ip}"

    return False, "none"


def get_severity(event):
    """Determine finding severity."""
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
    """Extract resource name from event."""
    params = event.get('requestParameters') or {}
    if not isinstance(params, dict):
        return ''
    for key in ['instanceId', 'bucketName', 'functionName',
                'tableName', 'roleName', 'userName', 'groupName',
                'policyName', 'name', 'dbInstanceIdentifier',
                'securityGroupId', 'groupId', 'groupName']:
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
    """Store finding in DynamoDB."""
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(Item=finding)


def send_sns_alert(finding):
    """Send SNS alert."""
    emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}

    message = (
        f"{emoji.get(finding['severity'], '⚪')} NON-IAC CHANGE DETECTED\n\n"
        f"Severity:  {finding['severity']}\n"
        f"Account:   {finding['account_id']}\n"
        f"Region:    {finding['region']}\n"
        f"Service:   {finding['event_source']}\n"
        f"Action:    {finding['event_name']}\n"
        f"User:      {finding['user_name']}\n"
        f"User ARN:  {finding['user_arn']}\n"
        f"Source IP: {finding['source_ip']}\n"
        f"User Agent: {finding['user_agent'][:100]}\n"
        f"Resource:  {finding['resource_name']}\n"
        f"Time:      {finding['event_time']}\n"
    )

    sns.publish(
        TopicArn=SNS_TOPIC,
        Subject=f"[{finding['severity']}] Non-IaC: {finding['event_name']}"[:100],
        Message=message,
    )


def send_slack_alert(finding):
    """Send Slack alert."""
    if not SLACK_URL:
        return

    colors = {'CRITICAL': '#FF0000', 'HIGH': '#FF8C00',
              'MEDIUM': '#FFD700', 'LOW': '#4169E1'}

    payload = {
        'attachments': [{
            'color': colors.get(finding['severity'], '#808080'),
            'title': f"🚨 Non-IaC Change [{finding['severity']}]",
            'fields': [
                {'title': 'Account', 'value': finding['account_id'], 'short': True},
                {'title': 'Region', 'value': finding['region'], 'short': True},
                {'title': 'Service', 'value': finding['event_source'], 'short': True},
                {'title': 'Action', 'value': finding['event_name'], 'short': True},
                {'title': 'User', 'value': finding['user_name'], 'short': True},
                {'title': 'Source IP', 'value': finding['source_ip'], 'short': True},
                {'title': 'Resource', 'value': finding['resource_name'] or 'N/A', 'short': True},
                {'title': 'User Agent', 'value': finding['user_agent'][:80], 'short': True},
            ],
            'footer': 'Non-IaC Detector',
        }]
    }

    try:
        http.request('POST', SLACK_URL,
                     body=json.dumps(payload).encode(),
                     headers={'Content-Type': 'application/json'})
    except Exception as e:
        print(f"Slack error: {e}")


def publish_metrics(findings):
    """Publish CloudWatch metrics."""
    if not findings:
        return

    metrics = []
    now = datetime.now(timezone.utc)

    # Total
    metrics.append({
        'MetricName': 'NonIaCChanges',
        'Value': len(findings),
        'Unit': 'Count',
        'Timestamp': now,
    })

    # By severity
    sev_counts = {}
    for f in findings:
        s = f['severity']
        sev_counts[s] = sev_counts.get(s, 0) + 1

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
# LAMBDA HANDLER
# ═══════════════════════════════════════

def lambda_handler(event, context):
    """Main handler - triggered by SQS."""

    print(f"Processing {len(event.get('Records', []))} SQS messages")

    findings = []
    stats = {'total': 0, 'skipped': 0, 'iac': 0, 'non_iac': 0}

    for sqs_record in event.get('Records', []):
        try:
            body = json.loads(sqs_record['body'])

            # Parse S3 event
            for s3_record in body.get('Records', []):
                bucket = s3_record.get('s3', {}).get('bucket', {}).get('name')
                key = s3_record.get('s3', {}).get('object', {}).get('key')

                if not bucket or not key:
                    continue

                print(f"Processing s3://{bucket}/{key}")

                # Read CloudTrail log
                try:
                    obj = s3.get_object(Bucket=bucket, Key=key)
                    data = json.loads(gzip.decompress(obj['Body'].read()))
                except Exception as e:
                    print(f"Error reading {key}: {e}")
                    continue

                for ct_event in data.get('Records', []):
                    stats['total'] += 1

                    # ── FILTER ──
                    if not is_write_event(ct_event):
                        stats['skipped'] += 1
                        continue

                    if should_skip(ct_event):
                        stats['skipped'] += 1
                        continue

                    # ── IAC CHECK ──
                    is_iac, method = is_iac_change(ct_event)

                    if is_iac:
                        stats['iac'] += 1
                        print(f"IaC change: {ct_event['eventName']} by {method}")
                        continue

                    # ── NON-IAC FOUND ──
                    stats['non_iac'] += 1
                    severity = get_severity(ct_event)

                    identity = ct_event.get('userIdentity', {})
                    finding = {
                        'finding_id': hashlib.sha256(
                            f"{ct_event.get('eventID', '')}{ct_event.get('eventTime', '')}".encode()
                        ).hexdigest()[:32],
                        'event_time': ct_event.get('eventTime', ''),
                        'account_id': ct_event.get('recipientAccountId', 'unknown'),
                        'region': ct_event.get('awsRegion', ''),
                        'event_source': ct_event.get('eventSource', ''),
                        'event_name': ct_event.get('eventName', ''),
                        'severity': severity,
                        'user_arn': identity.get('arn', ''),
                        'user_name': identity.get('userName',
                                     identity.get('principalId', 'unknown')),
                        'user_type': identity.get('type', ''),
                        'source_ip': ct_event.get('sourceIPAddress', ''),
                        'user_agent': ct_event.get('userAgent', '')[:200],
                        'resource_name': get_resource_name(ct_event),
                        'is_iac': False,
                        'ttl': int((datetime.now(timezone.utc) +
                                   timedelta(days=TTL_DAYS)).timestamp()),
                    }

                    # Store
                    try:
                        store_finding(finding)
                    except Exception as e:
                        print(f"DynamoDB error: {e}")

                    findings.append(finding)

                    print(f"🚨 NON-IAC [{severity}]: {finding['event_name']} "
                          f"by {finding['user_name']} from {finding['source_ip']}")

                    # Alert for HIGH+
                    if severity in ('CRITICAL', 'HIGH'):
                        try:
                            send_sns_alert(finding)
                            send_slack_alert(finding)
                        except Exception as e:
                            print(f"Alert error: {e}")

        except Exception as e:
            print(f"SQS record error: {e}")

    # Metrics
    try:
        publish_metrics(findings)
    except Exception as e:
        print(f"Metrics error: {e}")

    print(f"Stats: {json.dumps(stats)}")
    return stats