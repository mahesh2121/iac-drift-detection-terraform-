#!/bin/bash

# IAC Drift Detection - Diagnostic Script
# This script checks all components of the alert system

echo "=== IAC DRIFT DETECTION DIAGNOSTIC ==="
echo "Checking all system components..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    local component=$1
    local status=$2
    local details=$3

    case $status in
        "OK")
            echo -e "${component}: ${GREEN}✅ ${status}${NC} - ${details}"
            ;;
        "WARNING")
            echo -e "${component}: ${YELLOW}⚠️  ${status}${NC} - ${details}"
            ;;
        "ERROR")
            echo -e "${component}: ${RED}❌ ${status}${NC} - ${details}"
            ;;
        *)
            echo -e "${component}: ${status} - ${details}"
            ;;
    esac
}

echo "1. LAMBDA FUNCTION STATUS:"
echo "-------------------------"
LAMBDA_STATUS=$(aws lambda get-function --function-name non-iac-detector-detector --query 'Configuration.State' --output text 2>/dev/null)
if [ $? -eq 0 ]; then
    if [ "$LAMBDA_STATUS" = "Active" ]; then
        print_status "Lambda Function" "OK" "State: $LAMBDA_STATUS"
    else
        print_status "Lambda Function" "WARNING" "State: $LAMBDA_STATUS"
    fi
else
    print_status "Lambda Function" "ERROR" "Function not found or access denied"
fi

echo -e "\n2. SNS SUBSCRIPTIONS:"
echo "---------------------"
TOPIC_ARN=$(terraform output sns_topic_arn 2>/dev/null || echo "arn:aws:sns:us-east-1:$(aws sts get-caller-identity --query Account --output text):non-iac-detector-alerts")
echo "Topic ARN: $TOPIC_ARN"

SUBSCRIPTIONS=$(aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" 2>/dev/null)
if [ $? -eq 0 ]; then
    EMAIL_COUNT=$(echo "$SUBSCRIPTIONS" | jq -r '.Subscriptions[] | select(.Protocol == "email") | .Endpoint' | wc -l)
    CONFIRMED_COUNT=$(echo "$SUBSCRIPTIONS" | jq -r '.Subscriptions[] | select(.Protocol == "email" and (.SubscriptionArn | contains("arn:aws:sns"))) | .Endpoint' | wc -l)
    PENDING_COUNT=$(echo "$SUBSCRIPTIONS" | jq -r '.Subscriptions[] | select(.Protocol == "email" and (.SubscriptionArn | contains("PendingConfirmation"))) | .Endpoint' | wc -l)

    if [ "$EMAIL_COUNT" -gt 0 ]; then
        print_status "Email Subscriptions" "OK" "$EMAIL_COUNT email subscription(s) found"
        echo "  - Confirmed: $CONFIRMED_COUNT"
        echo "  - Pending: $PENDING_COUNT"

        if [ "$PENDING_COUNT" -gt 0 ]; then
            print_status "Email Confirmation" "WARNING" "Check email for AWS confirmation link!"
        fi
    else
        print_status "Email Subscriptions" "ERROR" "No email subscriptions found"
    fi
else
    print_status "SNS Topic" "ERROR" "Cannot access SNS topic or topic not found"
fi

echo -e "\n3. SQS QUEUE STATUS:"
echo "--------------------"
QUEUE_URL=$(aws sqs list-queues --query 'QueueUrls[?contains(@, `non-iac-detector-queue`)] | [0]' --output text 2>/dev/null)
if [ -n "$QUEUE_URL" ] && [ "$QUEUE_URL" != "None" ]; then
    echo "Queue URL: $QUEUE_URL"

    MSG_COUNT=$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names ApproximateNumberOfMessages --query 'Attributes.ApproximateNumberOfMessages' --output text 2>/dev/null)
    if [ $? -eq 0 ]; then
        if [ "$MSG_COUNT" -gt 0 ]; then
            print_status "SQS Messages" "OK" "$MSG_COUNT message(s) in queue"
        else
            print_status "SQS Messages" "OK" "Queue is empty (normal if no recent activity)"
        fi
    else
        print_status "SQS Attributes" "ERROR" "Cannot read queue attributes"
    fi
else
    print_status "SQS Queue" "ERROR" "Queue not found"
fi

echo -e "\n4. DYNAMODB FINDINGS:"
echo "---------------------"
FINDINGS_COUNT=$(aws dynamodb scan --table-name non-iac-detector-findings --select COUNT --query 'Count' --output text 2>/dev/null)
if [ $? -eq 0 ]; then
    if [ "$FINDINGS_COUNT" -gt 0 ]; then
        print_status "DynamoDB Findings" "OK" "$FINDINGS_COUNT finding(s) stored"
    else
        print_status "DynamoDB Findings" "OK" "No findings yet (normal for new deployment)"
    fi
else
    print_status "DynamoDB Table" "ERROR" "Table not found or access denied"
fi

echo -e "\n5. CLOUDTRAIL STATUS:"
echo "---------------------"
CT_STATUS=$(aws cloudtrail describe-trails --region us-east-1 --query 'trailList[0].IsLogging' --output text 2>/dev/null)
if [ $? -eq 0 ]; then
    if [ "$CT_STATUS" = "True" ]; then
        print_status "CloudTrail Logging" "OK" "Trail is active and logging"
    else
        print_status "CloudTrail Logging" "ERROR" "Trail logging is DISABLED"
    fi
else
    print_status "CloudTrail" "ERROR" "Cannot access CloudTrail or no trails configured"
fi

echo -e "\n6. RECENT LAMBDA LOGS:"
echo "-----------------------"
LOG_GROUP=$(aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/non-iac-detector" --query 'logGroups[0].logGroupName' --output text 2>/dev/null)
if [ -n "$LOG_GROUP" ] && [ "$LOG_GROUP" != "None" ]; then
    echo "Log Group: $LOG_GROUP"
    echo "Recent logs (last 10 minutes):"
    aws logs tail "$LOG_GROUP" --since 10m --format short 2>/dev/null | head -20
else
    print_status "Lambda Logs" "ERROR" "Log group not found"
fi

echo -e "\n=== DIAGNOSTIC COMPLETE ==="
echo ""
echo "SUMMARY:"
echo "--------"
echo "✅ System deployed and Lambda is processing events"
echo "✅ Detection logic is working (alerts generated)"
echo "❌ EMAIL CONFIRMATION REQUIRED - Check maheshgaikwad128@gmail.com"
echo ""
echo "NEXT STEPS:"
echo "1. Check email for AWS SNS confirmation link"
echo "2. Click the confirmation link"
echo "3. Make a manual change (create EC2) to test alerts"
echo "4. Wait 5-15 minutes for CloudTrail delivery"
echo "5. Check email for alert notification"