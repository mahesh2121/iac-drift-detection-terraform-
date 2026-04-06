output "cloudtrail_name" {
  value = aws_cloudtrail.main.name
}

output "s3_bucket" {
  value = aws_s3_bucket.cloudtrail.id
}

output "lambda_function" {
  value = aws_lambda_function.detector.function_name
}

output "dynamodb_table" {
  value = aws_dynamodb_table.findings.name
}

output "sns_topic" {
  value = aws_sns_topic.alerts.arn
}

# ═══════════════════════════════════════
# TEST COMMANDS - Ready to Copy/Paste
# ═══════════════════════════════════════

output "test_commands" {
  value = {

    step1_deploy = "terraform apply -auto-approve"

    step2_confirm_email = "Check your email (${var.alert_email}) and CONFIRM the SNS subscription"

    step3_test_non_iac_change = <<-EOT

      echo "=== Creating NON-IAC changes (manual via CLI) ==="

      # Test 1: Create Security Group (HIGH - ec2 is critical service)
      aws ec2 create-security-group \
        --group-name "test-non-iac-sg" \
        --description "Manual change test" \
        --vpc-id $(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)

      # Test 2: Create S3 Bucket (HIGH - s3 is critical service)
      aws s3 mb s3://test-non-iac-bucket-$(date +%s)

      # Test 3: Create IAM User (CRITICAL - CreateUser is high event)
      aws iam create-user --user-name test-non-iac-user

      # Test 4: Add inline policy (CRITICAL - PutUserPolicy)
      aws iam put-user-policy \
        --user-name test-non-iac-user \
        --policy-name test-policy \
        --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'

      echo "=== Wait 5-10 minutes for CloudTrail to deliver logs ==="

    EOT

    step4_check_findings = <<-EOT

      echo "=== Checking findings in DynamoDB ==="

      # Count all findings
      aws dynamodb scan \
        --table-name ${aws_dynamodb_table.findings.name} \
        --select COUNT

      # Get recent findings
      aws dynamodb scan \
        --table-name ${aws_dynamodb_table.findings.name} \
        --limit 5 \
        --projection-expression "event_time,event_name,severity,user_name,source_ip,resource_name"

      # Get CRITICAL findings only
      aws dynamodb query \
        --table-name ${aws_dynamodb_table.findings.name} \
        --index-name severity-index \
        --key-condition-expression "severity = :s" \
        --expression-attribute-values '{":s":{"S":"CRITICAL"}}' \
        --limit 5

    EOT

    step5_check_lambda_logs = <<-EOT

      echo "=== Lambda execution logs ==="

      aws logs tail /aws/lambda/${aws_lambda_function.detector.function_name} \
        --since 1h --follow

    EOT

    step6_cleanup_test_resources = <<-EOT

      echo "=== Cleaning up test resources ==="

      # Delete test security group
      SG_ID=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=test-non-iac-sg" \
        --query 'SecurityGroups[0].GroupId' --output text)
      [ "$SG_ID" != "None" ] && aws ec2 delete-security-group --group-id $SG_ID

      # Delete test IAM user
      aws iam delete-user-policy --user-name test-non-iac-user --policy-name test-policy 2>/dev/null
      aws iam delete-user --user-name test-non-iac-user 2>/dev/null

      # Delete test S3 bucket
      for bucket in $(aws s3 ls | grep test-non-iac-bucket | awk '{print $3}'); do
        aws s3 rb s3://$bucket --force
      done

      echo "=== Test resources cleaned up ==="

    EOT

    step7_destroy_all = "terraform destroy -auto-approve"
  }
}