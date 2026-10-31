# ═══════════════════════════════════════════════════
# LAMBDA FUNCTION
# ═══════════════════════════════════════════════════

data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/detector"
  output_path = "${path.module}/.build/detector.zip"
}

resource "aws_lambda_function" "detector" {
  function_name    = "${local.prefix}-detector"
  description      = "Detects non-IaC changes from CloudTrail"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  timeout          = 150
  memory_size      = 256
  role             = aws_iam_role.lambda.arn

  environment {
    variables = {
      DETECTOR_CONFIG = replace(
        local.detector_config,
        "\"sns_topic_arn\":\"WILL_BE_SET\"",
        "\"sns_topic_arn\":\"${aws_sns_topic.alerts.arn}\""
      )
      DYNAMODB_TABLE    = aws_dynamodb_table.findings.name
      SNS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      TTL_DAYS          = "90"
      CLOUDTRAIL_BUCKET = var.cloudtrail_bucket_name
      CLOUDTRAIL_PREFIX = var.cloudtrail_logs_prefix
      ACCOUNT_IDS       = join(",", var.cloudtrail_account_ids)
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tags = local.common_tags
}

# Daily reconciliation for the complete previous UTC calendar day.
resource "aws_cloudwatch_event_rule" "yesterday_scan" {
  name                = "${local.prefix}-yesterday-scan"
  description         = "Scans the prior UTC day's CloudTrail logs"
  schedule_expression = var.yesterday_scan_schedule_expression
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "yesterday_scan" {
  rule      = aws_cloudwatch_event_rule.yesterday_scan.name
  target_id = "yesterday-cloudtrail-scan"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_yesterday_scan" {
  statement_id  = "AllowExecutionFromEventBridgeYesterdayScan"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.yesterday_scan.arn
}

# Lambda log group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = 14
  tags              = local.common_tags
}
