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
      DYNAMODB_TABLE = aws_dynamodb_table.findings.name
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      TTL_DAYS       = "90"
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  tags = local.common_tags
}

# SQS → Lambda trigger
resource "aws_lambda_event_source_mapping" "sqs" {
  event_source_arn                   = aws_sqs_queue.processing.arn
  function_name                      = aws_lambda_function.detector.arn
  batch_size                         = 5
  maximum_batching_window_in_seconds = 30
  enabled                            = true
}

# Lambda log group
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = 14
  tags              = local.common_tags
}