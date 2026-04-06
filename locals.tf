data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  prefix     = var.project_name

  common_tags = merge(var.tags, {
    Project   = var.project_name
    ManagedBy = "Terraform"
  })

  # Lambda config passed as environment variable
  detector_config = jsonencode({
    iac_user_agents = var.iac_user_agents
    iac_role_patterns = var.iac_role_patterns
    iac_source_ips    = var.iac_source_ips

    excluded_event_sources = [
      "cloudtrail.amazonaws.com",
      "config.amazonaws.com",
      "guardduty.amazonaws.com",
      "sso.amazonaws.com",
      "signin.amazonaws.com",
      "health.amazonaws.com",
      "trustedadvisor.amazonaws.com",
    ]

    excluded_event_names = [
      "ConsoleLogin",
      "AssumeRole",
      "SwitchRole",
      "GetSessionToken",
      "Decrypt",
      "Encrypt",
      "GenerateDataKey",
    ]

    critical_services = [
      "iam.amazonaws.com",
      "ec2.amazonaws.com",
      "s3.amazonaws.com",
      "rds.amazonaws.com",
      "lambda.amazonaws.com",
      "kms.amazonaws.com",
    ]

    high_event_names = [
      "DeleteBucket",
      "TerminateInstances",
      "DeleteDBInstance",
      "CreateUser",
      "AttachRolePolicy",
      "PutBucketPolicy",
      "DeleteTrail",
      "StopLogging",
      "AuthorizeSecurityGroupIngress",
    ]

    dynamodb_table    = "${local.prefix}-findings"
    sns_topic_arn     = "WILL_BE_SET"
    slack_webhook_url = var.slack_webhook_url
    account_id        = local.account_id
  })
}