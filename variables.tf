variable "region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "non-iac-detector"
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket containing centralized multi-account CloudTrail logs."
  type        = string
  default     = "non-iac-poc-test-804266303347-us-east-1"
}

variable "cloudtrail_logs_prefix" {
  description = "Prefix in the centralized bucket containing account log folders."
  type        = string
  default     = "AWSLogs/"
}

variable "cloudtrail_account_ids" {
  description = "Account IDs whose CloudTrail logs the detector should scan."
  type        = list(string)
  default     = ["804266303347", "999999999999", "1111111", "111111111111"]
}

# ═══════════════════════════════════════
# IaC IDENTIFICATION
# ═══════════════════════════════════════

variable "iac_role_patterns" {
  type = list(string)
  default = [
    "terraform-*",
    "github-actions-*",
    "gitlab-runner-*",
    "jenkins-*",
    "cicd-*",
    "deploy-*",
    "pipeline-*",
    "AWSReservedSSO_Admin*",
  ]
}

variable "iac_user_agents" {
  type = list(string)
  default = [
    "terraform",
    "cloudformation",
    "pulumi",
    "aws-cdk",
  ]
}

variable "iac_source_ips" {
  type        = list(string)
  description = "CI/CD runner IPs"
  default     = []
}

# ═══════════════════════════════════════
# ALERTING
# ═══════════════════════════════════════

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

variable "slack_webhook_url" {
  type      = string
  default   = ""
  sensitive = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "yesterday_scan_schedule_expression" {
  description = "EventBridge schedule for the daily prior-UTC-day CloudTrail scan."
  type        = string
  default     = "cron(30 1 * * ? *)"
}
