variable "region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "non-iac-detector"
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