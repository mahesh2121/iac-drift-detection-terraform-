terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # Local backend for testing (switch to S3 for real use)
  # backend "s3" {
  #   bucket = "my-tf-state"
  #   key    = "cloudtrail-detector.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.region
}