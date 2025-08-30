terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
  }
  
  # Optional: Configure remote state storage
  # backend "s3" {
  #   bucket = "your-terraform-state-bucket"
  #   key    = "silentcanary/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.aws_region
}

# Data sources
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}

# Local values
locals {
  cluster_name = "silentcanary-cluster"
  common_tags = {
    Project     = "SilentCanary"
    Environment = var.environment
    CreatedBy   = "Terraform"
  }
}