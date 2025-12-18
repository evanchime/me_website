# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "me_website_image" {
  description = "me_website container image"
  type        = string
  default     = "661510969671.dkr.ecr.eu-west-2.amazonaws.com/me_website:latest"
}

variable "existing_rds_instance_name" {
  description = "RDS instance name"
  type        = string
  default     = "me-website-database-instance"
}

variable "database_master_password" {
  description = "Master password for the RDS instance"
  type        = string
  sensitive   = true
}

variable "existing_rds_security_group_id" {
    description = "Security group ID of the existing RDS instance"
    type        = string
}

variable "health_check_secret_value_wo" {
  description = "The secret value for the X-Health-Check-Secret header."
  type        = string
  sensitive   = true
}

variable "cloudfront_distribution_id" {
  description = "cloudfront_distribution_id"
  type        = string
}

variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default   = "iplayishow.com"
}