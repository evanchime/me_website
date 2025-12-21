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
  default     = "${data.aws_caller_identity.current.account_id}.dkr.ecr.eu-west-2.amazonaws.com/me_website:latest"
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

variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default   = "iplayishow.com"
}