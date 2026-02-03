# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "me_website_email_host_user" {
    description = "Email address for me_website application admin"
    type        = string
    default = "evanchime@gmail.com"
}

variable "lambda_layer_name" {
  description = "The name of the Lambda layer for RDS rotation."
  type        = string
  default     = "rds-postgres-rotation"
}

variable "lambda_layer_version" {
  description = "The version of the Lambda layer for RDS rotation."
  type        = string
  default     = "0"
}