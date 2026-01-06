# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default   = "iplayishow.com"
}

variable "tfc_kubernetes_dynamic_credentials" {
  description = "Dynamic credentials object injected by HCP Terraform"
  type = object({
    default = object({
      token_path = string
    })
    aliases = map(object({
      token_path = string
    }))
  })
}

variable "mode" {
  description = "RBAC mode: platform or application"
  type        = string
}

variable "tfc_hostname" {
  description = "Terraform Cloud hostname (e.g. https://app.terraform.io)"
  type        = string
  default     = "https://app.terraform.io"
}

variable "tfc_org" {
  description = "Terraform Cloud organization name"
  type        = string
}

variable "tfc_project" {
  description = "Terraform Cloud project name"
  type        = string
}

variable "tfc_workspace" {
  description = "Terraform Cloud workspace name"
  type        = string
  default     = "me-website-k8s-platform"
}

variable "tfc_kubernetes_audience" {
  description = "OIDC audience for Kubernetes provider (must match TFC_KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE)"
  type        = string
  default     = "kubernetes"
}
