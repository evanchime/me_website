# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {

  cloud {
    organization = "DevOps_As_A_Way"
    workspaces {
      project = "k8s-migration"
      name = "k8s-migration-platform"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.7.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.0.1"
    }

    helm = {
      source  = "hashicorp/helm"
      version = ">= 3.0"
    }

  }

  required_version = "~> 1.3"
}
