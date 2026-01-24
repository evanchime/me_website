# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {

  cloud {
    organization = "DevOps_As_A_Way"
    workspaces {
      project = "k8s-migration"
      name = "k8s-migration-network"
    }
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  required_version = "~> 1.3"

}

