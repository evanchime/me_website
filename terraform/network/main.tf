###############################################
# PROVIDER & GLOBAL CONFIGURATION
###############################################

provider "aws" {
  region = var.region
}

locals {
  # Common tags applied to all resources
  tags = {
    Project     = "k8s-migration"
    Environment = "production"
    Terraform   = "true"
  }
  cloudfront_origin_prefix_list_id = "pl-93a247fa"
}

###############################################
# DATA SOURCES
###############################################

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_route53_zone" "iplayishow" {
  name = "${trimsuffix(var.domain_name, ".")}."
  private_zone = false
}

#######################################################
# VPC — Networking foundation for EKS, Lambda, and RDS
#######################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.5"

  name = "me_website-vpc"
  cidr = "10.0.0.0/16"

  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Required for EKS load balancers
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  # Required for EKS Fargate + VPC CNI
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/pod-eni" = "1"
  }

  tags = local.tags
}
