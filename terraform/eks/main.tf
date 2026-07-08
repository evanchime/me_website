provider "aws" {
  region = data.terraform_remote_state.me_website_k8s_network.outputs.region
}

locals {
  # Unique cluster name with random suffix
  cluster_name        = data.terraform_remote_state.me_website_k8s_network.outputs.cluster_name
  tags = {
    Environment = "production"
    Project     = "k8s-migration"
    Terraform   = "true"
  }
}

data "aws_caller_identity" "current" {}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.10"

  name = local.cluster_name

  endpoint_public_access  = true
  endpoint_private_access = true
  endpoint_public_access_cidrs = ["0.0.0.0/0"]

  enable_cluster_creator_admin_permissions = true

  # Core EKS addons
  addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
  }

  # Grant admin access to your SSO role
  access_entries = {
    Evan_Admin = {
      principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_AdministratorAccess_95a4a8e95b834fbe"

      policy_associations = {
        cluster = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = { type = "cluster" }
        }
      }
    }

    GitHub_Actions_IaC_Pipeline = {
      principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/GitHubActions-Terraform-Role"

      policy_associations = {
        cluster = {
          policy_arn   = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = { type = "cluster" }
        }
      }
    }
  }

  vpc_id     = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id
  subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids

  #########################################
  # Fargate profiles — system namespaces
  #########################################

  fargate_profiles = {
    system = {
      name       = "fp-system"
      subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
      selectors = [
        { namespace = "kube-system" },
        { namespace = "default" },
        { namespace = "external-dns" }
      ]
    }

    me_website = {
      name       = "fp-me-website"
      subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
      selectors = [
        { namespace = "me-website-app" }
      ]
    }

    observability = {
      name       = "fp-observability"
      subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
      selectors = [
        { namespace = "grafana-operator" },
        { namespace = "adot-col" }
      ]
    }

    external_secrets = {
      name       = "fp-external-secrets"
      subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
      selectors = [
        { namespace = "external-secrets" }
      ]
    }

  }

  tags = local.tags
}
