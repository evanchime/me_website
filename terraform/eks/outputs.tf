# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "region" {
  description = "AWS region"
  value       = data.terraform_remote_state.me_website_k8s_network.outputs.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

output "cluster_version" {
  description = "Kubernetes Cluster Version"
  value       = module.eks.cluster_version
}

output "cluster_primary_security_group_id" {
  description = "The cluster-primary security group ID created by the EKS module. Useful for configuring access to cluster resources like EFS."
  value       = module.eks.cluster_primary_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster."
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "oidc_provider_arn" {
  description = "The ARN of the cluster's OIDC provider for IAM roles for service accounts (IRSA)."
  value       = module.eks.oidc_provider_arn
}
