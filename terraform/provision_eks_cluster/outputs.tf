# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnets" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnet" {
  description = "List of IDs of the public subnets, suitable for NAT gateways and public load balancers."
  value       = module.vpc.public_subnets
}

output "cluster_primary_security_group_id" {
  description = "The cluster-primary security group ID created by the EKS module. Useful for configuring access to cluster resources like EFS."
  value       = module.eks.cluster_primary_security_group_id
}

output "fargate_app_sg_id" {
  description = "The fargate app security group ID for pods on Fargate"
  value       = module.fargate_app_sg.security_group_id
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

output "vpc_cidr_block" {
  description = "The CIDR block of the main VPC."
  value       = module.vpc.vpc_cidr_block
}

output "rds_lambda_security_group_id" {
  description = "The ID of the security group attached to the RDS secrets rotation Lambda function."
  value       = module.rds_lambda_security_group.security_group_id
}

output "efs_access_point_id" {
  description = "The ID of the EFS access point created for the me_website application."
  value       = module.efs.access_points["me_website-filesystem"].id
}

output "efs_file_system_id" {
  description = "The ID of the EFS file system."
  value       = module.efs.id
}

output "route53_zone_id" {
  description = "The ID of the Route53 hosted zone for the application domain."
  value       = data.aws_route53_zone.iplayishow.zone_id
}

output "me_website_irsa_role_arn" {
  description = "The ARN of the IAM role created for the me_website application service account."
  value       = module.me_website_irsa_role.arn
}

output "me_website_k8s_db_endpoint" {
  value = aws_db_instance.me_website_k8s_db.endpoint
}

output "me_website_k8s_db_username" {
  value = aws_db_instance.me_website_k8s_db.username
}

output "me_website_k8s_db_password" {
  value = aws_db_instance.me_website_k8s_db.password
  sensitive = true
}

output "me_website_k8s_db_name" {
  value = aws_db_instance.me_website_k8s_db.db_name
}

output "me_website_k8s_db_security_group_id" {
  value = module.rds_security_group.security_group_id
}

output "me_website_app_kubernetes_namespace" {
  value = kubernetes_namespace_v1.me_website_app.metadata[0].name
}

output "alb_security_group_id" {
  value = module.alb_security_group.security_group_id
}

output "me_website_k8s_db_secret" {
  value = aws_secretsmanager_secret.rds_master_credentials.name
}