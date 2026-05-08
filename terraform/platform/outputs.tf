# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "region" {
  description = "AWS region"
  value       = data.terraform_remote_state.me_website_k8s_eks.outputs.region
}

output "fargate_app_sg_id" {
  description = "The fargate app security group ID for pods on Fargate"
  value       = module.fargate_app_sg.security_group_id
}

output "rds_security_group_id" {
    description = "The ID of the security group attached to the RDS instance."
    value = module.rds_security_group.security_group_id
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

output "me_website_k8s_db_port" {
  value = aws_db_instance.me_website_k8s_db.port
}

output "me_website_k8s_db_host" {
  value = aws_db_instance.me_website_k8s_db.address
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

output "me_website_prometheus_workspace_endpoint" {
  value = aws_prometheus_workspace.me_website_prometheus.prometheus_endpoint
}

output "grafana_workspace_url" {
  value = "https://${module.me_website_managed_grafana.workspace_endpoint}"
}

output "adot_col_namespace" {
  value = kubernetes_namespace_v1.adot_col.metadata[0].name
}

output "adot_infra_config_map" {
  value = kubernetes_config_map_v1.adot_infra_config.metadata[0].name
}

output "grafana_workspace_id" {
  description = "The ID of the Grafana workspace created for the me_website application."
  value = module.me_website_managed_grafana.workspace_id
}

output "grafana_provider_secret_name" {
  description = "The name of the Secrets Manager secret containing the Grafana API token for the Grafana provider"
  sensitive = true
  value     = aws_secretsmanager_secret.grafana_provider_token.name
}

output "grafana_operator_secret_name" {
  description = "The name of the Secrets Manager secret containing the Grafana API token for the Grafana Operator to connect to the workspace."
  sensitive = true
  value     = aws_secretsmanager_secret.grafana_operator_token.name
}

output "adot_collector_service_account" {
  description = "The name of the Kubernetes Service Account used by the ADOT Collector."
  value       = kubernetes_service_account_v1.adot_collector_service_account.metadata[0].name
}
