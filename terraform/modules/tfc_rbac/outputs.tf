output "tfc_users" {
  description = "The plan/apply user identities used for RBAC bindings"
  value = {
    plan  = local.tfc_user_plan
    apply = local.tfc_user_apply
  }
}

output "identity_provider_config" {
  description = "EKS identity provider config name"
  value       = aws_eks_identity_provider_config.tfc_oidc.oidc[0].identity_provider_config_name
}