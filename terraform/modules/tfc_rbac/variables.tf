variable "mode" {
  description = "RBAC mode: platform or application"
  type        = string
}

variable "tfc_hostname" {
  description = "Terraform Cloud hostname (e.g. https://app.terraform.io)"
  type        = string
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
}

variable "target_namespace" {
  description = "Target namespace for application mode. Required if mode = application."
  type        = string
  default     = null
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "tfc_kubernetes_audience" {
  description = "OIDC audience for Kubernetes provider (must match TFC_KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE)"
  type        = string
}

variable "tfc_kubernetes_dynamic_credentials" {
  description = "Dynamic credentials object injected by Terraform Cloud"
  type = object({
    default = object({
      token_path = string
    })
    aliases = map(object({
      token_path = string
    }))
  })
}