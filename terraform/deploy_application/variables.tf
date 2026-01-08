variable "app_alb_dns_name" {
  description = "DNS name of the ALB fronting the Django app"
  type        = string
}

variable "static_bucket_domain_name" {
  description = "Domain name of the static S3 bucket origin"
  type        = string
  default     = "me-website-bucket.s3.eu-west-2.amazonaws.com"
}

variable "error_pages_bucket_domain_name" {
  description = "Domain name of the error pages S3 bucket origin"
  type        = string
  default     = "me-website-static-error-pages-bucket.s3.eu-west-2.amazonaws.com"
}

variable "cloudfront_distribution_id" {
  description = "cloudfront_distribution_id"
  type        = string
  sensitive = true
}

variable "iam_policy_arn" {
  description = "IAM Policy to be attached to role"
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/AmazonEventBridgeReadOnlyAccess","arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
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
  default     = "me-website-k8s-app"
}

variable "tfc_kubernetes_audience" {
  description = "OIDC audience for Kubernetes provider (must match TFC_KUBERNETES_WORKLOAD_IDENTITY_AUDIENCE)"
  type        = string
  default     = "kubernetes"
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