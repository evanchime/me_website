variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default     = "iplayishow.com"
}

variable "cluster_name" {
  description = "EKS Cluster Name"
  type        = string
  default     = "meweb-eks"
}

variable "alb_target_origin_id" {
  description = "The CloudFront origin ID for the ALB"
  type        = string
  default     = "me-website-app-origin"
}

variable "error_pages_origin_id" {
  description = "The CloudFront origin ID for the error pages S3 bucket"
  type        = string
  default     = "me-website-error-pages-origin"
}

variable "static_origin_id" {
  description = "The CloudFront origin ID for the static files S3 bucket"
  type        = string
  default     = "me-website-static-origin"
}

variable "alb_target_placeholder_domain_name" {
  description = "The placeholder domain name of the ALB to be used as CloudFront origin"
  type        = string
  default     = "placeholder.example.com"
}