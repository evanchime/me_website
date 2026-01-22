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

variable "alb_target_placeholder_domain_name" {
  description = "The domain name of the ALB to be used as CloudFront origin"
  type        = string
  default     = "placeholder.example.com"
}