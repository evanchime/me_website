variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "domain_name" {
  description = "The domain name for the website"
  type        = string
  default   = "iplayishow.com"
}

variable "cluster_name" {
  description = "EKS Cluster Name"
  type        = string
  default     = "meweb-eks"
}
