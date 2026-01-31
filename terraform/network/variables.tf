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

variable "cloudfront_cert_arn" {
  description = "The ACM certificate ARN for CloudFront"
  type        = string
  default     = "arn:aws:acm:us-east-1:661510969671:certificate/a356c6a6-82fc-4c32-a0eb-fe10ca213bcf"
}

variable "iam_policy_arn" {
  description = "IAM Policy to be attached to role"
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/AmazonEventBridgeReadOnlyAccess","arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
}

variable "enable_lambda" {
  description = "Whether to enable the Lambda function and layer"
  type    = bool
  default = false
}

variable "lambda_layer_s3_key" {
  description = "The S3 key for the Lambda layer zip file"
  type = string
  default = ""
}