variable "health_check_secret_value_wo" {
  description = "The secret value for the X-Health-Check-Secret header."
  type        = string
  sensitive   = true
}

variable "cloudfront_distribution_id" {
  description = "cloudfront_distribution_id"
  type        = string
}
