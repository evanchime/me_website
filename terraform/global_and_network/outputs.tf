output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "EKS Cluster Name"
  value       = var.cluster_name
}

output "cloudfront_distribution_id" {
  description = "The cloudfrond distribution ID"
  value       = aws_cloudfront_distribution.me_website.id
}

output "s3_bucket_resources" {
  description = "Bucket ARNs including /* variants"
  value = flatten([
    for b in aws_s3_bucket.buckets : [
      b.arn,
      "${b.arn}/*"
    ]
  ])
}

output "vpc_id" {
  description = "The VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "The private subnet IDs"
  value       = module.vpc.private_subnets
}

output "route53_zone_id" {
  description = "The Route53 Hosted Zone ID"
  value       = data.aws_route53_zone.iplayishow.zone_id
}

output "route53_arn" {
  description = "The Route53 Hosted Zone ARN"
  value       = data.aws_route53_zone.iplayishow.arn
}

output "vpc_cidr_block" {
  description = "The VPC CIDR block"
  value       = module.vpc.vpc_cidr_block
}

output "cloudfront_origin_facing_prefix_list_id" {
  description = "The CloudFront origin-facing prefix list ID"
  value       = data.aws_prefix_list.cloudfront_origin_facing.id
}