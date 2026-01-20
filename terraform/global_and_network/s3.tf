locals {
  s3_buckets = {
    static = {
      name = "me-website-static"
    }
    error_pages = {
      name = "me-website-static-error-pages"
    }
  }

  s3_origins = {
    static = {
      bucket_name   = aws_s3_bucket.buckets["static"].bucket
      bucket_domain = aws_s3_bucket.buckets["static"].bucket_regional_domain_name
    }
    error_pages = {
      bucket_name   = aws_s3_bucket.buckets["error_pages"].bucket
      bucket_domain = aws_s3_bucket.buckets["error_pages"].bucket_regional_domain_name
    }
  }
}

data "aws_caller_identity" "current" {}


resource "aws_s3_bucket" "buckets" {
  for_each = local.s3_buckets

  bucket = "${each.value.name}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = each.value.name
  }
}

data "aws_iam_policy_document" "s3_bucket_policy" {
  for_each = local.s3_origins

  statement {
    sid    = "AllowCloudFrontServicePrincipalRead"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      "arn:aws:s3:::${each.value.bucket_name}",
      "arn:aws:s3:::${each.value.bucket_name}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [
        "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${aws_cloudfront_distribution.me_website.id}"
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  for_each = local.s3_origins

  bucket = each.value.bucket_name
  policy = data.aws_iam_policy_document.s3_bucket_policy[each.key].json

}

