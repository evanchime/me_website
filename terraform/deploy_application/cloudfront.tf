provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

data "aws_acm_certificate" "cloudfront_cert" {
  provider = aws.us_east_1
  domain   = "iplayishow.com"
  statuses = ["ISSUED"]
  most_recent = true
}

data "aws_cloudfront_cache_policy" "app_cache" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "app_request" {
  name = "Managed-AllViewerExceptHostHeader"
}

data "aws_cloudfront_cache_policy" "static_cache" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_response_headers_policy" "static_headers" {
  name = "Managed-SimpleCORS"
}

data "aws_cloudfront_cache_policy" "error_cache" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_origin_access_control" "me_website-oac" {
  for_each = local.s3_origins

  name                              = "oac-${each.key}"
  description                       = "OAC for ${each.key} S3 origin"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "me_website" {
  enabled             = true
  comment             = "me-website CloudFront distribution"
  is_ipv6_enabled     = true
  price_class         = "PriceClass_All"
  http_version        = "http2and3"
  default_root_object = ""

  aliases = [
    "iplayishow.com",
    "www.iplayishow.com",
    "static.iplayishow.com",
  ]

  # ------------ ORIGINS ------------

  # App origin (ALB) – previously EC2; NO X-Secret header here
  origin {
    domain_name = data.kubernetes_ingress_v1.me_website_app.status[0].load_balancer[0].ingress[0].hostname
    origin_id   = "app-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 30
      origin_keepalive_timeout = 5
    }
  }

  # Static files origin (S3)
  origin {
    domain_name              = local.s3_origins.static.bucket_domain
    origin_id                = "static-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.me_website-oac["static"].id

  }

  # Error pages origin (S3)
  origin {
    domain_name              = local.s3_origins.error_pages.bucket_domain
    origin_id                = "error-pages-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.me_website-oac["error_pages"].id
  }

  # ------------ DEFAULT BEHAVIOR (APP) ------------

  default_cache_behavior {
    target_origin_id       = "app-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = [
      "DELETE",
      "GET",
      "HEAD",
      "OPTIONS",
      "PATCH",
      "POST",
      "PUT",
    ]

    cached_methods = [
      "GET",
      "HEAD",
    ]

    cache_policy_id          = data.aws_cloudfront_cache_policy.app_cache.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.app_request.id

    compress  = true
    min_ttl   = 0
    default_ttl = 0
    max_ttl   = 0
  }

  # ------------ ORDERED BEHAVIORS ------------

  # /static/* -> S3 static bucket
  ordered_cache_behavior {
    path_pattern           = "/static/*"
    target_origin_id       = "static-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = [
      "GET",
      "HEAD",
      "OPTIONS",
    ]

    cached_methods = [
      "GET",
      "HEAD",
    ]

    cache_policy_id            = data.aws_cloudfront_cache_policy.static_cache.id
    response_headers_policy_id = data.aws_cloudfront_response_headers_policy.static_headers.id

    compress   = true
    min_ttl    = 0
    default_ttl = 0
    max_ttl    = 0
  }

  # /errors/* -> error pages S3 bucket
  ordered_cache_behavior {
    path_pattern           = "/errors/*"
    target_origin_id       = "error-pages-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = [
      "GET",
      "HEAD",
    ]

    cached_methods = [
      "GET",
      "HEAD",
    ]

    cache_policy_id = data.aws_cloudfront_cache_policy.error_cache.id

    compress   = true
    min_ttl    = 0
    default_ttl = 0
    max_ttl    = 0
  }

  # ------------ CUSTOM ERROR RESPONSES ------------

  custom_error_response {
    error_code            = 400
    error_caching_min_ttl = 10
    response_code         = 400
    response_page_path    = "/errors/400.html"
  }

  custom_error_response {
    error_code            = 403
    error_caching_min_ttl = 10
    response_code         = 403
    response_page_path    = "/errors/403.html"
  }

  custom_error_response {
    error_code            = 404
    error_caching_min_ttl = 10
    response_code         = 404
    response_page_path    = "/errors/404.html"
  }

  custom_error_response {
    error_code            = 500
    error_caching_min_ttl = 10
    response_code         = 500
    response_page_path    = "/errors/500.html"
  }

  custom_error_response {
    error_code            = 502
    error_caching_min_ttl = 10
    response_code         = 502
    response_page_path    = "/errors/500.html"
  }

  custom_error_response {
    error_code            = 503
    error_caching_min_ttl = 10
    response_code         = 503
    response_page_path    = "/errors/500.html"
  }

  custom_error_response {
    error_code            = 504
    error_caching_min_ttl = 10
    response_code         = 504
    response_page_path    = "/errors/500.html"
  }

  # ------------ RESTRICTIONS & TRUSTED SETTINGS ------------

  restrictions {
    geo_restriction {
      restriction_type = "none"
      locations        = []
    }
  }

  viewer_certificate {
    acm_certificate_arn            = data.aws_acm_certificate.cloudfront_cert.arn
    ssl_support_method             = "sni-only"
    minimum_protocol_version       = "TLSv1.2_2021"
    cloudfront_default_certificate = false
  }

  retain_on_delete      = false
  wait_for_deployment   = true
}
