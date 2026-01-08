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
    domain_name              = var.static_bucket_domain_name
    origin_id                = "static-origin"
    origin_access_control_id = "E22WCEJAR6758S" # or replace with aws_cloudfront_origin_access_control.*.id

    # using OAC instead of legacy OAI, so no s3_origin_config
  }

  # Error pages origin (S3)
  origin {
    domain_name              = var.error_pages_bucket_domain_name
    origin_id                = "error-pages-origin"
    origin_access_control_id = "E36POSVKU25VQM" # or replace with aws_cloudfront_origin_access_control.*.id
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

    # Same as your export
    cache_policy_id          = "d28f3cd2-c7df-4f9c-869b-c4ff433fb74b"
    origin_request_policy_id = "5bc19d50-2297-45ff-9b93-2cb198db5484"

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

    cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6"
    response_headers_policy_id = "4e525da8-319b-40d2-8a32-72499ae5da61"

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

    cache_policy_id = "b5728d30-8c7d-4f3f-8a64-6417da4a466e"

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
    acm_certificate_arn            = "arn:aws:acm:us-east-1:661510969671:certificate/a356c6a6-82fc-4c32-a0eb-fe10ca213bcf"
    ssl_support_method             = "sni-only"
    minimum_protocol_version       = "TLSv1.2_2021"
    cloudfront_default_certificate = false
  }

  retain_on_delete      = false
  wait_for_deployment   = true
}
