provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

locals {
#   cloudfront_policies = {
#     app_cache = {
#       type = "cache"
#       name = "Managed-CachingDisabled"
#     }
#     static_cache = {
#       type = "cache"
#       name = "Managed-CachingOptimized"
#     }
#     error_cache = {
#       type = "cache"
#       name = "Managed-CachingDisabled"
#     }
#   }
  cname_records = {
    www = {
      ttl     = 300
      records = ["iplayishow.com"]
    }

    static = {
      ttl     = 172800
      records = [aws_cloudfront_distribution.me_website.domain_name]
    }
  }
  root_alias_record_types = ["A", "AAAA"]
  cloudfront_cert_arn = var.cloudfront_cert_arn
}

# data "aws_cloudfront_cache_policy" "policies" {
#   for_each = {
#     for k, v in local.cloudfront_policies :
#     k => v
#     if v.type == "cache"
#   }

#   name = each.value.name
# }

# data "aws_cloudfront_origin_request_policy" "app_request" {
#   name = "Managed-AllViewerExceptHostHeader"
# }

# data "aws_cloudfront_response_headers_policy" "static_headers" {
#   name = "Managed-SimpleCORS"
# }

data "aws_cloudfront_cache_policy" "static_managed_cache_policy" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_response_headers_policy" "me_website_static_assets_response_headers_policy" {
  name    = "Me-Website-Static-Assets-Response-Headers-Policy"
  comment = "Hardens security via HSTS, CSP, and Frame Options"

  security_headers_config {
    # Strict-Transport-Security (HSTS)
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    # X-Content-Type-Options
    content_type_options {
      override = true
    }

    # X-Frame-Options (DENY)
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    # X-XSS-Protection
    xss_protection {
      protection = true
      mode_block = true
      override   = true
    }

    # Referrer-Policy
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    # Content-Security-Policy (CSP)
    content_security_policy {
      override = true
      content_security_policy = "default-src 'self' https://*.cloudfront.net; script-src 'self' https://*.cloudfront.net https://*.s3.amazonaws.com https://cdn.jsdelivr.net https://getbootstrap.com; style-src 'self' 'unsafe-inline' https://*.cloudfront.net https://*.s3.amazonaws.com; img-src 'self' https://*.cloudfront.net https://*.s3.amazonaws.com data:; object-src 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests;"
    }
  }
}

resource "aws_cloudfront_origin_request_policy" "me_website_origin_request_policy" {
  name    = "Me-Website-Origin-Request-Policy"
  comment = "Forwards CSRF, Session, and Host headers to the application origin"

  cookies_config {
    cookie_behavior = "all"
  }

  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "Origin",
        "X-CSRFToken",
        "Referer",
        "Host" 
      ]
    }
  }

  query_strings_config {
    query_string_behavior = "all"
  }
}

resource "aws_cloudfront_cache_policy" "me_website_static_error_cache_policy" {
  name    = "Me-Website-Static-Error-Cache-Policy"
  comment = "Cache policy for static error pages or assets with high rotation"

  min_ttl     = 10
  max_ttl     = 10
  default_ttl = 10

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true

    headers_config {
      header_behavior = "none"
    }

    cookies_config {
      cookie_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_cache_policy" "me_website_origin_cache_policy" {
  name        = "Me-Website-Origin-Cache-Policy"
  comment     = "Optimized caching for apps using CSRF tokens and Session cookies"
  
  min_ttl     = 0
  max_ttl     = 86400
  default_ttl = 300

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true

    headers_config {
      header_behavior = "whitelist"
      headers {
        items = [
          "Origin",
          "X-CSRFToken",
          "Referer",
          "Host"
        ]
      }
    }

    cookies_config {
      cookie_behavior = "whitelist"
      cookies {
        items = [
          "sessionid",
          "csrftoken"
        ]
      }
    }

    query_strings_config {
      query_string_behavior = "all"
    }
  }
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
  price_class         = "PriceClass_200"
  http_version        = "http2and3"
  default_root_object = ""

  aliases = [
    "iplayishow.com",
    "www.iplayishow.com",
    "static.iplayishow.com",
  ]

  # ------------ ORIGINS ------------

  # App origin (ALB) – placeholder domain name
  origin {
    # domain_name = var.alb_target_placeholder_domain_name
    domain_name = var.alb_target_domain_name
    origin_id   = var.alb_target_origin_id

    connection_attempts = 3
    connection_timeout  = 10

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
    origin_id                = var.static_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.me_website-oac["static"].id

  }

  # Error pages origin (S3)
  origin {
    domain_name              = local.s3_origins.error_pages.bucket_domain
    origin_id                = var.error_pages_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.me_website-oac["error_pages"].id
  }

  # ------------ DEFAULT BEHAVIOR (APP) ------------

  default_cache_behavior {
    target_origin_id       = var.alb_target_origin_id
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

    # cache_policy_id          = data.aws_cloudfront_cache_policy.policies["app_cache"].id
    # origin_request_policy_id = data.aws_cloudfront_origin_request_policy.app_request.id
    cache_policy_id = aws_cloudfront_cache_policy.me_website_origin_cache_policy.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.me_website_origin_request_policy.id

    compress  = true
    min_ttl   = 0
    default_ttl = 0
    max_ttl   = 0
  }

  # ------------ ORDERED BEHAVIORS ------------

  # /static/* -> S3 static bucket
  ordered_cache_behavior {
    path_pattern           = "/static/*"
    target_origin_id       = var.static_origin_id
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

    # cache_policy_id            = data.aws_cloudfront_cache_policy.policies["static_cache"].id
    # response_headers_policy_id = data.aws_cloudfront_response_headers_policy.static_headers.id
    cache_policy_id = data.aws_cloudfront_cache_policy.static_managed_cache_policy.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.me_website_static_assets_response_headers_policy.id

    compress   = true
    min_ttl    = 0
    default_ttl = 0
    max_ttl    = 0
  }

  # /errors/* -> error pages S3 bucket
  ordered_cache_behavior {
    path_pattern           = "/errors/*"
    target_origin_id       = var.error_pages_origin_id
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = [
      "GET",
      "HEAD",
    ]

    cached_methods = [
      "GET",
      "HEAD",
    ]

    # cache_policy_id = data.aws_cloudfront_cache_policy.policies["error_cache"].id
    cache_policy_id = aws_cloudfront_cache_policy.me_website_static_error_cache_policy.id

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
    acm_certificate_arn            = local.cloudfront_cert_arn
    ssl_support_method             = "sni-only"
    minimum_protocol_version       = "TLSv1.2_2021"
    cloudfront_default_certificate = false
  }

  retain_on_delete      = false
  wait_for_deployment   = true
}

resource "aws_route53_record" "root_alias" {
  for_each = toset(local.root_alias_record_types)

  zone_id = data.aws_route53_zone.iplayishow.zone_id
  name    = "iplayishow.com"
  type    = each.value

  alias {
    name                   = aws_cloudfront_distribution.me_website.domain_name
    zone_id                = aws_cloudfront_distribution.me_website.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "cname" {
  for_each = local.cname_records

  zone_id = data.aws_route53_zone.iplayishow.zone_id
  name    = each.key
  type    = "CNAME"
  ttl     = each.value.ttl
  records = each.value.records
}

# data "archive_file" "alb_lambda_zip" {
#   type        = "zip"
#   source_file = "${path.module}/lambda/alb/lambda_function.py"
#   output_path = "${path.module}/lambda/alb/lambda_function.zip"
# }

# resource "aws_lambda_layer_version" "lambda_layer" {
#   count = var.enable_lambda ? 1 : 0

#   s3_bucket           = aws_s3_bucket.buckets["lambda_layer"].bucket
#   s3_key              = "layers/${var.lambda_layer_name}/v${var.lambda_layer_version}.zip"
#   layer_name          = var.lambda_layer_name
#   compatible_runtimes = ["python3.12", "python3.11", "python3.10"]
# }

# resource "aws_lambda_function" "update_cloudfront_alb_origin" {
#   depends_on = [
#     aws_iam_role_policy_attachment.attach_custom_policy,
#     aws_iam_role_policy_attachment.additional-necessary-policies
#   ]

#   count            = var.enable_lambda ? 1 : 0

#   function_name    = "cloudfront-alb-origin-update-function"
#   role             = aws_iam_role.lambda_cloudfront_updater_role.arn
#   handler          = "lambda_function.lambda_handler"
#   runtime          = "python3.12"

#   filename         = data.archive_file.alb_lambda_zip.output_path
#   source_code_hash = data.archive_file.alb_lambda_zip.output_base64sha256


#   layers = [
#     aws_lambda_layer_version.lambda_layer[0].arn
#   ]

#   timeout     = 300
#   memory_size = 128
#   reserved_concurrent_executions = 1

#   environment {
#     variables = {
#       ALB_TARGET_ORIGIN_ID = var.alb_target_origin_id
#       CLOUDFRONT_DISTRIBUTION_ID = aws_cloudfront_distribution.me_website.id
#       ALB_TARGET_PLACEHOLDER_DOMAIN = var.alb_target_placeholder_domain_name
#     }
#   }
# }

# resource "aws_cloudwatch_event_rule" "create_loadbalancer_event" {
#   count = var.enable_lambda ? 1 : 0

#   name        = "create_loadbalancer_event"
#   description = "loadbalancer events"

#   event_pattern = <<PATTERN
# {
#   "source": [
#     "aws.elasticloadbalancing"
#   ],
#   "detail-type": [
#     "AWS API Call via CloudTrail"
#   ],
#   "detail": {
#     "eventSource": [
#       "elasticloadbalancing.amazonaws.com"
#     ],
#     "eventName": [
#       "CreateLoadBalancer"
#     ]
#   }
# }
# PATTERN
# }

# resource "aws_cloudwatch_event_target" "create_loadbalancer_event_target" {
#   count = var.enable_lambda ? 1 : 0

#   rule      = aws_cloudwatch_event_rule.create_loadbalancer_event[0].name
#   target_id = "cloudfront-update"
#   arn       = aws_lambda_function.update_cloudfront_alb_origin[0].arn
# }

# resource "aws_lambda_permission" "allow_cloudwatch_to_call_lambda" {
#     count = var.enable_lambda ? 1 : 0

#     statement_id = "AllowExecutionFromCloudWatch"
#     action = "lambda:InvokeFunction"
#     function_name = aws_lambda_function.update_cloudfront_alb_origin[0].function_name
#     principal = "events.amazonaws.com"
#     source_arn = aws_cloudwatch_event_rule.create_loadbalancer_event[0].arn
# }
