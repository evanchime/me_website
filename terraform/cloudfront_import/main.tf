# cloudfront-import/main.tf
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}
provider "aws" {
  region = "us-east-1" # CloudFront resources are global, but use us-east-1 for the provider
}

resource "aws_cloudfront_distribution" "distribution" {
    aliases                         = [
        "iplayishow.com",
        "static.iplayishow.com",
        "www.iplayishow.com",
    ]
    anycast_ip_list_id              = null
    arn                             = "arn:aws:cloudfront::661510969671:distribution/E1UWBXVQBOWYCU"
    caller_reference                = "1c24232d-d46d-44f8-937d-1adcf7ca0b4d"
    continuous_deployment_policy_id = null
    default_root_object             = null
    domain_name                     = "d2qrn0fo3yrnru.cloudfront.net"
    enabled                         = true
    etag                            = "E1EJPBTXJVVF2V"
    hosted_zone_id                  = "Z2FDTNDATAQYW2"
    http_version                    = "http2and3"
    id                              = "E1UWBXVQBOWYCU"
    in_progress_validation_batches  = 0
    is_ipv6_enabled                 = true
    last_modified_time              = "2025-10-09 04:01:05.481 +0000 UTC"
    logging_v1_enabled              = false
    price_class                     = "PriceClass_All"
    retain_on_delete                = false
    staging                         = false
    status                          = "Deployed"
    tags                            = {}
    tags_all                        = {}
    trusted_key_groups              = [
        {
            enabled = false
            items   = []
        },
    ]
    trusted_signers                 = [
        {
            enabled = false
            items   = []
        },
    ]
    wait_for_deployment             = true
    web_acl_id                      = null

    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 400
        response_code         = 400
        response_page_path    = "/errors/400.html"
    }
    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 403
        response_code         = 403
        response_page_path    = "/errors/403.html"
    }
    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 404
        response_code         = 404
        response_page_path    = "/errors/404.html"
    }
    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 500
        response_code         = 500
        response_page_path    = "/errors/500.html"
    }
    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 502
        response_code         = 502
        response_page_path    = "/errors/500.html"
    }
    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 503
        response_code         = 503
        response_page_path    = "/errors/500.html"
    }
    custom_error_response {
        error_caching_min_ttl = 10
        error_code            = 504
        response_code         = 504
        response_page_path    = "/errors/500.html"
    }

    default_cache_behavior {
        allowed_methods            = [
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT",
        ]
        cache_policy_id            = "d28f3cd2-c7df-4f9c-869b-c4ff433fb74b"
        cached_methods             = [
            "GET",
            "HEAD",
        ]
        compress                   = true
        default_ttl                = 0
        field_level_encryption_id  = null
        max_ttl                    = 0
        min_ttl                    = 0
        origin_request_policy_id   = "5bc19d50-2297-45ff-9b93-2cb198db5484"
        realtime_log_config_arn    = null
        response_headers_policy_id = null
        smooth_streaming           = false
        target_origin_id           = "ec2-3-9-178-161.eu-west-2.compute.amazonaws.com"
        trusted_key_groups         = []
        trusted_signers            = []
        viewer_protocol_policy     = "redirect-to-https"

        grpc_config {
            enabled = false
        }
    }

    ordered_cache_behavior {
        allowed_methods            = [
            "GET",
            "HEAD",
            "OPTIONS",
        ]
        cache_policy_id            = "658327ea-f89d-4fab-a63d-7e88639e58f6"
        cached_methods             = [
            "GET",
            "HEAD",
        ]
        compress                   = true
        default_ttl                = 0
        field_level_encryption_id  = null
        max_ttl                    = 0
        min_ttl                    = 0
        origin_request_policy_id   = null
        path_pattern               = "/static/*"
        realtime_log_config_arn    = null
        response_headers_policy_id = "4e525da8-319b-40d2-8a32-72499ae5da61"
        smooth_streaming           = false
        target_origin_id           = "me-website-bucket.s3.eu-west-2.amazonaws.com"
        trusted_key_groups         = []
        trusted_signers            = []
        viewer_protocol_policy     = "redirect-to-https"

        grpc_config {
            enabled = false
        }
    }
    ordered_cache_behavior {
        allowed_methods            = [
            "GET",
            "HEAD",
        ]
        cache_policy_id            = "b5728d30-8c7d-4f3f-8a64-6417da4a466e"
        cached_methods             = [
            "GET",
            "HEAD",
        ]
        compress                   = true
        default_ttl                = 0
        field_level_encryption_id  = null
        max_ttl                    = 0
        min_ttl                    = 0
        origin_request_policy_id   = null
        path_pattern               = "/errors/*"
        realtime_log_config_arn    = null
        response_headers_policy_id = null
        smooth_streaming           = false
        target_origin_id           = "me-website-static-error-pages-bucket.s3.eu-west-2.amazonaws.com"
        trusted_key_groups         = []
        trusted_signers            = []
        viewer_protocol_policy     = "redirect-to-https"

        grpc_config {
            enabled = false
        }
    }

    origin {
        connection_attempts         = 3
        connection_timeout          = 10
        domain_name                 = "ec2-3-9-178-161.eu-west-2.compute.amazonaws.com"
        origin_access_control_id    = null
        origin_id                   = "ec2-3-9-178-161.eu-west-2.compute.amazonaws.com"
        origin_path                 = null
        response_completion_timeout = 0


        custom_origin_config {
            http_port                = 80
            https_port               = 443
            ip_address_type          = null
            origin_keepalive_timeout = 5
            origin_protocol_policy   = "https-only"
            origin_read_timeout      = 30
            origin_ssl_protocols     = [
                "TLSv1.2",
            ]
        }
    }
    origin {
        connection_attempts         = 3
        connection_timeout          = 10
        domain_name                 = "me-website-bucket.s3.eu-west-2.amazonaws.com"
        origin_access_control_id    = "E22WCEJAR6758S"
        origin_id                   = "me-website-bucket.s3.eu-west-2.amazonaws.com"
        origin_path                 = null
        response_completion_timeout = 0
    }
    origin {
        connection_attempts         = 3
        connection_timeout          = 10
        domain_name                 = "me-website-static-error-pages-bucket.s3.eu-west-2.amazonaws.com"
        origin_access_control_id    = "E36POSVKU25VQM"
        origin_id                   = "me-website-static-error-pages-bucket.s3.eu-west-2.amazonaws.com"
        origin_path                 = null
        response_completion_timeout = 0
    }

    restrictions {
        geo_restriction {
            locations        = []
            restriction_type = "none"
        }
    }

    viewer_certificate {
        acm_certificate_arn            = "arn:aws:acm:us-east-1:661510969671:certificate/a356c6a6-82fc-4c32-a0eb-fe10ca213bcf"
        cloudfront_default_certificate = false
        iam_certificate_id             = null
        minimum_protocol_version       = "TLSv1.2_2021"
        ssl_support_method             = "sni-only"
    }
}
# import {
#   to = aws_cloudfront_distribution.distribution
#   id = "E1UWBXVQBOWYCU"
# }
