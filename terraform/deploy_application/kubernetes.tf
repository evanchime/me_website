terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.48.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.16.1"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.9.0"
    }
  }
}

provider "aws" {
  region = data.terraform_remote_state.me_website_k8s_platform.outputs.region
}

data "aws_eks_cluster" "cluster" {
  name = data.terraform_remote_state.me_website_k8s_platform.outputs.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = file(var.tfc_kubernetes_dynamic_credentials.default.token_path)
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
    token                  = file(var.tfc_kubernetes_dynamic_credentials.default.token_path)
  }
}

locals {
  me_website_image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.eu-west-2.amazonaws.com/me_website:latest"
}

data "aws_caller_identity" "current" {}

data "kubernetes_ingress_v1" "me_website_app" {
  metadata {
    name      = kubernetes_manifest.me_website_app_ingress.manifest["metadata"]["name"]
    namespace = kubernetes_manifest.me_website_app_ingress.manifest["metadata"]["namespace"]
  }
}

module "tfc_rbac_app" {
  source = "../modules/tfc-rbac"

  mode            = "application"
  cluster_name    = module.eks.cluster_name
  target_namespace = "me-website-app"

  tfc_hostname  = var.tfc_hostname
  tfc_org       = var.tfc_org
  tfc_project   = var.tfc_project
  tfc_workspace = var.tfc_workspace

  tfc_kubernetes_audience           = var.tfc_kubernetes_audience
  tfc_kubernetes_dynamic_credentials = var.tfc_kubernetes_dynamic_credentials
}

# Service account for me_website application
resource "kubernetes_service_account_v1" "me_website" {
  metadata {
    name      = "me_website-service-account"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    annotations = {
      "eks.amazonaws.com/role-arn" = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_irsa_role_arn
    }
  }
}

resource "kubernetes_persistent_volume" "efs_pv" {
  metadata {
    name = "me-website-efs-pv"
  }

  spec {
    capacity = {
      storage = "5Gi"
    }
    access_modes                         = ["ReadWriteMany"]
    volume_mode                          = "Filesystem"
    persistent_volume_reclaim_policy     = "Retain"
    storage_class_name                   = "efs"
    persistent_volume_source {
      csi {
        driver       = "efs.csi.aws.com"
        volume_handle = "${data.terraform_remote_state.platform.outputs.efs_file_system_id}::${data.terraform_remote_state.platform.outputs.efs_access_point_id}"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "efs_pvc" {
  metadata {
    name      = "me-website-efs-pvc"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
  }
  spec {
    access_modes = ["ReadWriteMany"]
    resources {
      requests = {
        storage = "5Gi"
      }
    }
    storage_class_name = "efs"
    volume_name        = kubernetes_persistent_volume.efs_pv.metadata[0].name
  }

  depends_on = [ kubernetes_persistent_volume.efs_pv ]
}

resource "kubernetes_deployment_v1" "me_website" {
  depends_on = [
    kubernetes_manifest.me_website_secrets_provider_class
  ]

  metadata {
    name      = "me-website"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace

    labels = {
      app = "me-website"
    }
  }

  spec {
    replicas = 2


    selector {
      match_labels = {
        app = "me-website"
      }
    }

    template {
      metadata {
        labels = {
          app = "me-website"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.me_website.metadata[0].name

        # -----------------------------
        # Volumes: Secrets + EFS
        # -----------------------------
        volume {
          name = "secrets-volume"
          csi {
            driver = "secrets-store.csi.k8s.io"
            read_only = true
            volume_attributes = {
              secretProviderClass = "me-website-secrets"
            }
          }
        }

        volume {
          name = "efs-volume"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.efs_pvc.metadata[0].name
          }
        }

        container {
          name  = "me-website"
          image = local.me_website_image

          port {
            container_port = 8000
          }

          # -----------------------------
          # Mount Secrets + Media
          # -----------------------------
          volume_mount {
            name       = "secrets-volume"
            mount_path = "/var/secrets/app"
            read_only  = true
          }

          volume_mount {
            name       = "efs-volume"
            mount_path = "/app/media"
          }

          # -----------------------------
          # Environment: ConfigMap + Secret
          # -----------------------------
          env_from {
            config_map_ref {
              name = "me-website-config"
            }
          }

          env_from {
            secret_ref {
              name = "me-website-app-secrets"
            }
          }

          # -----------------------------
          # Database env vars from synced Secret
          # -----------------------------
          env {
            name = "DATABASE_HOST"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "host"
              }
            }
          }

          env {
            name = "DATABASE_USER"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "username"
              }
            }
          }

          env {
            name = "DATABASE_PASSWORD"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "password"
              }
            }
          }

          env {
            name = "DATABASE_PORT"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "port"
              }
            }
          }

          # Construct DATABASE_URL for django-environ
          env {
            name = "DATABASE_URL"
            value = "postgres://$(DATABASE_USER):$(DATABASE_PASSWORD)@$(DATABASE_HOST):$(DATABASE_PORT)/${data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_db_name}?sslmode=require"
          }

          # -----------------------------
          # Probes: Startup, Readiness, Liveness
          # -----------------------------
          startup_probe {
            http_get {
              path = "/ht/"
              port = 8000
              http_header {
                name  = "X-Health-Check-Secret"
                value = var.health_check_secret
              }
            }
            period_seconds    = 10
            failure_threshold = 30
          }

          readiness_probe {
            http_get {
              path = "/ht/"
              port = 8000
              http_header {
                name  = "X-Health-Check-Secret"
                value = var.health_check_secret
              }
            }
            initial_delay_seconds = 20
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          liveness_probe {
            http_get {
              path = "/ht/"
              port = 8000
              http_header {
                name  = "X-Health-Check-Secret"
                value = var.health_check_secret
              }
            }
            initial_delay_seconds = 60
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          # -----------------------------
          # Resource Requests/Limits
          # -----------------------------
          resources {
            requests = {
              cpu    = "200m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1"
              memory = "1Gi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_job_v1" "me_website_migrate" {
  depends_on = [
    kubernetes_manifest.me_website_secrets_provider_class
  ]

  metadata {
    name      = "me-website-migrate"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace

    labels = {
      job = "me-website-migrate"
    }
  }

  spec {
    parallelism                = 1
    completions                = 1
    backoff_limit              = 1
    ttl_seconds_after_finished = 86400

    template {
      metadata {
        labels = {
          job = "me-website-migrate"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.me_website.metadata[0].name
        restart_policy       = "OnFailure"

        # -----------------------------
        # Volumes
        # -----------------------------
        volume {
          name = "secrets-volume"

          csi {
            driver    = "secrets-store.csi.k8s.io"
            read_only = true
            volume_attributes = {
              secretProviderClass = "me-website-secrets"
            }
          }
        }

        # -----------------------------
        # Container
        # -----------------------------
        container {
          name  = "migrate"
          image = local.me_website_image

          image_pull_policy = "IfNotPresent"

          # Volume mounts
          volume_mount {
            name       = "secrets-volume"
            mount_path = "/var/secrets/app"
            read_only  = true
          }

          # envFrom: ConfigMap + Secret
          env_from {
            config_map_ref {
              name = "me-website-config"
            }
          }

          env_from {
            secret_ref {
              name = "me-website-app-secrets"
            }
          }

          # DB env vars from synced Secret
          env {
            name = "DATABASE_HOST"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "host"
              }
            }
          }

          env {
            name = "DATABASE_USER"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "username"
              }
            }
          }

          env {
            name = "DATABASE_PASSWORD"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "password"
              }
            }
          }

          env {
            name = "DATABASE_PORT"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "port"
              }
            }
          }

          # Construct DATABASE_URL
          env {
            name  = "DATABASE_URL"
            value = "postgres://$(DATABASE_USER):$(DATABASE_PASSWORD)@$(DATABASE_HOST):$(DATABASE_PORT)/${data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_db_name}?sslmode=require"
          }

          # Command + args
          command = ["python3", "manage.py"]
          args    = ["migrate", "--noinput"]
        }
      }
    }
  }
}

resource "kubernetes_job_v1" "me_website_collectstatic" {
  depends_on = [
    kubernetes_manifest.me_website_secrets_provider_class
  ]
  
  metadata {
    name      = "me-website-collectstatic"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace

    labels = {
      job = "me-website-collectstatic"
    }
  }

  spec {
    parallelism                = 1
    completions                = 1
    backoff_limit              = 1
    ttl_seconds_after_finished = 86400

    template {
      metadata {
        labels = {
          job = "me-website-collectstatic"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.me_website.metadata[0].name
        restart_policy       = "OnFailure"

        # -----------------------------
        # Volumes
        # -----------------------------
        volume {
          name = "secrets-volume"

          csi {
            driver       = "secrets-store.csi.k8s.io"
            read_only    = true
            volume_attributes = {
              secretProviderClass = "me-website-secrets"
            }
          }
        }

        # -----------------------------
        # Container
        # -----------------------------
        container {
          name  = "collectstatic"
          image = local.me_website_image
          image_pull_policy = "IfNotPresent"

          # Volume mounts
          volume_mount {
            name       = "secrets-volume"
            mount_path = "/var/secrets/app"
            read_only  = true
          }

          # envFrom: ConfigMap + Secret
          env_from {
            config_map_ref {
              name = "me-website-config"
            }
          }

          env_from {
            secret_ref {
              name = "me-website-app-secrets"
            }
          }

          # DB env vars from synced Secret
          env {
            name = "DATABASE_HOST"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "host"
              }
            }
          }

          env {
            name = "DATABASE_USER"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "username"
              }
            }
          }

          env {
            name = "DATABASE_PASSWORD"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "password"
              }
            }
          }

          env {
            name = "DATABASE_PORT"
            value_from {
              secret_key_ref {
                name = "me-website-db"
                key  = "port"
              }
            }
          }

          # Construct DATABASE_URL
          env {
            name  = "DATABASE_URL"
            value = "postgres://$(DATABASE_USER):$(DATABASE_PASSWORD)@$(DATABASE_HOST):$(DATABASE_PORT)/${data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_db_name}?sslmode=require"
          }

          # Command + args
          command = ["python3", "manage.py"]
          args    = ["collectstatic", "--noinput", "--clear"]
        }
      }
    }
  }
}

resource "aws_secretsmanager_secret" "me_website_app_secrets" {
  name        = "me-website-app-secrets"
  description = "Application secrets for the me-website Django app"
}

resource "aws_secretsmanager_secret_version" "me_website_app_secrets_version" {
  secret_id     = aws_secretsmanager_secret.me_website_app_secrets.id
  secret_string = jsonencode({
    ME_WEBSITE_DJANGO_SECRET_KEY = var.me_website_django_secret_key
    SECRET_ADMIN_URL             = var.secret_admin_url
    EMAIL_HOST_USER              = var.me_website_email_host_user
    EMAIL_HOST_PASSWORD          = var.me_website_email_host_password
    AWS_STORAGE_BUCKET_NAME      = aws_s3_bucket.buckets["static"].bucket
    AWS_S3_CUSTOM_DOMAIN         = "static.iplayishow.com"
    AWS_S3_REGION_NAME           = "eu-west-2"
    HEALTH_CHECK_SECRET          = var.health_check_secret
  })
}

resource "kubernetes_config_map_v1" "me_website_config" {
  metadata {
    name      = "me-website-config"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
  }

  data = {
    DJANGO_SETTINGS_MODULE = var.me_website_django_settings_module
    DEBUG                  = tostring(var.me_website_debug_mode)
    ALLOWED_HOSTS          = var.me_website_allowed_hosts
    CSRF_TRUSTED_ORIGINS   = "${var.me_website_csrf_trusted_origins},https://${aws_cloudfront_distribution.me_website.domain_name}"
    APP_VERSION            = var.me_website_app_version
  }
}

resource "kubernetes_manifest" "me_website_secrets_provider_class" {
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "me-website-secrets"
      namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    }
    spec = {
      provider = "aws"
      parameters = {
        objects = <<EOF
- objectName: "${data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_secret}"
  objectType: "secretsmanager"
- objectName: "me-website-app-secrets"
  objectType: "secretsmanager"
EOF
      }
      secretObjects = [
        {
          secretName = "me-website-db"
          type       = "Opaque"
          data = [
            { objectName = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_secret, key = "host" },
            { objectName = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_secret, key = "username" },
            { objectName = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_secret, key = "password" },
            { objectName = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_secret, key = "port" },
          ]
        },
        {
          secretName = "me-website-app-secrets"
          type       = "Opaque"
          data = [
            { objectName = "me-website-app-secrets", key = "ME_WEBSITE_DJANGO_SECRET_KEY" },
            { objectName = "me-website-app-secrets", key = "SECRET_ADMIN_URL" },
            { objectName = "me-website-app-secrets", key = "EMAIL_HOST_USER" },
            { objectName = "me-website-app-secrets", key = "EMAIL_HOST_PASSWORD" },
            { objectName = "me-website-app-secrets", key = "AWS_STORAGE_BUCKET_NAME" },
            { objectName = "me-website-app-secrets", key = "AWS_S3_REGION_NAME" },
            { objectName = "me-website-app-secrets", key = "AWS_S3_CUSTOM_DOMAIN" },
            { objectName = "me-website-app-secrets", key = "HEALTH_CHECK_SECRET" },
          ]
        }
      ]
    }
  }
}

resource "kubernetes_service_v1" "me_website" {
  metadata {
    name      = "me-website-app-service"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
  }

  spec {
    selector = {
      app = "me-website"
    }

    port {
      port        = 8000
      target_port = 8000
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_manifest" "letsencrypt_prod_clusterissuer" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind       = "ClusterIssuer"
    metadata = {
      name = "letsencrypt-prod"
    }
    spec = {
      acme = {
        email  = var.me_website_email_host_user
        server = "https://acme-v02.api.letsencrypt.org/directory"
        privateKeySecretRef = {
          name = "letsencrypt-prod-key"
        }
        solvers = [
          {
            dns01 = {
              route53 = {
                region       = "eu-west-2"
                hostedZoneID = data.terraform_remote_state.me_website_k8s_platform.outputs.route53_zone_id
              }
            }
          }
        ]
      }
    }
  }
}

resource "kubernetes_manifest" "me_website_app_ingress" {
  manifest = {
    apiVersion = "networking.k8s.io/v1"
    kind       = "Ingress"
    metadata = {
      name      = "me-website-app-ingress"
      namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
      annotations = {
        "kubernetes.io/ingress.class" = "alb"
        "alb.ingress.kubernetes.io/load-balancer-name" = "k8s-me-website-app-alb"
        "alb.ingress.kubernetes.io/scheme"          = "internet-facing"
        "alb.ingress.kubernetes.io/security-groups" = data.terraform_remote_state.me_website_k8s_platform.outputs.alb_security_group_id
        "alb.ingress.kubernetes.io/listen-ports" = jsonencode([{ "HTTPS" = 443 }])
        "cert-manager.io/cluster-issuer" = "letsencrypt-prod"
      }
    }
    spec = {
      tls = [
        {
            hosts      = ["app.iplayishow.com"]
            secretName = "app-iplayishow-com-tls"
        }
      ]

      rules = [
        {
            host = "app.iplayishow.com"
            http = {
                paths = [
                    {
                        path     = "/"
                        pathType = "Prefix"
                        backend = {
                            service = {
                                name = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_service_name
                                port = { number = 8000 }
                            }
                        }
                    }
                ]
            }
        }
      ]
    }
  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations["alb.ingress.kubernetes.io/conditions.secure-rule"]
    ]
  }
}

resource "kubernetes_manifest" "fargate_sg_policy" {
  manifest = {
    apiVersion = "vpcresources.k8s.aws/v1beta1"
    kind       = "SecurityGroupPolicy"
    metadata = {
      name      = "me-website-sg-policy"
      namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    }
    spec = {
      podSelector = {
        matchLabels = {
          app = "me-website"
        }
      }
      securityGroups = {
        groupIds = [data.terraform_remote_state.me_website_k8s_platform.outputs.fargate_app_sg_id]
      }
    }
  }
}

resource "terraform_data" "alb_lambda_package" {
  triggers_replace = [
    filebase64sha256("${path.module}/lambda/alb/lambda_function.py")
  ]

  provisioner "local-exec" {
    command = <<EOF
      rm -f "${path.module}/lambda/alb/lambda_function.zip"
      cd "${path.module}/lambda/alb" && zip -r lambda_function.zip lambda_function.py
    EOF
  }
}

resource "terraform_data" "alb_lambda_install_dependencies" {
  triggers_replace = [
    filebase64sha256("${path.module}/lambda/alb/requirements.txt")
  ]

  provisioner "local-exec" {
    command = <<EOF
        rm -rf "${path.module}/lambda/alb/layer"
        mkdir -p "${path.module}/lambda/alb/layer/python"
        pip install -r "${path.module}/lambda/alb/requirements.txt" -t "${path.module}/lambda/alb/layer/python"
        rm -f "${path.module}/lambda/alb/lambda_layer.zip"
        cd "${path.module}/lambda/alb/layer" && zip -r ../lambda_layer.zip .
    EOF
  }

}

resource "aws_lambda_layer_version" "lambda_layer" {
  depends_on = [terraform_data.alb_lambda_install_dependencies]

  filename   = "${path.module}/lambda/alb/lambda_layer.zip"
  layer_name = "lambda-layer"
  compatible_runtimes = ["python3.12", "python3.11", "python3.10"]

  source_code_hash = filebase64sha256("${path.module}/lambda/alb/lambda_layer.zip")
}

resource "aws_lambda_function" "update_cloudfront_alb_origin" {
  depends_on = [
    terraform_data.alb_lambda_package,
    terraform_data.alb_lambda_install_dependencies,
    aws_iam_role_policy_attachment.attach_custom_policy,
    aws_iam_role_policy_attachment.additional-necessary-policies
  ]

  filename         = "${path.module}/lambda/alb/lambda_function.zip"
  function_name    = "cloudfront-alb-origin-update-function"
  role             = aws_iam_role.lambda_cloudfront_updater_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = filebase64sha256("${path.module}/lambda/alb/lambda_function.zip")

  layers = [
    aws_lambda_layer_version.lambda_layer.arn
  ]

  timeout     = 300
  memory_size = 128
  reserved_concurrent_executions = 1

  environment {
    variables = {
      cloudfront_distribution_id = aws_cloudfront_distribution.me_website.id
    }
  }
}

resource "aws_cloudwatch_event_rule" "create_loadbalancer_event" {
  name        = "create_loadbalancer_event"
  description = "loadbalancer events"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.elasticloadbalancing"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "elasticloadbalancing.amazonaws.com"
    ],
    "eventName": [
      "CreateLoadBalancer"
    ]
  }
}
PATTERN
}

resource "aws_cloudwatch_event_target" "create_loadbalancer_event_target" {
  rule      = aws_cloudwatch_event_rule.create_loadbalancer_event.name
  target_id = "cloudfront-update"
  arn       = aws_lambda_function.update_cloudfront_alb_origin.arn
}


resource "aws_lambda_permission" "allow_cloudwatch_to_call_lambda" {
    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.update_cloudfront_alb_origin.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.create_loadbalancer_event.arn
}


