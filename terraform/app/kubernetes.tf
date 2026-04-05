provider "aws" {
  region = data.terraform_remote_state.me_website_k8s_platform.outputs.region
}

provider "grafana" {
  url  = "https://${data.terraform_remote_state.me_website_k8s_platform.outputs.grafana_url}"
  auth = var.grafana_api_key # You'll need to generate this after initial login
}

data "aws_eks_cluster" "cluster" {
  name = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", data.aws_eks_cluster.cluster.name]
  }
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", data.aws_eks_cluster.cluster.name]
    }
  }
}

locals {
  me_website_image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.eu-west-2.amazonaws.com/me_website:${var.me_website_image_tag}"

  # Common tags applied to all resources
  tags = {
    Project     = "k8s-migration"
    Environment = "production"
    Terraform   = "true"
  }
}

data "aws_caller_identity" "current" {}

# Service account for me_website application
resource "kubernetes_service_account_v1" "me_website" {
  metadata {
    name      = "me-website-service-account"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    annotations = {
      "eks.amazonaws.com/role-arn" = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_irsa_role_arn
    }
  }
}

resource "kubernetes_deployment_v1" "me_website" {
  depends_on = [
    kubernetes_manifest.fargate_sg_policy_app,
    kubernetes_job_v1.me_website_migrate,
    kubernetes_job_v1.me_website_collectstatic
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

        container {
          name  = "me-website"
          image = local.me_website_image

          port {
            container_port = 8000
          }

          env {
            name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
            value = "http://localhost:4317"
          }

          env {
            name  = "OTEL_EXPORTER_OTLP_INSECURE"
            value = "true"
          }

          # envFrom: ConfigMap + Secret
          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.me_website_config.metadata[0].name
            }
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.me_website_app_secrets.metadata[0].name
            }
          }

          # DB env vars from K8s Secret
          env {
            name = "DATABASE_HOST"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "host"
              }
            }
          }

          env {
            name = "DATABASE_USER"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "username"
              }
            }
          }

          env {
            name = "DATABASE_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "password"
              }
            }
          }

          env {
            name = "DATABASE_PORT"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "port"
              }
            }
          }

          env {
            name = "DATABASE_NAME"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "dbname"
              }
            }
          }

          # Probes
          startup_probe {
            exec {
              command = [
                "sh",
                "-c",
                "curl -fsS -H \"X-Health-Check-Secret: $HEALTH_CHECK_SECRET\" http://localhost:8000/ht/"
              ]
            }
            timeout_seconds   = 3
            period_seconds    = 10
            failure_threshold = 30
          }

          readiness_probe {
            exec {
              command = [
                "sh",
                "-c",
                "curl -fsS -H \"X-Health-Check-Secret: $HEALTH_CHECK_SECRET\" http://localhost:8000/ht/"
              ]
            }
            initial_delay_seconds = 20
            period_seconds        = 10
            timeout_seconds       = 3
            failure_threshold     = 3
          }

          liveness_probe {
            exec {
              command = [
                "sh",
                "-c",
                "curl -fsS -H \"X-Health-Check-Secret: $HEALTH_CHECK_SECRET\" http://localhost:8000/ht/"
              ]
            }
            initial_delay_seconds = 60
            period_seconds        = 30
            timeout_seconds       = 5
            failure_threshold     = 3
          }

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

        # --- ADOT Sidecar ---
        container {
          name    = "adot-collector"
          image   = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
          command = ["/awscollector"]
          args    = ["--config=/etc/otel-config.yaml"]

          port {
            container_port = 4317 # OTLP gRPC
          }

          port {
            container_port = 4318 # OTLP HTTP
          }

          env {
            name  = "AWS_REGION"
            value = data.terraform_remote_state.me_website_k8s_platform.outputs.region
          }

          volume_mount {
            name       = "adot-config-volume"
            mount_path = "/etc/otel-config.yaml"
            sub_path   = "otel-config.yaml"
          }
        }

        volume {
          name = "adot-config-volume"
          config_map {
            name = kubernetes_config_map_v1.adot_app_config.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_job_v1" "me_website_migrate" {
  depends_on = [
    kubernetes_manifest.fargate_sg_policy_jobs
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
    backoff_limit              = 6
    ttl_seconds_after_finished = 86400

    template {
      metadata {
        labels = {
          job = "me-website-migrate"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.me_website.metadata[0].name
        restart_policy       = "Never"

        container {
          name  = "migrate"
          image = local.me_website_image
          image_pull_policy = "IfNotPresent"

          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.me_website_config.metadata[0].name
            }
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.me_website_app_secrets.metadata[0].name
            }
          }

          env {
            name = "DATABASE_HOST"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "host"
              }
            }
          }

          env {
            name = "DATABASE_USER"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "username"
              }
            }
          }

          env {
            name = "DATABASE_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "password"
              }
            }
          }

          env {
            name = "DATABASE_PORT"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "port"
              }
            }
          }

          env {
            name = "DATABASE_NAME"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "dbname"
              }
            }
          }

          command = ["/app/entrypoint.sh"]
          args    = ["python3", "manage.py", "migrate", "--noinput"]
        }
      }
    }
  }
  
  wait_for_completion = true
  timeouts {
    create = "10m"
    update = "10m"
  }
}

resource "kubernetes_job_v1" "me_website_collectstatic" {
  depends_on = [
    kubernetes_manifest.fargate_sg_policy_jobs
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
    backoff_limit              = 6
    ttl_seconds_after_finished = 86400

    template {
      metadata {
        labels = {
          job = "me-website-collectstatic"
        }
      }

      spec {
        service_account_name = kubernetes_service_account_v1.me_website.metadata[0].name
        restart_policy       = "Never"

        container {
          name  = "collectstatic"
          image = local.me_website_image
          image_pull_policy = "IfNotPresent"

          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.me_website_config.metadata[0].name
            }
          }

          env_from {
            secret_ref {
              name = kubernetes_secret_v1.me_website_app_secrets.metadata[0].name
            }
          }

          env {
            name = "DATABASE_HOST"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "host"
              }
            }
          }

          env {
            name = "DATABASE_USER"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "username"
              }
            }
          }

          env {
            name = "DATABASE_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "password"
              }
            }
          }

          env {
            name = "DATABASE_PORT"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "port"
              }
            }
          }

          env {
            name = "DATABASE_NAME"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.me_website_db.metadata[0].name
                key  = "dbname"
              }
            }
          }

          command = ["/app/entrypoint.sh"]
          args    = ["python3", "manage.py", "collectstatic", "--noinput", "--clear"]
        }
      }
    }
  }

  wait_for_completion = true
  timeouts {
    create = "5m"
    update = "5m"
  }
}

resource "kubernetes_config_map_v1" "adot_app_config" {
  metadata {
    name      = "adot-app-config"
    namespace = "me-website-app"
  }

  data = {
    "otel-config.yaml" = <<EOF
extensions:
  sigv4auth:
    region: "${data.terraform_remote_state.me_website_k8s_platform.outputs.region}"
    service: "aps"

receivers:
  otlp:
    protocols:
      grpc:
      http:

exporters:
  prometheusremotewrite:
    endpoint: "${data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_prometheus_workspace_endpoint}api/v1/remote_write"
    auth:
      authenticator: sigv4auth
  awsxray:
    region: "${data.terraform_remote_state.me_website_k8s_platform.outputs.region}"

service:
  extensions: [sigv4auth]
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheusremotewrite]
    traces:
      receivers: [otlp]
      exporters: [awsxray]
EOF
  }
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
    CSRF_TRUSTED_ORIGINS   = "${var.me_website_csrf_trusted_origins},https://${data.terraform_remote_state.me_website_k8s_network.outputs.cloudfront_distribution_domain_name}"
    APP_VERSION            = var.me_website_app_version
  }
}

resource "kubernetes_secret_v1" "me_website_app_secrets" {
  metadata {
    name      = "me-website-app-secrets"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
  }

  data = {
    ME_WEBSITE_DJANGO_SECRET_KEY = var.me_website_django_secret_key
    SECRET_ADMIN_URL             = var.me_website_secret_admin_url
    EMAIL_HOST_USER              = var.me_website_email_host_user
    EMAIL_HOST_PASSWORD          = var.me_website_email_host_password
    AWS_STORAGE_BUCKET_NAME      = data.terraform_remote_state.me_website_k8s_network.outputs.s3_static_assets_bucket
    AWS_S3_CUSTOM_DOMAIN         ="static.iplayishow.com"
    AWS_S3_REGION_NAME           = data.terraform_remote_state.me_website_k8s_platform.outputs.region
    HEALTH_CHECK_SECRET          = var.me_website_health_check_secret
  }

  type = "Opaque"
}

resource "kubernetes_secret_v1" "me_website_db" {
  metadata {
    name      = "me-website-db"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
  }

  data = {
    host     = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_host
    username = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_username
    password = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_password
    port     = tostring(data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_port)
    dbname   = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_name
  }

  type = "Opaque"
}

resource "kubernetes_service_v1" "me_website_app_service" {
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

resource "kubernetes_service_v1" "adot_collector_service" {
  metadata {
    name      = "adot-collector-service"
    namespace = "${data.terraform_remote_state.me_website_k8s_platform.outputs.adot_col_namespace}"
    labels = {
      app       = "aws-adot"
      component = "adot-collector"
    }
  }

  spec {
    selector = {
      component = "adot-collector"
    }

    port {
      name        = "metrics"
      port        = 8888
      target_port = 8888
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_ingress_v1" "me_website_app_ingress" {
  wait_for_load_balancer = true

  metadata {
    name      = "me-website-app-ingress"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    
    annotations = {
      "alb.ingress.kubernetes.io/load-balancer-name" = "k8s-me-website-app-alb"
      "alb.ingress.kubernetes.io/target-type"       = "ip"
      "alb.ingress.kubernetes.io/scheme"            = "internet-facing"
      "alb.ingress.kubernetes.io/security-groups"   = data.terraform_remote_state.me_website_k8s_platform.outputs.alb_security_group_id
      "alb.ingress.kubernetes.io/listen-ports"      = jsonencode([{ "HTTP" = 80 }])
      "alb.ingress.kubernetes.io/healthcheck-path"  = "/health/"
    }
  }

  spec {
    ingress_class_name = "alb"

    rule {
      host = "www.iplayishow.com"
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.me_website_app_service.metadata[0].name
              port {
                number = 8000
              }
            }
          }
        }
      }
    }

    rule {
      host = "iplayishow.com"
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.me_website_app_service.metadata[0].name
              port {
                number = 8000
              }
            }
          }
        }
      }
    }
  }
}

# Policy for main app pods
resource "kubernetes_manifest" "fargate_sg_policy_app" {
  manifest = {
    apiVersion = "vpcresources.k8s.aws/v1beta1"
    kind       = "SecurityGroupPolicy"
    metadata = {
      name      = "me-website-sg-policy-app"
      namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    }
    spec = {
      podSelector = {
        matchLabels = {
          app = "me-website"
        }
      }
      securityGroups = {
        groupIds = [
          data.terraform_remote_state.me_website_k8s_platform.outputs.fargate_app_sg_id,
          data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        ]
      }
    }
  }
}

# Policy for both job types
resource "kubernetes_manifest" "fargate_sg_policy_jobs" {
  manifest = {
    apiVersion = "vpcresources.k8s.aws/v1beta1"
    kind       = "SecurityGroupPolicy"
    metadata = {
      name      = "me-website-sg-policy-jobs"
      namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_kubernetes_namespace
    }
    spec = {
      podSelector = {
        matchExpressions = [
          {
            key      = "job"
            operator = "In"
            values   = ["me-website-migrate", "me-website-collectstatic"]
          }
        ]
      }
      securityGroups = {
        groupIds = [
          data.terraform_remote_state.me_website_k8s_platform.outputs.fargate_app_sg_id,
          data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        ]
      }
    }
  }
}

resource "aws_route53_record" "alb_cname" {
  depends_on = [kubernetes_ingress_v1.me_website_app_ingress]
  
  zone_id = data.terraform_remote_state.me_website_k8s_network.outputs.route53_zone_id
  name    = "alb"
  type    = "CNAME"
  ttl     = 60
  records = [kubernetes_ingress_v1.me_website_app_ingress.status[0].load_balancer[0].ingress[0].hostname]
}

resource "kubernetes_stateful_set_v1" "adot_infra" {
  metadata {
    name      = "adot-collector"
    namespace = data.terraform_remote_state.me_website_k8s_platform.outputs.adot_col_namespace
  }

  spec {
    service_name = "adot-collector-service"
    replicas     = 1

    selector {
      match_labels = { app = "aws-adot", component = "adot-collector" }
    }

    template {
      metadata {
        labels = { app = "aws-adot", component = "adot-collector" }
      }

      spec {
        service_account_name = "adot-collector"
        
        container {
          name    = "adot-collector"
          image   = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
          command = ["/awscollector"]
          args    = ["--config=/conf/otel-config.yaml"]

          resources {
            limits = {
              cpu    = "250m"
              memory = "512Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "256Mi"
            }
          }

          env {
            name  = "OTEL_RESOURCE_ATTRIBUTES"
            value = "ClusterName=${data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name}"
          }

          volume_mount {
            name       = "adot-infra-config-volume"
            mount_path = "/etc/otel-config.yaml"
            sub_path   = "otel-config.yaml"
          }
        }

        volume {
          name = "adot-infra-config-volume"
          config_map {
            name = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_adot_infra_config_map
          }
        }
      }
    }
  }
}

