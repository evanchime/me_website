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

data "aws_caller_identity" "current" {}

data "kubernetes_config_map" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }
}

data "kubernetes_ingress_v1" "me_website_app" {
  metadata {
    name      = kubernetes_manifest.me_website_app_ingress.manifest["metadata"]["name"]
    namespace = kubernetes_manifest.me_website_app_ingress.manifest["metadata"]["namespace"]
  }
}


locals {
  existing_map_roles = (
    try(yamldecode(data.kubernetes_config_map.aws_auth.data["mapRoles"]), [])
  )
  lambda_map_role = {
    rolearn  = module.cloudfront_secret_rotation_lambda_role.arn
    username = module.cloudfront_secret_rotation_lambda_role.arn
    groups   = ["lambda-ingress-patcher"]
  }
  merged_map_roles = distinct(
    concat(local.existing_map_roles, [local.lambda_map_role])
  )
  me_website_image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.eu-west-2.amazonaws.com/me_website:latest"
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

resource "kubernetes_config_map" "aws_auth_merged" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = yamlencode(local.merged_map_roles)
  }
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
            name  = "DATABASE_HOST"
            value = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db.endpoint
          }
          env {
            name  = "DATABASE_USER"
            value = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db.username
          }
          env {
            name  = "DATABASE_PASSWORD"
            value = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_k8s_db_password
          }

          liveness_probe {
            http_get {
              path = "/ht/"
              port = 8000
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/ht/"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }

          volume_mount {
            name       = "efs-volume"
            mount_path = "/app/media"
          }
        }

        volume {
          name = "efs-volume"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.efs_pvc.metadata[0].name
          }
        }
      }
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

resource "kubernetes_manifest" "lambda_ingress_patcher_role" {
  manifest = {
    apiVersion = "rbac.authorization.k8s.io/v1"
    kind       = "Role"
    metadata = {
      name      = "ingress-patching-role"
      namespace = "me_website-app"
    }
    rules = [{
      apiGroups = ["networking.k8s.io"]
      resources = ["ingresses"]
      verbs     = ["get", "patch"]
    }]
  }
}

resource "kubernetes_manifest" "lambda_ingress_patcher_rolebinding" {
  manifest = {
    apiVersion = "rbac.authorization.k8s.io/v1"
    kind       = "RoleBinding"
    metadata = {
      name      = "ingress-patching-rolebinding"
      namespace = "me_website-app"
    }
    roleRef = {
      apiGroup = "rbac.authorization.k8s.io"
      kind     = "Role"
      name     = "ingress-patching-role"
    }
    subjects = [{
      kind = "User"
      name = module.cloudfront_secret_rotation_lambda_role.arn
      apiGroup = "rbac.authorization.k8s.io"
    }]
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
        "alb.ingress.kubernetes.io/scheme" = "internal"
        "alb.ingress.kubernetes.io/load-balancer-name" = "k8s-me-website-app-alb"
        "alb.ingress.kubernetes.io/security-groups" = join(",", [
          data.terraform_remote_state.me_website_k8s_platform.outputs.cluster_primary_security_group_id,
          data.terraform_remote_state.me_website_k8s_platform.outputs.alb_security_group_id
        ])
        "alb.ingress.kubernetes.io/listen-ports" = jsonencode([{ "HTTPS" = 443 }])
      }
    }
    spec = {
      rules = [{
        http = {
          paths = [{
            path     = "/"
            pathType = "Prefix"
            backend = {
              service = {
                name = data.terraform_remote_state.me_website_k8s_platform.outputs.me_website_app_service_name
                port = { number = 8000 }
              }
            }
          }]
        }
      }]
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


