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
  }
}

# Retrieve EKS cluster information
provider "aws" {
  region = data.terraform_remote_state.eks.outputs.region
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      data.aws_eks_cluster.cluster.name
    ]
  }
}

provider "helm" {
  kubernetes = {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", data.aws_eks_cluster.cluster.name]
      command     = "aws"
    }
  }
}

data "terraform_remote_state" "eks" {
  backend = "remote"

  config = {
    organization = "hashicorp-training"
    workspaces = {
      name = "hcup-be-shared"
    }
  }
}

data "aws_eks_cluster" "cluster" {
  name = data.terraform_remote_state.eks.outputs.cluster_name
}

data "aws_caller_identity" "current" {}


data "kubernetes_config_map" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }
}

data "kubernetes_config_map" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  depends_on = [
    module.eks,                 # cluster must exist
    module.eks.fargate_profiles 
  ]
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

resource "kubernetes_config_map" "aws_auth_merged" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = yamlencode(local.merged_map_roles)
  }

  depends_on = [
    module.eks,
    module.eks.fargate_profiles
  ]
}

# Service account for me_website application
resource "kubernetes_service_account_v1" "me_website" {
  metadata {
    name      = "me_website-service-account"
    namespace = kubernetes_namespace.me_website_app.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = module.me_website_irsa_role.iam_role_arn
    }
  }

  depends_on = [module.eks]
}

resource "kubernetes_persistent_volume" "efs_pv" {
  metadata {
      name = "me-website-efs-pv"
  }
  spec {
    capacity = {
      storage = "5Gi"
    }
    access_modes = ["ReadWriteMany"]
    volume_mode = "Filesystem"
    persistent_volume_reclaim_policy = "Retain"
    storage_class_name = "efs"
    persistent_volume_source {
      csi {
        driver = "efs.csi.aws.com"
        volume_handle = "${module.efs.id}::${module.efs.access_points["me_website-filesystem"].id}"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim" "efs_pvc" {
  metadata {
    name      = "me-website-efs-pvc"
    namespace = kubernetes_namespace.me_website_app.metadata[0].name
  }
  spec {
    access_modes = ["ReadWriteMany"]
    resources {
      requests = {
        storage = "5Gi"
      }
    }
    storage_class_name = "efs"
    volume_name = kubernetes_persistent_volume.efs_pv.metadata[0].name
  }
  depends_on = [ kubernetes_persistent_volume.efs_pv ]
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
      name      = "me_website-app-ingress"
      namespace = "me_website-app"
      annotations = {
        "kubernetes.io/ingress.class" = "alb"
        "alb.ingress.kubernetes.io/scheme" = "internal"
        "alb.ingress.kubernetes.io/load-balancer-name" = "k8s-me_website-app-alb"
        "alb.ingress.kubernetes.io/security-groups" = join(",", [
          data.terraform_remote_state.eks.outputs.cluster_primary_security_group_id,
          data.terraform_remote_state.eks.outputs.cloudfront_alb_security_group_id
        ])
        "alb.ingress.kubernetes.io/listen-ports" = jsonencode([{ "HTTPS" = 443 }])
        "alb.ingress.kubernetes.io/conditions.secure-rule" = ""
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
                name = "me_website-app-service"
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
      name      = "me_website-sg-policy"
      namespace = "me_website-app"
    }
    spec = {
      podSelector = {
        matchLabels = {
          app = "me_website"
        }
      }
      securityGroups = {
        groupIds = [data.terraform_remote_state.eks.outputs.fargate_app_sg_id]
      }
    }
  }
}

data "archive_file" "lambda_my_function" {
  type             = "zip"
  source_file      = "../src/lambda-cloudfront.py"
  output_file_mode = "0666"
  output_path      = "${path.module}/files/cloudfront.zip"
}

resource "aws_iam_role" "lambda_cloudfront_updater_role" {
  name               = "lambda-cloudfront-updater-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    effect = "Allow"
  }
}

resource "aws_iam_policy" "specific_cloudfront_updates" {
  name        = "SpecificCloudFrontUpdatesPolicy"
  description = "Allows updating only a specific CloudFront distribution"
  policy      = data.aws_iam_policy_document.specific_cloudfront_updates.json
}

data "aws_iam_policy_document" "specific_cloudfront_updates" {
  # Allow read-only access to ALL distributions (for listing/getting)
  statement {
    sid       = "ReadOnlyAccess"
    effect    = "Allow"
    actions   = [
      "cloudfront:List*",
      "cloudfront:Get*"
    ]
    resources = ["*"]
  }

  # Restrict WRITE access to our distribution only
  statement {
    sid    = "WriteToOurDistribution"
    effect = "Allow"
    actions = [
      "cloudfront:UpdateDistribution",
      "cloudfront:UpdateCloudFrontOriginAccessIdentity"
    ]
    # REPLACE with your specific CloudFront Distribution ARN
    resources = ["arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${var.cloudfront_distribution_id}"]
  }
}

resource "aws_iam_role_policy_attachment" "attach_custom_policy" {
  role       = aws_iam_role.lambda_cloudfront_updater_role.name
  policy_arn = aws_iam_policy.specific_cloudfront_updates.arn
}

resource "aws_iam_role_policy_attachment" "additional-necessary-policies" {
  role       = aws_iam_role.lambda_cloudfront_updater_role.name
  count      = length(var.iam_policy_arn)
  policy_arn = var.iam_policy_arn[count.index]
}


data "archive_file" "alb_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/alb"
  output_path = "${path.module}/lambda/alb/alb_function.zip"

  depends_on = [terraform_data.alb_lambda_install_dependencies]
}

resource "terraform_data" "alb_lambda_install_dependencies" {
  triggers_replace = [
    filebase64sha256("${path.module}/lambda/alb/requirements.txt"),
    filebase64sha256("${path.module}/lambda/alb/lambda_function.py")
  ]

  provisioner "local-exec" {
    command = "cd ${path.module}/lambda/alb && pip install -r requirements.txt -t ."
  }
}

resource "aws_lambda_function" "update_cloudfront_alb_origin" {
  filename         = data.archive_file.alb_lambda_zip.output_path
  function_name = "cloudfront-alb-origin-update-function"
  role        = aws_iam_role.lambda_cloudfront_updater_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.alb_lambda_zip.output_base64sha256
  timeout     = 300
  memory_size = 128
  reserved_concurrent_executions = 1
  environment {
    variables = {
      cloudfront_distribution_id = var.cloudfront_distribution_id
    }
  }


  depends_on = [
    terraform_data.alb_lambda_install_dependencies,
    aws_iam_role_policy_attachment.attach_custom_policy,
    aws_iam_role_policy_attachment.additional-necessary-policies
  ]

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


