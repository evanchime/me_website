locals {
  alb_sa_name     = "aws-load-balancer-controller"
  alb_policy_path = "${path.module}/policy/aws-load-balancer-controller.json"
  namespace = "kube-system"
  external_dns_sa_name   = "external-dns"
  external_dns_policy    = "${path.module}/policy/external-dns-route53.json"
}

data "aws_iam_policy_document" "external_dns_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/", "")}:sub"

      values = [
        "system:serviceaccount:${local.namespace}:${local.external_dns_sa_name}"
      ]
    }
  }
}
  
resource "aws_iam_role" "external_dns" {
  name               = "${data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name}-external-dns"
  assume_role_policy = data.aws_iam_policy_document.external_dns_assume_role.json
  tags               = local.tags
}

resource "aws_iam_policy" "external_dns" {
  name   = "${data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name}-external-dns-route53"
  policy = file(local.external_dns_policy)
  tags   = local.tags
}

resource "aws_iam_role_policy_attachment" "external_dns" {
  role       = aws_iam_role.external_dns.name
  policy_arn = aws_iam_policy.external_dns.arn
}

data "aws_iam_policy_document" "alb_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn, "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/", "")}:sub"
      values = [
        "system:serviceaccount:${local.namespace}:${local.alb_sa_name}"
      ]
    }
  }
}

resource "aws_iam_role" "alb" {
  name               = "${data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name}-alb-controller"
  assume_role_policy = data.aws_iam_policy_document.alb_assume_role.json
  tags               = local.tags
}

resource "aws_iam_policy" "alb" {
  name   = "${data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name}-alb-controller-policy"
  policy = file(local.alb_policy_path)
  tags   = local.tags
}

resource "aws_iam_role_policy_attachment" "alb" {
  role       = aws_iam_role.alb.name
  policy_arn = aws_iam_policy.alb.arn
}

# IAM policy document granting the me_website application access to 
# S3, Secrets Manager, and RDS IAM authentication.
data "aws_iam_policy_document" "me_website_app" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = data.terraform_remote_state.me_website_k8s_network.outputs.s3_bucket_resources
  }

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [
      aws_secretsmanager_secret.rds_master_credentials.arn
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "rds-db:connect"
    ]
    resources = [
      "arn:aws:rds-db:${data.terraform_remote_state.me_website_k8s_eks.outputs.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.me_website_k8s_db.resource_id}/${aws_db_instance.me_website_k8s_db.username}"
    ]
  }
}

# IAM policy resource attaching the me_website app permissions 
# (S3, Secrets Manager, RDS IAM auth).
resource "aws_iam_policy" "me_website_app" {
  name        = "${local.cluster_name}-me_website-app-policy"
  description = "Policy for me_website application"
  policy      = data.aws_iam_policy_document.me_website_app.json
  tags        = local.tags
}

resource "aws_iam_role_policy" "me_website_logging" {
  name = "me-website-cloudwatch-logging"
  role = data.terraform_remote_state.me_website_k8s_eks.outputs.me_website_fargate_profile_pod_exec_role
 
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogStream",
        "logs:CreateLogGroup",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}