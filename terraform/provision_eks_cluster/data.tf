data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_route53_zone" "iplayishow" {
  name = "${trimsuffix(var.domain_name, ".")}."
}

# IAM role for me_website application (for accessing RDS, S3, etc.)
data "aws_iam_policy_document" "me_website_app" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]
    resources = [
      "arn:aws:s3:::me-website-bucket",
      "arn:aws:s3:::me-website-bucket/*",
      "arn:aws:s3:::me-website-static-error-pages-bucket",
      "arn:aws:s3:::me-website-static-error-pages-bucket/*"
    ]
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
      "arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.me_website_k8s_db.resource_id}/${aws_db_instance.me_website_k8s_db.username}"
    ]
  }
}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_permissions_policy" {
  statement {
    actions   = ["ec2:Describe*"]
    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    resources = [aws_secretsmanager_secret.rds_master_credentials.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetRandomPassword"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:DeleteNetworkInterface",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSubnets",
      "ec2:DetachNetworkInterface",
      "ec2:AssignPrivateIpAddresses",
      "ec2:UnassignPrivateIpAddresses",
    ]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "lambda:SourceFunctionArn"
      values   = [aws_lambda_function.rds_postgres_rotation.arn]
    }
  }
    
  statement {
    effect = "Allow"
    actions = [
    "rds:DescribeDBInstances",
    "rds:ModifyDBInstance",
    ]
    resources = [aws_db_instance.me_website_k8s_db.arn]
  }
}

data "archive_file" "rds_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/rds"
  output_path = "${path.module}/lambda/rds/rds_function.zip"

  depends_on = [terraform_data.rds_lambda_install_dependencies]
}

