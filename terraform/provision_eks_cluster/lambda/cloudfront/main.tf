data "aws_cloudfront_distribution" "existing" {
  id = var.cloudfront_distribution_id
}

data "aws_iam_policy_document" "cloudfront_secret_rotation_lambda" {
  statement {
    effect = "Allow"
    actions = [
      "cloudfront:GetDistribution",
      "cloudfront:UpdateDistribution",
    ]
    resources = ["arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/${data.aws_cloudfront_distribution.existing.id}"]
  }

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:UpdateSecretVersionStage",
    ]
    resources = [aws_secretsmanager_secret.cloudfront_header_secret.arn]
  }

   statement {
        effect = "Allow"
        actions = ["ssm:GetParameter"]
        resources = [aws_ssm_parameter.health_check_secret.arn]
   }

  statement {
    effect = "Allow"
    actions = ["eks:DescribeCluster"]
    resources = [module.eks.cluster_arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

module "cloudfront_secret_rotation_lambda_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role"
  version = "6.2.3"

  name        = "cloudfront-secret-rotation-lambda-role"

  trust_policy_permissions = {
    lambda_assume = {
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["lambda.amazonaws.com"]
        }
      ]
      actions = ["sts:AssumeRole"]
    }
  }

  policies = {
    cloudfront_secret_rotation = aws_iam_policy.cloudfront_secret_rotation_lambda.arn
  }

  tags = local.tags
}

resource "aws_iam_policy" "cloudfront_secret_rotation_lambda" {
  name        = "cloudfront-secret-rotation-lambda-policy"
  description = "Permissions for Lambda to rotate CloudFront header & update K8s Ingress"
  policy      = data.aws_iam_policy_document.cloudfront_secret_rotation_lambda.json
}

resource "terraform_data" "cloudfront_lambda_install_dependencies" {
  triggers_replace = [
    filebase64sha256("${path.module}/lambda/cloudfront/requirements.txt"),
    filebase64sha256("${path.module}/lambda/cloudfront/lambda_function.py")
  ]

  provisioner "local-exec" {
    command = "cd ${path.module}/lambda/cloudfront && pip install -r requirements.txt -t ."
  }
}

resource "aws_lambda_function" "cloudfront_secret_rotation" {
  filename         = data.archive_file.cloudfront_lambda_zip.output_path
  function_name    = "cloudfront_secret_rotation"
  role             = module.cloudfront_secret_rotation_lambda_irsa_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.cloudfront_lambda_zip.output_base64sha256
  timeout          = 60

  # Environment variables
  environment {
    variables = {
      CLUSTER_NAME          = module.eks.cluster_name
      CLOUDFRONT_DIST_ID    = data.aws_cloudfront_distribution.existing.id
      K8S_INGRESS_NAME      = "me_website-app-ingress"
      K8S_INGRESS_NAMESPACE = "me_website-app"
    }
  }

  tags = local.tags

  depends_on = [
    terraform_data.cloudfront_lambda_install_dependencies,
    module.cloudfront_secret_rotation_lambda_irsa_role
  ]

}

resource "aws_lambda_permission" "cloudfront_allow_secrets_manager" {
  statement_id  = "AllowExecutionFromSecretsManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secret_rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_ssm_parameter" "health_check_secret" {
  name = "/me_website/prod/HEALTH_CHECK_SECRET"
  description = "Secret key for the application's health check endpoint."
  type = "String"
  tier = "Standard"
  tags = local.tags
  value_wo         = var.health_check_secret_value_wo
  value_wo_version = local.health_check_secret_version
}

resource "aws_secretsmanager_secret" "cloudfront_header_secret" {
  name = "cloudfront-alb-header-secret/me-website"
  description = "Secret for X-Secret header between CloudFront and ALB"
}

resource "aws_secretsmanager_secret_rotation" "cloudfront_header_secret_rotation" {
  secret_id           = aws_secretsmanager_secret.cloudfront_header_secret.id
  rotation_lambda_arn = aws_lambda_function.secret_rotation_sync.arn

  rotation_rules {
    automatically_after_days = 30
  }
    depends_on = [
        aws_secretsmanager_secret_version.cloudfront_header_secret_initial_version
    ]
}

resource "aws_secretsmanager_secret_version" "cloudfront_header_secret_initial_version" {
  secret_id = aws_secretsmanager_secret.cloudfront_header_secret.id
  secret_string = var.health_check_secret_value_wo

  # This tells Terraform to ignore future changes to this resource.
  # After the first rotation, AWS will manage the secret versions, not 
  # Terraform.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

data "archive_file" "cloudfront_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/cloudfront"
  output_path = "${path.module}/lambda/cloudfront/cloudfront_function.zip"

  depends_on = [terraform_data.cloudfront_lambda_install_dependencies]
}