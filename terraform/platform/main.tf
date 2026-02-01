###############################################
# PROVIDER & GLOBAL CONFIGURATION
###############################################

provider "aws" {
  region = data.terraform_remote_state.me_website_k8s_network.outputs.region
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = file(var.tfc_kubernetes_dynamic_credentials.default.token_path)
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = file(var.tfc_kubernetes_dynamic_credentials.default.token_path)
  }
}

locals {
  # Unique cluster name with random suffix
  cluster_name        = data.terraform_remote_state.me_website_k8s_network.outputs.cluster_name

  # Common tags applied to all resources
  tags = {
    Project     = "k8s-migration"
    Environment = "production"
    Terraform   = "true"
  }

  # Allow the terraform workspace variable to be overridden, but fall back to the workspace name
  tfc_workspace = var.tfc_workspace != null ? var.tfc_workspace : terraform.workspace
  
}

# Random strings for naming
resource "random_string" "suffix" {
  length  = 8
  special = false
}

resource "random_string" "prefix" {
  length  = 6
  upper   = false
  special = false
  numeric = false
}

###############################################
# DATA SOURCES
###############################################

data "aws_caller_identity" "current" {}

###############################################
# CONFIGURE K8S OIDC RBAC FOR THIS WORKSPACE 
###############################################
module "tfc_rbac_platform" {
  source = "../modules/tfc_rbac"

  mode         = "platform"
  cluster_name = module.eks.cluster_name

  tfc_hostname  = var.tfc_hostname
  tfc_org       = var.tfc_org
  tfc_project   = var.tfc_project
  tfc_workspace = local.tfc_workspace

  tfc_kubernetes_audience           = var.tfc_kubernetes_audience
  tfc_kubernetes_dynamic_credentials = var.tfc_kubernetes_dynamic_credentials
}

########################################################################################################### 
# EKS CLUSTER (Control plane + Fargate profiles) + K8S NAMESPACE + K8S CLUSTERISSUER +App FARGATE PROFILE
###########################################################################################################

resource "kubernetes_namespace_v1" "me_website_app" {
  metadata {
    name = "me-website-app"
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
                hostedZoneID = data.terraform_remote_state.me_website_k8s_network.outputs.route53_zone_id
              }
            }
          }
        ]
      }
    }
  }
}

module "fargate_me_website" {
  source  = "terraform-aws-modules/eks/aws//modules/fargate-profile"
  version = "~>21.10"

  cluster_name = module.eks.cluster_name
  name         = "fp-me-website"
  subnet_ids   = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids

  selectors = [
    {
      namespace = kubernetes_namespace_v1.me_website_app.metadata[0].name
    }
  ]

  # IRSA role for app pods
  create_iam_role            = true
  iam_role_name              = "${local.cluster_name}-fargate-me-website"
  iam_role_attach_cni_policy = true

  iam_role_additional_policies = {
    CloudWatchLogsFull = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    SecretsManagerRead = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
  }

  depends_on = [
    kubernetes_namespace_v1.me_website_app
  ]
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.10"

  name = local.cluster_name

  endpoint_public_access  = true
  endpoint_private_access = true
  endpoint_public_access_cidrs = ["0.0.0.0/0"]

  enable_cluster_creator_admin_permissions = true

  # Core EKS addons
  addons = {
    coredns   = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni   = { most_recent = true }
  }

  # Grant admin access to your SSO role
  access_entries = {
    Evan_Admin = {
      principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_AdministratorAccess_95a4a8e95b834fbe"

      policy_associations = {
        cluster = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = { type = "cluster" }
        }
      }
    }
  }

  vpc_id     = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id
  subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids

  #########################################
  # Fargate profiles — system namespaces
  #########################################

  fargate_profiles = {
    system = {
      name       = "fp-system"
      subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
      selectors = [
        { namespace = "kube-system" },
        { namespace = "default" }
      ]
    }
    cert_manager = {
        name       = "fp-cert-manager"
        subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
        selectors = [
            { namespace = "cert-manager" }
        ]
    }
  }

  tags = local.tags
}

###############################################################
# EKS ADDONS (ALB Controller, ExternalDNS, CSI Driver, etc.)
###############################################################

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.23"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  enable_aws_load_balancer_controller = true
  aws_load_balancer_controller = {
    namespace = "kube-system"
  }

  enable_metrics_server                        = true
  enable_external_dns                          = true
  enable_secrets_store_csi_driver              = true
  enable_secrets_store_csi_driver_provider_aws = true

  enable_cert_manager                          = true
  cert_manager = {
    name      = "cert-manager-core"
    namespace = "cert-manager"

    values = [
        <<-EOF
        webhook:
            securePort: 10260
            validatingWebhookConfigurationAnnotations: {}
        EOF
    ]
 }
  

  cert_manager_route53_hosted_zone_arns = [
    data.terraform_remote_state.me_website_k8s_network.outputs.route53_arn
  ]

  tags = local.tags

  depends_on = [module.eks]
}

###############################################
# EFS — Persistent storage for media files
###############################################

module "efs" {
  source  = "terraform-aws-modules/efs/aws"
  version = "~> 2.0"

  name           = "${local.cluster_name}-efs"
  creation_token = "${local.cluster_name}-efs-token"

  # One mount target per private subnet
  mount_targets = {
    ap1 = {
        subnet_id       = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids[0]
        security_groups = [module.efs_security_group.security_group_id]
    }
    ap2 = {
        subnet_id       = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids[1]
        security_groups = [module.efs_security_group.security_group_id]
    }
    ap3 = {
        subnet_id       = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids[2]
        security_groups = [module.efs_security_group.security_group_id]
    }
 }

  create_security_group = false
  
  # Access point for app media
  access_points = {
    me_website-filesystem = {
      posix_user = { uid = 1000, gid = 1000 }
      root_directory = {
        path = "/me_website-filesystem"
        creation_info = {
          owner_uid   = 1000
          owner_gid   = 1000
          permissions = "755"
        }
      }
    }
  }

  tags = local.tags
}

##################################################################
# SECURITY GROUPS — ALB, Fargate, RDS, Lambda, EKS Primary, EFS
##################################################################

# SG for Fargate app pods
module "fargate_app_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name        = "${local.cluster_name}-fargate-app-sg"
  description = "Security group for app pods on Fargate"
  vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

  ingress_with_source_security_group_id = [
    {
        rule                     = "http-80-tcp"
        source_security_group_id = module.alb_security_group.security_group_id
        description              = "From ALB to me_website pods"
    }
  ]

  egress_with_cidr_blocks = [
    {
      rule        = "all-all"
      cidr_blocks = "0.0.0.0/0"
      description = "Allow all outbound traffic"
    }
  ]

  tags = local.tags
}

# SG for ALB (internal)
module "alb_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name        = "${local.cluster_name}-alb-sg"
  description = "Security group for public ALB only reachable from CloudFront"
  vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

  ingress_with_prefix_list_ids = [
    {
      rule            = "https-443-tcp"
      prefix_list_ids = data.terraform_remote_state.me_website_k8s_network.outputs.cloudfront_origin_facing_prefix_list_id
      description     = "CloudFront edge to ALB"
    }
  ]

  egress_with_cidr_blocks = [
    {
      rule        = "http-80-tcp"
      cidr_blocks = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_cidr_block
      description = "ALB to EKS nodes/pods"
    }
  ]

  tags = local.tags
}

# SG for RDS instance
module "rds_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name        = "${local.cluster_name}-rds-sg"
  description = "Security group for the RDS instance"
  vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

  ingress_with_source_security_group_id = [
    {
      rule                     = "postgresql-tcp"
      source_security_group_id = module.fargate_app_sg.security_group_id
      description              = "Allow app pods on Fargate to access RDS PostgreSQL"
    },
    {
      rule                     = "postgresql-tcp"
      source_security_group_id = module.rds_lambda_security_group.security_group_id
      description              = "Allow Lambda to access RDS PostgreSQL"
    }
  ]

  tags = local.tags
}

# SG for EKS primary cluster SG (patching inbound rules)
module "eks_primary_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name               = "${local.cluster_name}-primary-sg"
  description        = "EKS cluster security group"
  vpc_id             = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id
  security_group_id  = module.eks.cluster_primary_security_group_id

  ingress_with_source_security_group_id = [
    {
      rule                     = "http-80-tcp"
      source_security_group_id = module.alb_security_group.security_group_id
      description              = "From ALB to me_website pods"
    },
    {
      rule                     = "all-all"
      source_security_group_id = module.eks.cluster_primary_security_group_id
      description              = "Internal EKS cluster communication"
    }
  ]

  egress_with_cidr_blocks = [
    {
      rule        = "https-443-tcp"
      cidr_blocks = "0.0.0.0/0"
      description = "me_website to AWS services & internet"
    },
    {
      rule        = "dns-udp"
      cidr_blocks = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_cidr_block
      description = "DNS resolution"
    },
    {
      rule        = "dns-tcp"
      cidr_blocks = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_cidr_block
      description = "DNS resolution"
    }
  ]

  tags = local.tags
}

# SG for EFS filesystem
module "efs_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name        = "${local.cluster_name}-efs-sg"
  description = "Security group for EFS filesystem"
  vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

  ingress_with_source_security_group_id = [ 
    {
        rule = "nfs-tcp"
        source_security_group_id = module.eks.cluster_primary_security_group_id
        description = "Allow EKS cluster to access EFS via NFS"
    }
   ]

  tags = local.tags
}

###############################################################
# RDS — Subnet group, parameter group, instance
###############################################################

resource "aws_db_subnet_group" "me_website_rds" {
  name       = "me_website-rds"
  subnet_ids = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
  tags       = local.tags
}

resource "aws_db_parameter_group" "me_website_k8s_rds_parameters" {
  name_prefix = "pg-${random_string.prefix.id}-"
  family      = "postgres17"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "me_website_k8s_db" {
  identifier                  = "me-webiste-database-instance-k8s"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  apply_immediately           = true
  engine                      = "postgres"
  engine_version              = "17.4"
  username                    = "me_website_k8s_admin"
  password                    = random_password.db_password.result
  allow_major_version_upgrade = true

  db_subnet_group_name   = aws_db_subnet_group.me_website_rds.name
  vpc_security_group_ids = [module.rds_security_group.security_group_id]
  parameter_group_name   = aws_db_parameter_group.me_website_k8s_rds_parameters.name

  skip_final_snapshot     = true
  backup_retention_period = 1
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

###############################################################
# SECRETS MANAGER — RDS master credentials + rotation
###############################################################

resource "aws_secretsmanager_secret" "rds_master_credentials" {
  name        = "rds-master-credentials/me-website-k8s"
  description = "Master credentials for the me-website-k8s RDS PostgreSQL instance"
}

resource "aws_secretsmanager_secret_version" "rds_master_initial_version" {
  secret_id = aws_secretsmanager_secret.rds_master_credentials.id

  secret_string = jsonencode({
    engine   = aws_db_instance.me_website_k8s_db.engine
    host     = aws_db_instance.me_website_k8s_db.address
    username = aws_db_instance.me_website_k8s_db.username
    password = random_password.db_password.result
    port     = aws_db_instance.me_website_k8s_db.port
  })

  depends_on = [ aws_db_instance.me_website_k8s_db ]

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_rotation" "rds_master_rotation" {
  secret_id           = aws_secretsmanager_secret.rds_master_credentials.id
  rotation_lambda_arn = aws_lambda_function.rds_postgres_rotation.arn

  rotation_rules {
    automatically_after_days = 30
  }

  depends_on = [
    aws_secretsmanager_secret_version.rds_master_initial_version
  ]
}

###############################################################
# IAM — IRSA role for me_website app
###############################################################

module "me_website_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.2"

  name = "${local.cluster_name}-me_website-app"

  policies = {
    me_website_app = aws_iam_policy.me_website_app.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["me_website-app:me_website-service-account"]
    }
  }

  tags = local.tags
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
      "arn:aws:rds-db:${var.region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.me_website_k8s_db.resource_id}/${aws_db_instance.me_website_k8s_db.username}"
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

###############################################################
# LAMBDA — RDS password rotation function
###############################################################

# IAM trust policy document allowing the Lambda service (lambda.amazonaws.com) 
# to assume the rotation function's IAM role.
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

# IAM policy document granting the rotation Lambda permissions for 
# EC2 networking, Secrets Manager operations, and RDS updates.
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

# IAM role and policies for the RDS rotation Lambda function
resource "aws_iam_role" "rds_secrets_rotation_lambda" {
  name               = "rds_secrets_rotation_lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.rds_secrets_rotation_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_permissions_policy" {
  name   = "lambda_permissions_policy"
  role   = aws_iam_role.rds_secrets_rotation_lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions_policy.json
}

# Lambda security group
module "rds_lambda_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name        = "${local.cluster_name}-lambda-rds-sg"
  description = "Security group for the RDS instance"
  vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

  # Allow Lambda → RDS
  egress_with_source_security_group_id = [
    {
      rule                     = "postgresql-tcp"
      source_security_group_id = module.rds_security_group.security_group_id
      description              = "Allow Lambda to access RDS PostgreSQL"
    }
  ]

  # Allow Lambda → Secrets Manager
  egress_with_cidr_blocks = [
    {
      rule        = "https-443-tcp"
      cidr_blocks = "0.0.0.0/0"
      description = "Allow Lambda to access Secrets Manager"
    }
  ]

  tags = local.tags
}

resource "terraform_data" "rds_lambda_package" {
  triggers_replace = [
    filebase64sha256("${path.module}/lambda/rds/lambda_function.py")
  ]

  provisioner "local-exec" {
    command = <<EOF
      rm -f "${path.module}/lambda/rds/lambda_function.zip"
      cd "${path.module}/lambda/rds" && zip -r lambda_function.zip lambda_function.py
    EOF
  }
}

resource "terraform_data" "rds_lambda_install_dependencies"{
    triggers_replace = [
        filebase64sha256("${path.module}/lambda/rds/requirements.txt")
    ]
    provisioner "local-exec" {
        command = <<EOF
            rm -rf "${path.module}/lambda/rds/layer"
            rm -f "${path.module}/lambda/rds/lambda_layer.zip"
            mkdir -p "${path.module}/lambda/rds/layer/python"

            docker run \
            --rm \
            -v "${path.module}/lambda/rds":/var/task \
            public.ecr.aws/lambda/python:3.11 \
            /bin/bash -c "\
                pip install -r requirements.txt -t layer/python && \
                cd layer && zip -r ../lambda_layer.zip . \
            "
        EOF
    }
}

resource "aws_lambda_layer_version" "lambda_layer" {
  depends_on = [terraform_data.rds_lambda_install_dependencies]
  filename   = "${path.module}/lambda/rds/lambda_layer.zip"
  layer_name = "lambda-layer"
  compatible_runtimes = ["python3.11"]
  source_code_hash = filebase64sha256("${path.module}/lambda/rds/lambda_layer.zip")
}

# Lambda function
resource "aws_lambda_function" "rds_postgres_rotation" {
  filename         = "${path.module}/lambda/rds/lambda_function.zip"
  function_name    = "rds_postgres_rotation_single_user"
  role             = aws_iam_role.rds_secrets_rotation_lambda.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60

  layers = [
    aws_lambda_layer_version.lambda_layer.arn
  ]

  # Environment variables for rotation logic
  environment {
    variables = {
      DATABASE_TIMEOUT   = "10"
      EXCLUDE_CHARACTERS = "/@\"'\\"
      LOG_LEVEL          = "INFO"
      ENVIRONMENT        = "production"
      APPLICATION        = "me_website"
    }
  }

  # Ensure dependencies, IAM role, and SG exist before Lambda is created
  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    module.rds_lambda_security_group,
    terraform_data.rds_lambda_package,
    terraform_data.rds_lambda_install_dependencies,
  ]

  # Lambda runs inside the VPC to reach RDS
  vpc_config {
    subnet_ids         = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
    security_group_ids = [module.rds_lambda_security_group.security_group_id]
  }

  tags = local.tags
}

# Allow Secrets Manager to invoke the rotation Lambda
resource "aws_lambda_permission" "rds_allow_secret_manager" {
  statement_id  = "AllowExecutionFromSecretManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rds_postgres_rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}