###############################################
# PROVIDER & GLOBAL CONFIGURATION
###############################################

provider "aws" {
  region = var.region
}


data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

locals {
  # Unique cluster name with random suffix
  cluster_name        = "meweb-eks"

  # Common tags applied to all resources
  tags = {
    Project     = "k8s-migration"
    Environment = "production"
    Terraform   = "true"
  }
  
  # Current IP for EKS API access
  my_ip_cidr = "${data.external.my_ip.result.ip}/32"

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

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_route53_zone" "iplayishow" {
  name = "${trimsuffix(var.domain_name, ".")}."
}

data "external" "my_ip" {
  program = [
    "bash",
    "-c",
    "echo '{\"ip\": \"'$(curl -s https://checkip.amazonaws.com)'\"}'"
  ]
}

#######################################################
# VPC — Networking foundation for EKS, Lambda, and RDS
#######################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.5"

  name = "me_website-vpc"
  cidr = "10.0.0.0/16"

  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Required for EKS load balancers
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  # Required for EKS Fargate + VPC CNI
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/pod-eni" = "1"
  }

  tags = local.tags
}

#######################################################################################
# EKS CLUSTER (Control plane + Fargate profiles) + K8S NAMESPACE + App FARGATE PROFILE
#######################################################################################

resource "kubernetes_namespace_v1" "me_website_app" {
  metadata {
    name = "me-website-app"
  }
}

module "fargate_me_website" {
  source  = "terraform-aws-modules/eks/aws//modules/fargate-profile"
  version = "~>21.10"

  cluster_name = module.eks.cluster_name
  name         = "fp-me-website"
  subnet_ids   = module.vpc.private_subnets

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

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  #########################################
  # Fargate profiles — system namespaces
  #########################################

  fargate_profiles = {
    system = {
      name       = "fp-system"
      subnet_ids = module.vpc.private_subnets
      selectors = [
        { namespace = "kube-system" },
        { namespace = "default" }
      ]
    }
    cert_manager = {
        name       = "fp-cert-manager"
        subnet_ids = module.vpc.private_subnets
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
    data.aws_route53_zone.iplayishow.arn
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
        subnet_id       = module.vpc.private_subnets[0]
        security_groups = [module.efs_security_group.security_group_id]
    }
    ap2 = {
        subnet_id       = module.vpc.private_subnets[1]
        security_groups = [module.efs_security_group.security_group_id]
    }
    ap3 = {
        subnet_id       = module.vpc.private_subnets[2]
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

###############################################################
# SECURITY GROUPS — ALB, Fargate, RDS, Lambda, EKS Primary, EFS
###############################################################

# SG for Fargate app pods
module "fargate_app_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  name        = "${local.cluster_name}-fargate-app-sg"
  description = "Security group for app pods on Fargate"
  vpc_id      = module.vpc.vpc_id

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
  description = "Security group for internal ALB with CloudFront VPC Origin"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      rule        = "https-443-tcp"
      cidr_blocks = module.vpc.vpc_cidr_block
      description = "CloudFront VPC Origin ENIs to ALB"
    }
  ]

  egress_with_cidr_blocks = [
    {
      rule        = "http-80-tcp"
      cidr_blocks = module.vpc.vpc_cidr_block
      description = "ALB to EKS pods"
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
  vpc_id      = module.vpc.vpc_id

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
  vpc_id             = module.vpc.vpc_id
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
      cidr_blocks = module.vpc.vpc_cidr_block
      description = "DNS resolution"
    },
    {
      rule        = "dns-tcp"
      cidr_blocks = module.vpc.vpc_cidr_block
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
  vpc_id      = module.vpc.vpc_id

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
  subnet_ids = module.vpc.private_subnets
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
  vpc_id      = module.vpc.vpc_id

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

resource "aws_lambda_layer_version" "psycopg2" {
  filename   = "./lambda/rds/layer.zip"
  layer_name = "psycopg2-layer"
  compatible_runtimes = ["python3.11"]
}

# Lambda function
resource "aws_lambda_function" "rds_postgres_rotation" {
  filename         = "./lambda/rds/lambda_function.zip"
  function_name    = "rds_postgres_rotation_single_user"
  role             = aws_iam_role.rds_secrets_rotation_lambda.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  timeout          = 60

  layers = [
    aws_lambda_layer_version.psycopg2.arn
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
    module.rds_lambda_security_group
  ]

  # Lambda runs inside the VPC to reach RDS
  vpc_config {
    subnet_ids         = module.vpc.private_subnets
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