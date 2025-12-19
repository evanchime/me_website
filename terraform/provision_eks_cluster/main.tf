# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

provider "aws" {
  region = var.region
}

locals {
  cluster_name = "me_website-eks-${random_string.suffix.result}"
  tags = {
    Project     = "me-website"
    Environment = "production"
    Terraform   = "true"
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"

  name = "me_website-vpc"
  cidr = "10.0.0.0/16"
  
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }

  tags = local.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.8.5"

  cluster_name    = local.cluster_name
  cluster_version = "1.29"

  cluster_endpoint_public_access           = true
  enable_cluster_creator_admin_permissions = true

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
  }

  access_entries = {
    Evan_Admin = {
      principal_arn     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_AdministratorAccess_95a4a8e95b834fbe"

      policy_associations = {
        cluster = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  fargate_profiles = {
    # System namespaces (required)
    system = {
      name = "fp-system"
      subnet_ids = module.vpc.private_subnets

      selectors = [
        {
          namespace = "kube-system"
        },
        {
          namespace = "default"
        }
      ]
    }

    # me_website application namespace
    me_website = {
      name = "fp-me_website"
      subnet_ids = module.vpc.private_subnets

      selectors = [
        {
          namespace = "me_website-app"
        }
      ]

      # IAM configuration for me_website pods
      create_iam_role = true
      iam_role_name   = "${local.cluster_name}-fargate-me_website"
      iam_role_attach_cni_policy = true
      
      # Add permissions for CloudWatch, Secrets Manager, etc.
      iam_role_additional_policies = {
        CloudWatchLogsFull = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
        SecretsManagerRead = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
      }
    }
  }

  tags = local.tags
}

module "eks_blueprints_addons" {
  source = "aws-ia/eks-blueprints-addons/aws"
  version = "= 1.22.0"
  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  enable_aws_load_balancer_controller            = true
  enable_cluster_proportional_autoscaler         = true
  enable_metrics_server                          = true
  enable_external_dns                            = true
  enable_cert_manager                            = true
  enable_secrets_store_csi_driver                = true
  enable_secrets_store_csi_driver_provider_aws   = true

  cert_manager_route53_hosted_zone_arns          = [data.aws_route53_zone.iplayishow.arn]

  tags = local.tags

  depends_on = [ module.eks ]
}

# EFS for any persistent storage needs (media files, etc.)
module "efs" {
  source  = "terraform-aws-modules/efs/aws"
  version = "~> 1.0"
  
  name = "${local.cluster_name}-efs"
  creation_token = "${local.cluster_name}-efs-token"
  
  # Mount targets / Security group for EFS - allow NFS from EKS cluster
  mount_targets = {
    for subnet in module.vpc.private_subnets : subnet => {
      subnet_id = subnet
    }
  }
  security_group_description = "EFS for me_website EKS cluster"
  security_group_vpc_id      = module.vpc.vpc_id
  security_group_rules = {
    eks_cluster = {
      description              = "NFS from EKS cluster"
      source_security_group_id = module.eks.cluster_primary_security_group_id
      from_port                = 2049
      to_port                  = 2049
      protocol                 = "tcp"
    }
  }

  # Access point for me_website media files
  access_points = {
    me_website-filesystem = {
      posix_user = {
        gid = 1000
        uid = 1000
      }
      root_directory = {
        path = "/me_website-filesystem"
        creation_info = {
          owner_gid   = 1000
          owner_uid   = 1000
          permissions = "755"
        }
      }
    }
  }

  tags = local.tags
}

module "me_website_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "6.2.3"

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

# IAM policy for me_website application
resource "aws_iam_policy" "me_website_app" {
  name        = "${local.cluster_name}-me_website-app-policy"
  description = "Policy for me_website application"
  policy      = data.aws_iam_policy_document.me_website_app.json

  tags = local.tags
}

resource "aws_vpc_peering_connection" "eks_rds" {
    peer_vpc_id = data.aws_vpc.rds_vpc.id
    vpc_id = module.vpc.vpc_id
    auto_accept = true
    tags = {
        Name = "${local.cluster_name}-to-rds"
    }

}

# Add route to RDS VPC in EKS route tables
resource "aws_route" "eks_to_rds" {

    for_each = toset(module.vpc.private_route_table_ids)
    route_table_id = each.value
    destination_cidr_block = data.aws_vpc.rds_vpc.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.eks_rds.id
}

# Add route to EKS VPC in RDS route tables
resource "aws_route" "rds_to_eks" {
    for_each = toset(data.aws_route_tables.rds_vpc_route_tables.ids)
    route_table_id = each.value
    destination_cidr_block = module.vpc.vpc_cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.eks_rds.id
}

resource "aws_secretsmanager_secret" "rds_master_credentials" {
  name           = "rds-master-credentials/me-website"
  description    = "Master credentials for the me-website RDS PostgreSQL instance"
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

resource "aws_secretsmanager_secret_version" "rds_master_initial_version" {
  secret_id = aws_secretsmanager_secret.rds_master_credentials.id

  secret_string = jsonencode({
    engine   = data.aws_db_instance.existing_rds.engine  
    host     = data.aws_db_instance.existing_rds.address
    username = data.aws_db_instance.existing_rds.master_username 
    password = var.database_master_password          
    port     = data.aws_db_instance.existing_rds.port    
  })

  # This tells Terraform to ignore future changes to this resource.
  # After the first rotation, AWS will manage the secret versions, not 
  # Terraform.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_iam_role" "rds_secrets_rotation_lambda" {
  name               = "rds_secrets_rotation_lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "lambda_permissions_policy" {
  name = "lambda_permissions_policy"
  role = aws_iam_role.rds_secrets_rotation_lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.rds_secrets_rotation_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "terraform_data" "rds_lambda_install_dependencies" {
  triggers_replace = [
    filebase64sha256("${path.module}/lambda/rds/requirements.txt"),
    filebase64sha256("${path.module}/lambda/rds/lambda_function.py")
  ]

  provisioner "local-exec" {
    command = "cd ${path.module}/lambda/rds && pip install -r requirements.txt -t ."
  }
}

resource "aws_lambda_function" "rds_postgres_rotation" {
  filename         = data.archive_file.rds_lambda_zip.output_path
  function_name    = "rds_postgres_rotation_single_user"
  role             = aws_iam_role.rds_secrets_rotation_lambda.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.rds_lambda_zip.output_base64sha256
  timeout          = 60

  # Environment variables
  environment {
    variables = {
      DATABASE_TIMEOUT         = "10"
      EXCLUDE_CHARACTERS       = "/@\"'\\"
      LOG_LEVEL                = "INFO"
      ENVIRONMENT              = "production"
      APPLICATION              = "me_website"
    }
  }

  tags = local.tags

  depends_on = [
    terraform_data.rds_lambda_install_dependencies,
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_security_group.lambda_rds_sg
  ]
  vpc_config {
    subnet_ids         = data.aws_db_subnet_group.existing_rds.subnet_ids
    security_group_ids = [aws_security_group.lambda_rds_sg.id]
  }

}

resource "aws_lambda_permission" "rds_allow_secret_manager" {
  statement_id  = "AllowExecutionFromSecretManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rds_postgres_rotation.function_name
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_security_group" "lambda_rds_sg" {
  name        = "lambda-rds-access"
  description = "Allow Lambda to access RDS"
  vpc_id      = data.aws_vpc.rds_vpc.id
  tags = {
    Name = "lambda-rds-sg"
  }
}

resource "aws_vpc_security_group_egress_rule" "allow_postgreql_port" {
  security_group_id = aws_security_group.lambda_rds_sg.id
  cidr_ipv4         = data.aws_vpc.rds_vpc.cidr_block
  from_port         = 5432
  ip_protocol       = "tcp"
  to_port           = 5432
}

resource "aws_vpc_security_group_egress_rule" "allow_https_for_secretsmanager" {
  security_group_id = aws_security_group.lambda_rds_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "allow_lambda_to_rds" {
  security_group_id = data.aws_security_group.existing_rds.id
  description = "Allow Lambda to access RDS"
  ip_protocol       = "tcp"
  referenced_security_group_id = aws_security_group.lambda_rds_sg.id
  from_port         = 5432
  to_port           = 5432
}

resource "aws_vpc_security_group_egress_rule" "alb" {
  security_group_id = aws_security_group.lambda_rds_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 0
  ip_protocol       = "-1"
  to_port           = 0
}

resource "aws_security_group" "cloudfront_alb_sg" {
  name        = "cloudfront-alb-access"
  description = "Allow CloudFront to access ALB"
  vpc_id      = data.aws_vpc.rds_vpc.id
  tags = {
    Name = "cloudfront-alb-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_cloudfront_to_alb" {
  security_group_id = aws_security_group.cloudfront_alb_sg.id
  description       = "Allow CloudFront to access ALB"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = module.vpc.vpc_cidr_block
}