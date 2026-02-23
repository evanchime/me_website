###############################################
# PROVIDER & GLOBAL CONFIGURATION
###############################################

data "aws_eks_cluster" "cluster" {
  name = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name
}

provider "aws" {
  region = data.terraform_remote_state.me_website_k8s_eks.outputs.region
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
  cluster_name = data.aws_eks_cluster.cluster.name
  # Common tags applied to all resources
  tags = {
    Project     = "k8s-migration"
    Environment = "production"
    Terraform   = "true"
  }
}

# Random strings for naming
resource "random_string" "prefix" {
  length  = 6
  upper   = false
  special = false
  numeric = false
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "random_password" "db_password" {
  length  = 32
  special = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

###############################################
# DATA SOURCES
###############################################

data "aws_caller_identity" "current" {}

###############################################
# K8S NAMESPACE 
###############################################

resource "kubernetes_namespace_v1" "me_website_app" {
  metadata {
    name = "me-website-app"
  }
}

###############################################################
# EKS ADDONS (ALB Controller, ExternalDNS, CSI Driver, etc.)
###############################################################

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.23"

  cluster_name      = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name
  cluster_endpoint  = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_endpoint
  cluster_version   = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_version
  oidc_provider_arn = data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn

  enable_aws_load_balancer_controller          = true
  enable_metrics_server                        = true
  enable_external_dns                          = true
  enable_eks_fargate                           = true

  external_dns_route53_zone_arns = [
    data.terraform_remote_state.me_website_k8s_network.outputs.route53_arn
  ]

  aws_load_balancer_controller = {
    chart_version = "1.14.0"
    values = [
      yamlencode({
        region      = data.terraform_remote_state.me_website_k8s_eks.outputs.region
        vpcId       = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

        serviceAccount = {
          create = true
          name   = "aws-load-balancer-controller"
          annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.alb.arn
          }
        }
      })
    ]
  }

  external_dns = {
    chart_version = "1.20.0"
    values = [
      yamlencode({
        provider = "aws"
        policy   = "sync"
        txtOwnerId = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name

        serviceAccount = {
          create = true
          name   = "external-dns"
          annotations = {
            "eks.amazonaws.com/role-arn" = aws_iam_role.external_dns.arn
          }
        }
      })
    ]
  }

  metrics_server = {
    chart_version = "3.12.1"
  }

  tags = local.tags

}

###############################################
# EFS — Persistent storage for media files
###############################################

# module "efs" {
#   source  = "terraform-aws-modules/efs/aws"
#   version = "~> 2.0"

#   name           = "${local.cluster_name}-efs"
#   creation_token = "${local.cluster_name}-efs-token"

#   # One mount target per private subnet
#   mount_targets = {
#     ap1 = {
#         subnet_id       = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids[0]
#         security_groups = [module.efs_security_group.security_group_id]
#     }
#     ap2 = {
#         subnet_id       = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids[1]
#         security_groups = [module.efs_security_group.security_group_id]
#     }
#     ap3 = {
#         subnet_id       = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids[2]
#         security_groups = [module.efs_security_group.security_group_id]
#     }
#  }

#   create_security_group = false
  
#   # Access point for app media
#   access_points = {
#     me_website-filesystem = {
#       posix_user = { uid = 1000, gid = 1000 }
#       root_directory = {
#         path = "/me_website-filesystem"
#         creation_info = {
#           owner_uid   = 1000
#           owner_gid   = 1000
#           permissions = "755"
#         }
#       }
#     }
#   }

#   tags = local.tags
# }

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
    },
    {
        rule                     = "all-tcp"
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow kubelet + probes from cluster SG"
    }
  ]
  
  egress_with_source_security_group_id = [
    {
        rule                     = "dns-tcp"
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow dns tcp traffic to cluster primary security group"
    },
    {
        rule                     = "dns-udp"
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow dns udp traffic to cluster primary security group"
    },
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
      rule            = "http-80-tcp"
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
    # {
    #   rule                     = "postgresql-tcp"
    #   source_security_group_id = module.rds_lambda_security_group.security_group_id
    #   description              = "Allow Lambda to access RDS PostgreSQL"
    # },
    {
      rule                     = "postgresql-tcp"
      source_security_group_id = module.eks_primary_security_group.security_group_id
      description              = "Allow EKS cluster to access RDS PostgreSQL for management tasks"
    }
  ]

  tags = local.tags
}

# SG for EKS primary cluster SG (patching inbound rules)
module "eks_primary_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3"

  description        = "EKS cluster primary security group"
  create_sg  = false
  security_group_id  = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id

  ingress_with_source_security_group_id = [
    {
      rule                     = "http-80-tcp"
      source_security_group_id = module.alb_security_group.security_group_id
      description              = "From ALB to me_website pods"
    },
    { 
      rule                     = "dns-tcp"
      source_security_group_id = module.fargate_app_sg.security_group_id
      description              = "From me_website pods"
     },
     { 
       rule                     = "dns-udp"
       source_security_group_id = module.fargate_app_sg.security_group_id
       description              = "From me_website pods"
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
# module "efs_security_group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "~> 5.3"

#   name        = "${local.cluster_name}-efs-sg"
#   description = "Security group for EFS filesystem"
#   vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

#   ingress_with_source_security_group_id = [ 
#     {
#         rule = "nfs-tcp"
#         source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
#         description = "Allow EKS cluster to access EFS via NFS"
#     }
#    ]

#   tags = local.tags
# }

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
  db_name                     = "me_website_database_k8s"
  identifier                  = "me-website-database-instance-k8s"
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

###############################################################
# SECRETS MANAGER — RDS master credentials + rotation
###############################################################

resource "aws_secretsmanager_secret" "rds_master_credentials" {
  name        = "rds-master-credentials/me-website-k8s-${random_id.suffix.hex}"
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

# resource "aws_secretsmanager_secret_rotation" "rds_master_rotation" {
#   secret_id           = aws_secretsmanager_secret.rds_master_credentials.id
#   rotation_lambda_arn = aws_lambda_function.rds_postgres_rotation.arn

#   rotation_rules {
#     automatically_after_days = 30
#   }

#   depends_on = [
#     aws_secretsmanager_secret_version.rds_master_initial_version
#   ]
# }

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
      provider_arn               = data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn
      namespace_service_accounts = ["me_website-app:me_website-service-account"]
    }
  }

  tags = local.tags
}

###############################################################
# LAMBDA — RDS password rotation function
###############################################################

# Lambda security group
# module "rds_lambda_security_group" {
#   source  = "terraform-aws-modules/security-group/aws"
#   version = "~> 5.3"

#   name        = "${local.cluster_name}-lambda-rds-sg"
#   description = "Security group for the RDS instance"
#   vpc_id      = data.terraform_remote_state.me_website_k8s_network.outputs.vpc_id

#   # Allow Lambda → RDS
#   egress_with_source_security_group_id = [
#     {
#       rule                     = "postgresql-tcp"
#       source_security_group_id = module.rds_security_group.security_group_id
#       description              = "Allow Lambda to access RDS PostgreSQL"
#     }
#   ]

#   # Allow Lambda → Secrets Manager
#   egress_with_cidr_blocks = [
#     {
#       rule        = "https-443-tcp"
#       cidr_blocks = "0.0.0.0/0"
#       description = "Allow Lambda to access Secrets Manager"
#     }
#   ]

#   tags = local.tags
# }

# data "archive_file" "rds_lambda_zip" {
#   type        = "zip"
#   source_file = "${path.module}/lambda/rds/lambda_function.py"
#   output_path = "${path.module}/lambda/rds/lambda_function.zip"
# }

# resource "aws_lambda_layer_version" "lambda_layer" {
#   s3_bucket           = data.terraform_remote_state.me_website_k8s_network.outputs.s3_lambda_layer_bucket
#   s3_key              = "layers/${var.lambda_layer_name}/v${var.lambda_layer_version}.zip"
#   layer_name          = var.lambda_layer_name
#   compatible_runtimes = ["python3.12", "python3.11", "python3.10"]
# }

# resource "aws_lambda_function" "rds_postgres_rotation" {
#   function_name    = "rds_postgres_rotation_single_user"

#   role             = aws_iam_role.rds_secrets_rotation_lambda.arn
#   handler          = "lambda_function.lambda_handler"
#   runtime          = "python3.12"

#   filename         = data.archive_file.rds_lambda_zip.output_path
#   source_code_hash = data.archive_file.rds_lambda_zip.output_base64sha256


#   layers = [
#     aws_lambda_layer_version.lambda_layer.arn
#   ]

#   timeout     = 300

#  # Environment variables for rotation logic
#   environment {
#     variables = {
#       DATABASE_TIMEOUT   = "10"
#       EXCLUDE_CHARACTERS = "/@\"'\\"
#       LOG_LEVEL          = "INFO"
#       ENVIRONMENT        = "production"
#       APPLICATION        = "me_website"
#     }
#   }

#   # Ensure dependencies, IAM role, and SG exist before Lambda is created
#   depends_on = [
#     module.rds_lambda_security_group,
#     aws_iam_role_policy_attachment.lambda_basic_execution,
#     aws_iam_role_policy.lambda_permissions_policy,
#     aws_iam_role.rds_secrets_rotation_lambda,
#     data.aws_iam_policy_document.lambda_permissions_policy,
#     data.aws_iam_policy_document.lambda_assume_role,
#   ]

#   # Lambda runs inside the VPC to reach RDS
#   vpc_config {
#     subnet_ids         = data.terraform_remote_state.me_website_k8s_network.outputs.private_subnet_ids
#     security_group_ids = [module.rds_lambda_security_group.security_group_id]
#   }

#   tags = local.tags
# }

# # Allow Secrets Manager to invoke the rotation Lambda
# resource "aws_lambda_permission" "rds_allow_secret_manager" {
#   statement_id  = "AllowExecutionFromSecretManager"
#   action        = "lambda:InvokeFunction"
#   function_name = aws_lambda_function.rds_postgres_rotation.function_name
#   principal     = "secretsmanager.amazonaws.com"
# }