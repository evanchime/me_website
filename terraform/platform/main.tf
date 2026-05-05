###############################################
# PROVIDER & GLOBAL CONFIGURATION
###############################################

provider "aws" {
  region = data.terraform_remote_state.me_website_k8s_eks.outputs.region
}

provider "kubernetes" {
  host                   = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_endpoint
  cluster_ca_certificate = base64decode(data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name]
  }

}

provider "helm" {
  kubernetes {
    host                   = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_endpoint
    cluster_ca_certificate = base64decode(data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_certificate_authority_data)

    exec {
        api_version = "client.authentication.k8s.io/v1beta1"
        command     = "aws"
        args        = ["eks", "get-token", "--cluster-name", data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name]
    }
  }
}

locals {
  cluster_name = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_name
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

resource "kubernetes_namespace_v1" "adot_col" {
  metadata {
    name = "adot-col"
  }
}

resource "kubernetes_namespace_v1" "aws_observability" {
  metadata {
    name = "aws-observability"
    labels = {
      "aws-observability" = "enabled"
    }
  }
}

resource "kubernetes_namespace_v1" "external_secrets" {
  metadata { name = "external-secrets" }
}

resource "kubernetes_service_account_v1" "adot_collector" {
  metadata {
    name      = "adot-collector-service-account"
    namespace = kubernetes_namespace_v1.adot_col.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = module.me_website_adot_infra_irsa.arn
    }
  }
}

resource "kubernetes_service_account_v1" "external_secrets" {
  metadata {
    name      = "external-secrets"
    namespace = kubernetes_namespace_v1.external_secrets.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = module.external_secrets_irsa_role.iam_role_arn
    }
  }
}

resource "kubernetes_cluster_role_v1" "adot_infra" {
  metadata {
    name = "adotcol-admin-role"
  }

  rule {
    api_groups = [""]
    resources  = ["nodes", "nodes/proxy", "nodes/metrics", "services", "endpoints", "pods", "pods/proxy"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    # Specifically for the cAdvisor proxy scraping
    non_resource_urls = ["/metrics/cadvisor"]
    verbs             = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding_v1" "adot_infra" {
  metadata {
    name = "adotcol-admin-role-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role_v1.adot_infra.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "adot-collector-service-account"
    namespace = kubernetes_namespace_v1.adot_col.metadata[0].name
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
        from_port                = 8000
        to_port                  = 8000
        protocol                 = "tcp"
        source_security_group_id = module.alb_security_group.security_group_id
        description              = "Allow ALB to reach me-website pods"
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
      from_port                = 8000
      to_port                  = 8000
      protocol                 = "tcp"
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
        from_port                = 8000
        to_port                  = 8000
        protocol                 = "tcp"
        source_security_group_id = module.alb_security_group.security_group_id
        description              = "Allow ALB to reach me-website pods"
    },
    {
        from_port                = 8888
        to_port                  = 8888
        protocol                 = "tcp"
        # Use self-reference so the cluster can reach its own telemetry
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow internal metrics scraping for ADOT Collector"
    },
    {
        from_port                = 9443
        to_port                  = 9443
        protocol                 = "tcp"
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow EKS Control Plane to reach External Secrets Webhook"
    },
    {
        from_port                = 10260
        to_port                  = 10260
        protocol                 = "tcp"
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow EKS Control Plane to reach cert-manager Webhook"
    },
    {
        from_port                = 10250
        to_port                  = 10250
        protocol                 = "tcp"
        source_security_group_id = data.terraform_remote_state.me_website_k8s_eks.outputs.cluster_primary_security_group_id
        description              = "Allow EKS Control Plane to reach Kubelet/Metrics"
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

###############################################################
# IAM — IRSA role for me_website app
###############################################################

module "me_website_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.2"

  name = "${local.cluster_name}-me-website-app"

  policies = {
    me_website_app = aws_iam_policy.me_website_app.arn
    prometheus     = "arn:aws:iam::aws:policy/AmazonPrometheusRemoteWriteAccess"
    xray           = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
  }

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn
      namespace_service_accounts = ["me-website-app:me-website-service-account"]
    }
  }

  tags = local.tags
}

module "me_website_adot_infra_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.2"
  name    = "${local.cluster_name}-me-website-adot-infra"

  policies = {
    prometheus = "arn:aws:iam::aws:policy/AmazonPrometheusRemoteWriteAccess"
  }

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn
      namespace_service_accounts = ["adot-col:adot-collector-service-account"]
    }
  }
}

module "external_secrets_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts"
  version = "~> 6.2"

  name = "${local.cluster_name}external-secrets"

  policies = {
    policy = aws_iam_policy.external_secrets_policy.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = data.terraform_remote_state.me_website_k8s_eks.outputs.oidc_provider_arn
      namespace_service_accounts = ["external-secrets:external-secrets"]
    }
  }

  tags = local.tags
}

resource "aws_prometheus_workspace" "me_website_prometheus" {
  alias = "me-website-metrics"

  tags = local.tags
}

resource "kubernetes_config_map_v1" "adot_infra_config" {
  metadata {
    name      = "adot-infra-config"
    namespace = "adot-col"
  }

  data = {
    "otel-config.yaml" = <<EOF
extensions:
  sigv4auth:
    region: "${data.terraform_remote_state.me_website_k8s_eks.outputs.region}"
    service: "aps"

receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: 'kubernetes-nodes-cadvisor'
          scheme: https
          authorization:
            type: Bearer
            credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
          tls_config:
            ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
            insecure_skip_verify: true
          kubernetes_sd_configs:
            - role: node
          relabel_configs:
            - action: replace
              replacement: kubernetes.default.svc:443
              target_label: __address__
            - source_labels: [__meta_kubernetes_node_name]
              regex: (.+)
              target_label: __metrics_path__
              replacement: /api/v1/nodes/$${1}/proxy/metrics/cadvisor

exporters:
  prometheusremotewrite:
    endpoint: "${aws_prometheus_workspace.me_website_prometheus.prometheus_endpoint}api/v1/remote_write"
    auth:
      authenticator: sigv4auth

service:
  extensions: [sigv4auth]
  pipelines:
    metrics:
      receivers: [prometheus]
      exporters: [prometheusremotewrite]
EOF
  }
}

module "me_website_managed_grafana" {
  source  = "terraform-aws-modules/managed-service-grafana/aws"
  version = "2.3.1"

  # Workspace
  name        = "me-website-grafana-workspace"
  description = "Amazon Managed Grafana workspace for me-website application"
  associate_license         = false
  account_access_type       = "CURRENT_ACCOUNT"
  authentication_providers  = ["AWS_SSO"]
  permission_type           = "SERVICE_MANAGED"
  data_sources              = ["CLOUDWATCH", "PROMETHEUS", "XRAY"]
  grafana_version           = "10.4"

  configuration = jsonencode({
    unifiedAlerting = {
      enabled = true
    },
    plugins = {
      pluginAdminEnabled = true
    }
  })

  # Workspace IAM role
  create_iam_role                = true
  iam_role_name                  = "me-website-grafana-workspace"
  use_iam_role_name_prefix       = true
  iam_role_description           = "IAM role for Amazon Managed Grafana workspace for me-website application"
  iam_role_path                  = "/grafana/"
  iam_role_force_detach_policies = true
  iam_role_max_session_duration  = 7200
  iam_role_tags                  =  local.tags

  tags = local.tags
}

# The Fluent Bit configuration
resource "kubernetes_config_map_v1" "aws_logging" {
  metadata {
    name      = "aws-logging"
    namespace = kubernetes_namespace_v1.aws_observability.metadata[0].name
  }

  data = {
    "filters.conf" = <<EOF
[FILTER]
    Name parser
    Match *
    Key_Name log
    Parser json
    Reserve_Data True
EOF

    "output.conf" = <<EOF
[OUTPUT]
    Name cloudwatch_logs
    Match *
    region ${data.terraform_remote_state.me_website_k8s_eks.outputs.region}
    log_group_name /aws/eks/${local.cluster_name}/fargate-logs
    log_stream_prefix django-
    auto_create_group true
EOF

    "parsers.conf" = <<EOF
[PARSER]
    Name json
    Format json
    Time_Key asctime
    Time_Format %Y-%m-%dT%H:%M:%S
    Time_Keep On
EOF
  }
}

resource "aws_grafana_workspace_service_account" "this" {
  workspace_id   = module.me_website_managed_grafana.workspace_id
  name           = "grafana-workspace-service-account"
  grafana_role   = "ADMIN"
}

resource "aws_grafana_workspace_service_account_token" "grafana_operator_token" {
  workspace_id       = module.me_website_managed_grafana.workspace_id
  service_account_id = aws_grafana_workspace_service_account.this.service_account_id
  name               = "grafana-operator-token"
  seconds_to_live    = 2592000
}

resource "aws_grafana_workspace_service_account_token" "grafana_provider_token" {
  workspace_id       = module.me_website_managed_grafana.workspace_id
  service_account_id = aws_grafana_workspace_service_account.this.service_account_id
  name               = "grafana-provider-token"
  seconds_to_live    = 7200
}

resource "helm_release" "grafana_kubernetes_operator" {
  name       = "grafana-operator"
  namespace        = "grafana-operator"
  create_namespace = true
  repository = "oci://ghcr.io/grafana/helm-charts"
  chart      = "grafana-operator"
  verify     = false
  version    = "5.22.2"
  wait       = true
}

resource "random_id" "secret_suffix" { byte_length = 4 } 

resource "aws_secretsmanager_secret" "grafana_provider_token" {
  name        = "grafana/provider-token-${random_id.secret_suffix.hex}"
  description = "Managed Grafana Service Account Token for the EKS provider"
}

resource "aws_secretsmanager_secret_version" "initial_grafana_provider_token" {
  secret_id     = aws_secretsmanager_secret.grafana_provider_token.id
  secret_string = aws_grafana_workspace_service_account_token.grafana_provider_token.key
}

resource "aws_secretsmanager_secret" "grafana_operator_token" {
  name        = "grafana/operator-token-${random_id.secret_suffix.hex}"
  description = "Managed Grafana Service Account Token for the EKS Operator"
}

resource "aws_secretsmanager_secret_version" "initial_grafana_operator_token" {
  secret_id     = aws_secretsmanager_secret.grafana_operator_token.id
  secret_string = aws_grafana_workspace_service_account_token.grafana_operator_token.key

  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret_rotation" "grafana_operator_token" {
  secret_id     = aws_secretsmanager_secret.grafana_operator_token.id
  rotation_lambda_arn = aws_lambda_function.grafana_operator_token_rotation_lambda.arn
  rotation_rules {
    automatically_after_days = 29
  }
}

resource "helm_release" "external_secrets" {
  depends_on = [helm_release.cert_manager]

  name             = "external-secrets"
  repository       = "https://external-secrets.io"
  chart            = "external-secrets"
  namespace        = kubernetes_namespace_v1.external_secrets.metadata[0].name
  version          = "2.4.1"
  wait = true 
  wait_for_jobs = true 

  set = [
    {
      name  = "installCRDs"
      value = "true"
    },
    {
      # Fargate critical: Avoid port 10250
      name  = "webhook.port"
      value = "9443"
    },
    {
      # This tells ESO to let cert-manager handle the certificates
      name  = "webhook.certManager.enabled"
      value = "true"
    }
  ]
}

resource "helm_release" "cert_manager" {
  name = "cert-manager"

  repository = "oci://quay.io/jetstack/charts"
  chart      = "cert-manager"
  version    = "1.20.2" 

  namespace        = "cert-manager"
  create_namespace = true

  wait = true 
  wait_for_jobs = true 

  set = [
    {
      name  = "crds.enabled"
      value = "true"
    },
    {
      # Fargate critical: Avoid port 10250
      name  = "webhook.port"
      value = "10250"
    },
  ]
}


# SecretStore: Defines HOW to talk to AWS
resource "kubernetes_manifest" "aws_secret_store" {
  depends_on = [helm_release.external_secrets]
  manifest = {
    apiVersion = "external-secrets.io/v1"
    kind       = "SecretStore"
    metadata = {
      name      = "aws-secret-store"
      namespace = "grafana-operator"
    }
    spec = {
      provider = {
        aws = {
          service = "SecretsManager"
          region  = data.aws_region.current.name
        }
      }
    }
  }
}

# ExternalSecret: Defines WHAT secret to pull and how often
resource "kubernetes_manifest" "grafana_token_sync" {
  depends_on = [kubernetes_manifest.aws_secret_store]
  manifest = {
    apiVersion = "external-secrets.io/v1"
    kind       = "ExternalSecret"
    metadata = {
      name      = "grafana-token-sync"
      namespace = "grafana-operator"
    }
    spec = {
      refreshInterval = "1h" # ESO checks AWS for rotations every hour
      secretStoreRef = {
        name = "aws-secret-store"
        kind = "SecretStore"
      }
      target = {
        name = "grafana-operator-token"
        creationPolicy = "Owner"
      }
      data = [
        {
          secretKey = "token"
          remoteRef = {
            key = aws_secretsmanager_secret.grafana_operator_token.name
          }
        }
      ]
    }
  }
}

resource "aws_lambda_function" "grafana_operator_token_rotation_lambda" {
  function_name    = "grafana-operator-token-rotation"
  runtime          = "python3.12"
  handler          = "secrets_lambda.lambda_handler"
  role             = aws_iam_role.grafana_operator_token_rotator_role.arn
  timeout          = 60
  memory_size      = 128
  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256

  layers = [aws_lambda_layer_version.grafana_operator_token_rotation_layer.arn]

  environment {
    variables = {
      GRAFANA_TOKEN_NAME           = aws_grafana_workspace_service_account_token.grafana_operator_token.name
      GRAFANA_SERVICE_ACCOUNT_NAME = aws_grafana_workspace_service_account.this.name
      GRAFANA_WORKSPACE_ID         = module.me_website_managed_grafana.workspace_id
      GRAFANA_URL                  = module.me_website_managed_grafana.workspace_endpoint
    }
  }
}

resource "aws_lambda_layer_version" "grafana_operator_token_rotation_layer" {
  layer_name               = "boto3_v134144_lambda_layer"
  compatible_runtimes      = ["python3.12", "python3.13"]
  compatible_architectures = ["x86_64"]
  filename                 = "${path.module}/layer/python.zip"
}

data "archive_file" "grafana_operator_token_rotation" {
  type        = "zip"
  source_file = "${path.module}/src/secrets_lambda.py"
  output_path = "${path.module}/lambda/grafana_operator_token_rotation.zip" 
}

resource "aws_lambda_permission" "secrets_manager_invoke_permission" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.grafana_operator_token_rotation_lambda.function_name
  principal     = "secretsmanager.amazonaws.com"
  source_arn    = aws_secretsmanager_secret.grafana_operator_token.arn
}
