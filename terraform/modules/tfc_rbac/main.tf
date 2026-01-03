locals {
  tfc_user_plan  = "${var.tfc_hostname}#organization:${var.tfc_org}:project:${var.tfc_project}:workspace:${var.tfc_workspace}:run_phase:plan"
  tfc_user_apply = "${var.tfc_hostname}#organization:${var.tfc_org}:project:${var.tfc_project}:workspace:${var.tfc_workspace}:run_phase:apply"
}

resource "aws_eks_identity_provider_config" "tfc_oidc" {
  cluster_name = var.cluster_name

  oidc {
    identity_provider_config_name = "terraform-cloud"
    client_id                     = var.tfc_kubernetes_audience
    issuer_url                    = var.tfc_hostname
    username_claim                = "sub"
    groups_claim                  = null
  }
}

#
# Application mode: namespace‑scoped RBAC
#
resource "kubernetes_role_v1" "app_readonly" {
  count = var.mode == "application" ? 1 : 0

  metadata {
    name      = "tfc-app-readonly"
    namespace = var.target_namespace
  }

  rule {
    api_groups = ["", "apps"]
    resources  = ["pods", "services", "deployments", "configmaps", "secrets"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_role_v1" "app_write" {
  count = var.mode == "application" ? 1 : 0

  metadata {
    name      = "tfc-app-write"
    namespace = var.target_namespace
  }

  rule {
    api_groups = ["", "apps"]
    resources  = ["pods", "services", "deployments", "configmaps", "secrets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
}

resource "kubernetes_role_binding_v1" "app_plan" {
  count = var.mode == "application" ? 1 : 0

  metadata {
    name      = "tfc-app-plan"
    namespace = var.target_namespace
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.app_readonly[0].metadata[0].name
  }

  subject {
    kind      = "User"
    api_group = "rbac.authorization.k8s.io"
    name      = local.tfc_user_plan
  }
}

resource "kubernetes_role_binding_v1" "app_apply" {
  count = var.mode == "application" ? 1 : 0

  metadata {
    name      = "tfc-app-apply"
    namespace = var.target_namespace
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.app_write[0].metadata[0].name
  }

  subject {
    kind      = "User"
    api_group = "rbac.authorization.k8s.io"
    name      = local.tfc_user_apply
  }
}

#
# Platform mode: cluster‑wide RBAC (cluster‑admin for this one workspace)
#
resource "kubernetes_cluster_role_binding_v1" "platform_plan" {
  count = var.mode == "platform" ? 1 : 0

  metadata {
    name = "tfc-platform-plan"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }

  subject {
    kind      = "User"
    api_group = "rbac.authorization.k8s.io"
    name      = local.tfc_user_plan
  }
}

resource "kubernetes_cluster_role_binding_v1" "platform_apply" {
  count = var.mode == "platform" ? 1 : 0

  metadata {
    name = "tfc-platform-apply"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }

  subject {
    kind      = "User"
    api_group = "rbac.authorization.k8s.io"
    name      = local.tfc_user_apply
  }
}