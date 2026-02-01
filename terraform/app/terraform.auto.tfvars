tfc_org = "DevOps_As_A_Way"
tfc_project = "k8s-migration"
mode = "application"
tfc_kubernetes_dynamic_credentials = {
  default = {
    token_path = "/home/terraform/.terraform.d/kubernetes-credentials/default"
  }
  aliases = {}
}