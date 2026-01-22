data "terraform_remote_state" "me_website_k8s_network" {
  backend = "remote"

  config = {
    organization = "DevOps_As_A_Way"
    project = "k8s-migration"
    workspaces = {
      name = "k8s-migration-network"
    }
  }
}