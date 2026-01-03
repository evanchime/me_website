data "terraform_remote_state" "me_website_k8s_platform" {
  backend = "remote"

  config = {
    organization = "DevOps_As_A_Way"
    project = "k8s-migration"
    workspaces = {
      name = "me-website-k8s-platform"
    }
  }
}