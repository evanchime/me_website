data "terraform_remote_state" "me_website_k8s_platform" {
  backend = "remote"

  config = {
    organization = "DevOps_As_A_Way"
    workspaces = {
      name = "k8s-migration-platform"
    }
  }
}

data "terraform_remote_state" "me_website_k8s_network" {
  backend = "remote"

  config = {
    organization = "DevOps_As_A_Way"
    workspaces = {
      name = "k8s-migration-network"
    }
  }
}

data "terraform_remote_state" "me_website_k8s_eks" {
  backend = "remote"

  config = {
    organization = "DevOps_As_A_Way"
    workspaces = {
      name = "k8s-migration-eks"
    }
  }
}