output "collectstatic_job_yaml" {
  value = kubernetes_job_v1.me_website_collectstatic.manifest
}

output "migrate_job_yaml" {
  value = kubernetes_job_v1.me_website_migrate.manifest
}