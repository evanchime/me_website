variable "me_website_email_host_user" {
    description = "Email address for me_website application admin"
    type        = string
    default = "evanchime@gmail.com"
}

variable "me_website_health_check_secret" {
  description = "Secret string for health check endpoint"
  type        = string
  sensitive   = true
}

variable "me_website_email_host_password" {
    description = "App password for me_website application admin email"
    type        = string
    sensitive   = true
}

variable "me_website_secret_admin_url" {
    description = "Secret admin URL for me_website application"
    type        = string
    sensitive   = true
}

variable "me_website_django_secret_key" {
    description = "Django secret key for me_website application"
    type        = string
    sensitive   = true
}

variable "me_website_django_settings_module" {
  type        = string
  description = "Django settings module for the application"
  default     = "me_website_project.settings"
}

variable "me_website_debug_mode" {
  type        = bool
  description = "Enable or disable Django debug mode"
  default     = false
}

variable "me_website_allowed_hosts" {
  type        = string
  description = "Comma-separated list of allowed hosts"
  default     = ".iplayishow.com,localhost,127.0.0.1"
}

variable "me_website_csrf_trusted_origins" {
  type        = string
  description = "Comma-separated list of CSRF trusted origins"
  default     = "https://app.iplayishow.com,https://iplayishow.com,https://www.iplayishow.com"
}

variable "me_website_app_version" {
  type        = string
  description = "Application version identifier"
  default     = "1.0.0"
}