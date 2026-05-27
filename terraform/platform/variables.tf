# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "me_website_email_host_user" {
    description = "Email address for me_website application admin"
    type        = string
    default = "evanchime@gmail.com"
}

variable "me_website_grafana_contact_point_email_password" {
    description = "App password for me_website application Grafana contact point email address"
    type        = string
    sensitive   = true
}
