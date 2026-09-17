variable "cluster_name" {
  type = string
}

variable "cluster_mode" {
  type = string

  validation {
    condition     = contains(["classic", "vpc"], var.cluster_mode)
    error_message = "Cluster mode must be classic or vpc."
  }
}

variable "resource_group_name" {
  type = string
}

variable "region" {
  type = string
}

variable "config_dir" {
  type = string
}

variable "auth_allocation_uid" {
  type    = string
  default = ""
}
variable "auth_vpn_server_id" {
  type    = string
  default = ""
}
variable "auth_secrets_manager_id" {
  type    = string
  default = ""
}
variable "auth_secrets_manager_region" {
  type    = string
  default = ""
}
variable "auth_secret_group_id" {
  type    = string
  default = ""
}
variable "auth_certificate_template" {
  type    = string
  default = ""
}
variable "auth_issuer" {
  type    = string
  default = ""
}
variable "auth_ttl" {
  type    = string
  default = ""
}
