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
