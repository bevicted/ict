terraform {
  required_version = ">= 1.5.0"

  required_providers {
    ibm = {
      source  = "IBM-Cloud/ibm"
      version = "2.5.0"
    }
  }
}

provider "ibm" {
  region = var.region
}

data "ibm_resource_group" "selected" {
  name = var.resource_group_name
}

# This data source supplies the actual public-endpoint decision. A missing public
# endpoint leaves the credential data source uninstantiated.
data "ibm_container_vpc_cluster" "target" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  name              = var.cluster_name
  resource_group_id = data.ibm_resource_group.selected.id
}

data "ibm_container_cluster" "target" {
  count = var.cluster_mode == "classic" ? 1 : 0

  name                  = var.cluster_name
  resource_group_id     = data.ibm_resource_group.selected.id
  list_bounded_services = false
}

locals {
  cluster_id       = var.cluster_mode == "vpc" ? data.ibm_container_vpc_cluster.target[0].id : data.ibm_container_cluster.target[0].id
  public_available = var.cluster_mode == "vpc" ? data.ibm_container_vpc_cluster.target[0].public_service_endpoint : data.ibm_container_cluster.target[0].public_service_endpoint
  public_endpoint  = var.cluster_mode == "vpc" ? data.ibm_container_vpc_cluster.target[0].public_service_endpoint_url : data.ibm_container_cluster.target[0].public_service_endpoint_url
}

data "ibm_container_cluster_config" "public_admin" {
  count = local.public_available ? 1 : 0

  cluster_name_id   = local.cluster_id
  resource_group_id = data.ibm_resource_group.selected.id
  admin             = true
  config_dir        = var.config_dir
}

output "public_available" {
  value = local.public_available
}

output "public_endpoint" {
  value = local.public_endpoint
}

# The provider downloads a config file which refers to sibling PEM files. Export
# the credential material directly so the workflow can render one self-contained
# kubeconfig without copying those local references.
output "public_ca_certificate" {
  value     = try(data.ibm_container_cluster_config.public_admin[0].ca_certificate, "")
  sensitive = true
}

output "public_admin_certificate" {
  value     = try(data.ibm_container_cluster_config.public_admin[0].admin_certificate, "")
  sensitive = true
}

output "public_admin_key" {
  value     = try(data.ibm_container_cluster_config.public_admin[0].admin_key, "")
  sensitive = true
}
