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
data "ibm_container_cluster" "target" {
  name                  = var.cluster_name
  resource_group_id     = data.ibm_resource_group.selected.id
  list_bounded_services = false
}

data "ibm_container_cluster_config" "public_admin" {
  count = data.ibm_container_cluster.target.public_service_endpoint ? 1 : 0

  cluster_name_id   = data.ibm_container_cluster.target.id
  resource_group_id = data.ibm_resource_group.selected.id
  admin             = true
  endpoint_type     = "public"
  config_dir        = var.config_dir
}

output "public_available" {
  value = data.ibm_container_cluster.target.public_service_endpoint
}

output "public_endpoint" {
  value = data.ibm_container_cluster.target.public_service_endpoint_url
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
