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
  private_eligible = var.cluster_mode == "vpc" && !local.public_available && data.ibm_container_vpc_cluster.target[0].private_service_endpoint && trimspace(data.ibm_container_vpc_cluster.target[0].private_service_endpoint_url) != "" && var.auth_allocation_uid != "" && var.auth_vpn_server_id != "" && var.auth_secrets_manager_id != "" && var.auth_secrets_manager_region != "" && var.auth_secret_group_id != "" && var.auth_certificate_template != "" && var.auth_issuer != "" && var.auth_ttl != ""
  auth_mode        = local.public_available ? "public" : (local.private_eligible ? "vpn" : "unsupported")
}

data "ibm_container_cluster_config" "public_admin" {
  count = local.public_available ? 1 : 0

  cluster_name_id   = local.cluster_id
  resource_group_id = data.ibm_resource_group.selected.id
  admin             = true
  config_dir        = var.config_dir
}

output "auth_mode" {
  value = local.auth_mode
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

data "ibm_container_cluster_config" "private_admin" {
  count = local.private_eligible ? 1 : 0

  cluster_name_id   = local.cluster_id
  resource_group_id = data.ibm_resource_group.selected.id
  admin             = true
  endpoint_type     = "private"
  download          = true
  config_dir        = var.config_dir
}

data "ibm_is_vpn_server_client_configuration" "profile" {
  count = local.private_eligible ? 1 : 0

  vpn_server = var.auth_vpn_server_id
}

resource "ibm_sm_private_certificate" "allocation" {
  count = local.private_eligible ? 1 : 0

  instance_id          = var.auth_secrets_manager_id
  region               = var.auth_secrets_manager_region
  endpoint_type        = "public"
  secret_group_id      = var.auth_secret_group_id
  certificate_template = var.auth_certificate_template
  name                 = "ict-${var.auth_allocation_uid}-vpn"
  common_name          = "ict-${var.auth_allocation_uid}-vpn"
  ttl                  = var.auth_ttl
  format               = "pem"
  private_key_format   = "pkcs8"

  rotation { auto_rotate = false }
}

output "private_endpoint" {
  value = try(data.ibm_container_vpc_cluster.target[0].private_service_endpoint_url, "")
}

output "private_ca_certificate" {
  value     = try(data.ibm_container_cluster_config.private_admin[0].ca_certificate, "")
  sensitive = true
}

output "private_admin_certificate" {
  value     = try(data.ibm_container_cluster_config.private_admin[0].admin_certificate, "")
  sensitive = true
}

output "private_admin_key" {
  value     = try(data.ibm_container_cluster_config.private_admin[0].admin_key, "")
  sensitive = true
}

output "vpn_profile" {
  value     = try(data.ibm_is_vpn_server_client_configuration.profile[0].vpn_server_client_configuration, "")
  sensitive = true
}

output "vpn_certificate" {
  value     = try(ibm_sm_private_certificate.allocation[0].certificate, "")
  sensitive = true
}

output "vpn_private_key" {
  value     = try(ibm_sm_private_certificate.allocation[0].private_key, "")
  sensitive = true
}

output "vpn_ca_chain" {
  value     = try(ibm_sm_private_certificate.allocation[0].ca_chain, "")
  sensitive = true
}

output "vpn_expiry" {
  value = try(ibm_sm_private_certificate.allocation[0].expiration_date, "")
}

output "vpn_issuer" {
  value = try(ibm_sm_private_certificate.allocation[0].issuer, "")
}
