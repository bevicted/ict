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
  region = var.auth_secrets_manager_region
}

# Keep this resource address identical to the companion auth root. This cleanup
# root intentionally has no cluster or VPN data sources, so destroy can proceed
# from allocation state even after the cluster is gone.
resource "ibm_sm_private_certificate" "allocation" {
  count = 1

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
