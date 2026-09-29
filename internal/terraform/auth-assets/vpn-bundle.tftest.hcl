mock_provider "ibm" {}

run "vpn_ca_chain_is_a_string" {
  command = plan

  variables {
    cluster_name                = "fixture-vpc"
    cluster_mode                = "vpc"
    resource_group_name         = "fixture-resource-group"
    region                      = "us-south"
    config_dir                  = "/auth-tmpfs/ict-auth-test"
    auth_allocation_uid         = "allocation-123"
    auth_attempt_id             = "attempt-123"
    auth_vpn_server_id          = "vpn-123"
    auth_secrets_manager_id     = "secrets-123"
    auth_secrets_manager_region = "us-south"
    auth_secret_group_id        = "group-123"
    auth_certificate_template   = "template-123"
    auth_issuer                 = "issuer-123"
    auth_ttl                    = "24h"
  }

  override_data {
    target = data.ibm_container_vpc_cluster.target[0]
    values = {
      id                           = "cluster-123"
      public_service_endpoint      = false
      private_service_endpoint     = true
      private_service_endpoint_url = "https://private.example.invalid"
    }
  }

  override_resource {
    target          = ibm_sm_private_certificate.allocation[0]
    override_during = plan
    values = {
      ca_chain              = ["-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"]
      certificate_authority = "issuer-123"
      issuer                = "CN=issuer-123,O=Example"
    }
  }

  assert {
    condition     = output.auth_mode == "vpn" && output.vpn_ca_chain == "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----" && output.vpn_certificate_authority == "issuer-123"
    error_message = "VPN CA chains must be raw-output-compatible strings and certificate authorities must use their configured name, not the issuer DN."
  }
}

run "incomplete_private_bundle_fails_closed" {
  command = plan

  variables {
    cluster_name                = "fixture-vpc"
    cluster_mode                = "vpc"
    resource_group_name         = "fixture-resource-group"
    region                      = "us-south"
    config_dir                  = "/auth-tmpfs/ict-auth-test"
    auth_allocation_uid         = "allocation-123"
    auth_secrets_manager_id     = "secrets-123"
    auth_secrets_manager_region = "us-south"
    auth_secret_group_id        = "group-123"
    auth_certificate_template   = "template-123"
    auth_issuer                 = "issuer-123"
    auth_ttl                    = "24h"
  }

  override_data {
    target = data.ibm_container_vpc_cluster.target[0]
    values = {
      id                           = "cluster-123"
      public_service_endpoint      = false
      private_service_endpoint     = true
      private_service_endpoint_url = "https://private.example.invalid"
    }
  }

  assert {
    condition = (
      output.auth_mode == "unsupported" &&
      length(data.ibm_container_cluster_config.private_admin) == 0 &&
      length(data.ibm_is_vpn_server_client_configuration.profile) == 0 &&
      length(ibm_sm_private_certificate.allocation) == 0 &&
      output.private_ca_certificate == "" &&
      output.private_admin_certificate == "" &&
      output.private_admin_key == "" &&
      output.vpn_profile == "" &&
      output.vpn_certificate == "" &&
      output.vpn_private_key == "" &&
      output.vpn_ca_chain == "" &&
      output.vpn_expiry == "" &&
      output.vpn_certificate_authority == ""
    )
    error_message = "Incomplete private authentication policy must not create or export a VPN bundle."
  }
}
