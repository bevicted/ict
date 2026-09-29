mock_provider "ibm" {
  mock_data "ibm_resource_group" {
    defaults = {
      id = "resource-group-existing"
    }
  }

  mock_data "ibm_is_vpn_server" {
    defaults = {
      client_ip_pool = "192.168.192.0/22"
    }
  }

  mock_data "ibm_is_vpc" {
    defaults = {
      id = "vpc-existing"
    }
  }

  mock_data "ibm_is_security_group" {
    defaults = {
      id = "api-vpe-security-group"
    }
  }
}

run "public_vpc_does_not_read_or_manage_private_vpn_ingress" {
  command = plan

  variables {
    cluster_name        = "private-vpe-fixture"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "kubernetes"
    kube_version        = "1.30"
    worker_count        = 1
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
  }

  assert {
    condition     = length(data.ibm_is_vpn_server.private_api) == 0 && length(data.ibm_is_security_group.private_api) == 0 && length(ibm_is_security_group_rule.private_api_vpn_ingress) == 0
    error_message = "Public VPC clusters must not read or manage private API VPN ingress."
  }
}

run "private_vpc_allows_only_the_vpn_pool_on_the_explicit_vpe_port" {
  command = plan

  variables {
    cluster_name        = "private-vpe-fixture"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "kubernetes"
    kube_version        = "1.30"
    private_only        = true
    auth_vpn_server_id  = "vpn-server-123"
    vpc_id              = "vpc-existing"
    worker_count        = 1
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
  }

  override_resource {
    target          = ibm_container_vpc_cluster.cluster[0]
    override_during = plan
    values = {
      id                       = "cluster-123"
      vpe_service_endpoint_url = "https://api.private.example.invalid:8443"
    }
  }

  assert {
    condition     = length(data.ibm_is_security_group.private_api) == 1 && data.ibm_is_security_group.private_api[0].name == "kube-vpegw-cluster-123" && data.ibm_is_security_group.private_api[0].vpc == "vpc-existing" && length(ibm_is_security_group_rule.private_api_vpn_ingress) == 1 && ibm_is_security_group_rule.private_api_vpn_ingress[0].direction == "inbound" && ibm_is_security_group_rule.private_api_vpn_ingress[0].protocol == "tcp" && ibm_is_security_group_rule.private_api_vpn_ingress[0].remote == "192.168.192.0/22" && ibm_is_security_group_rule.private_api_vpn_ingress[0].port_min == 8443 && ibm_is_security_group_rule.private_api_vpn_ingress[0].port_max == 8443
    error_message = "Private VPC ingress must use the generated security group in the cluster VPC, exact VPN pool, and explicit endpoint port."
  }
}

run "private_vpc_defaults_https_port_to_443" {
  command = plan

  variables {
    cluster_name        = "private-vpe-fixture"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "kubernetes"
    kube_version        = "1.30"
    private_only        = true
    auth_vpn_server_id  = "vpn-server-123"
    vpc_id              = "vpc-existing"
    worker_count        = 1
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
  }

  override_resource {
    target          = ibm_container_vpc_cluster.cluster[0]
    override_during = plan
    values = {
      id                       = "cluster-123"
      vpe_service_endpoint_url = "https://api.private.example.invalid"
    }
  }

  assert {
    condition     = ibm_is_security_group_rule.private_api_vpn_ingress[0].port_min == 443 && ibm_is_security_group_rule.private_api_vpn_ingress[0].port_max == 443
    error_message = "HTTPS VPE endpoints without an explicit port must use TCP 443."
  }
}

run "private_vpc_rejects_non_https_vpe_endpoint" {
  command = plan

  variables {
    cluster_name        = "private-vpe-fixture"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "kubernetes"
    kube_version        = "1.30"
    private_only        = true
    auth_vpn_server_id  = "vpn-server-123"
    vpc_id              = "vpc-existing"
    worker_count        = 1
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
  }

  override_resource {
    target          = ibm_container_vpc_cluster.cluster[0]
    override_during = plan
    values = {
      id                       = "cluster-123"
      vpe_service_endpoint_url = "http://api.private.example.invalid:443"
    }
  }

  expect_failures = [ibm_is_security_group_rule.private_api_vpn_ingress]
}

run "private_vpc_rejects_invalid_vpe_port" {
  command = plan

  variables {
    cluster_name        = "private-vpe-fixture"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "kubernetes"
    kube_version        = "1.30"
    private_only        = true
    auth_vpn_server_id  = "vpn-server-123"
    vpc_id              = "vpc-existing"
    worker_count        = 1
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
  }

  override_resource {
    target          = ibm_container_vpc_cluster.cluster[0]
    override_during = plan
    values = {
      id                       = "cluster-123"
      vpe_service_endpoint_url = "https://api.private.example.invalid:65536"
    }
  }

  expect_failures = [ibm_is_security_group_rule.private_api_vpn_ingress]
}
