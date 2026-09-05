mock_provider "ibm" {}

run "satellite_hosts_use_three_zones_and_default_worker_pool" {
  command = plan

  variables {
    cluster_name                      = "synthetic-satellite"
    resource_group_name               = "fixture-resource-group"
    region                            = "us-south"
    cluster_mode                      = "satellite"
    platform                          = "openshift"
    kube_version                      = "4.17_openshift"
    worker_count                      = 1
    satellite_zones                   = ["us-south-1", "us-south-2", "us-south-3"]
    satellite_managed_from            = "us-south"
    satellite_host_image              = "rhel-8-synthetic"
    satellite_host_profile            = "bx2-4x16"
    satellite_ssh_public_key          = "synthetic-public-key"
    satellite_worker_operating_system = "RHCOS"
  }

  assert {
    condition     = length(ibm_is_instance.satellite_control_plane) == 3 && length(ibm_is_instance.satellite_worker) == 1 && ibm_satellite_host.satellite_worker[0].worker_pool == "default"
    error_message = "Satellite must create three control-plane hosts and assign the default worker host to the default pool."
  }

  assert {
    condition     = ibm_is_instance.satellite_control_plane[0].zone == "us-south-1" && ibm_is_instance.satellite_control_plane[1].zone == "us-south-2" && ibm_is_instance.satellite_control_plane[2].zone == "us-south-3" && contains(ibm_satellite_host.satellite_worker[0].labels, "satellite-role:cluster-worker")
    error_message = "Satellite control-plane and worker hosts must retain the selected zones and worker label."
  }
}

run "satellite_reuse_maps_unordered_networking_and_suppresses_control_plane" {
  command = plan

  variables {
    cluster_name                      = "synthetic-satellite"
    resource_group_name               = "fixture-resource-group"
    region                            = "us-south"
    cluster_mode                      = "satellite"
    platform                          = "openshift"
    kube_version                      = "4.17_openshift"
    worker_count                      = 1
    vpc_id                            = "vpc-existing"
    subnet_ids                        = ["subnet-3", "subnet-1", "subnet-2"]
    public_gateway_ids                = ["gateway-2", "gateway-3", "gateway-1"]
    satellite_zones                   = ["us-south-1", "us-south-2", "us-south-3"]
    satellite_location_id             = "location-existing"
    satellite_host_image              = "rhel-8-synthetic"
    satellite_host_profile            = "bx2-4x16"
    satellite_ssh_key_id              = "key-existing"
    satellite_worker_operating_system = "RHCOS"
  }

  override_data {
    target = data.ibm_is_vpc.satellite[0]
    values = { id = "vpc-existing" }
  }

  override_data {
    target = data.ibm_is_subnet.satellite["subnet-1"]
    values = { id = "subnet-1", vpc = "vpc-existing", zone = "us-south-1", public_gateway = "gateway-1" }
  }

  override_data {
    target = data.ibm_is_subnet.satellite["subnet-2"]
    values = { id = "subnet-2", vpc = "vpc-existing", zone = "us-south-2", public_gateway = "gateway-2" }
  }

  override_data {
    target = data.ibm_is_subnet.satellite["subnet-3"]
    values = { id = "subnet-3", vpc = "vpc-existing", zone = "us-south-3", public_gateway = "gateway-3" }
  }

  override_data {
    target = data.ibm_is_public_gateways.satellite[0]
    values = {
      public_gateways = [
        { id = "gateway-1", vpc = "vpc-existing", zone = "us-south-1" },
        { id = "gateway-2", vpc = "vpc-existing", zone = "us-south-2" },
        { id = "gateway-3", vpc = "vpc-existing", zone = "us-south-3" },
      ]
    }
  }

  override_data {
    target = data.ibm_satellite_location.satellite[0]
    values = { id = "location-existing", host_attached_count = 3, zones = ["us-south-1", "us-south-2", "us-south-3"] }
  }

  override_data {
    target = data.ibm_is_ssh_key.satellite[0]
    values = { id = "key-existing" }
  }

  assert {
    condition     = length(ibm_is_vpc.satellite) == 0 && length(ibm_is_subnet.satellite) == 0 && length(ibm_is_public_gateway.satellite) == 0 && length(ibm_is_subnet_public_gateway_attachment.satellite) == 0 && length(ibm_is_ssh_key.satellite) == 0 && length(ibm_satellite_location.satellite) == 0 && length(ibm_is_instance.satellite_control_plane) == 0 && length(ibm_satellite_host.satellite_control_plane) == 0 && length(ibm_is_instance.satellite_worker) == 1
    error_message = "Complete Satellite reuse must observe networking, key, and location while creating only workers."
  }

  assert {
    condition     = ibm_is_instance.satellite_worker[0].zone == "us-south-1" && ibm_is_instance.satellite_worker[0].primary_network_interface[0].subnet == "subnet-1" && contains(ibm_is_instance.satellite_worker[0].keys, "key-existing")
    error_message = "Unordered reused Satellite networking must be selected by its reported zone."
  }
}

run "satellite_reused_workers_are_unordered_and_create_only_assignments" {
  command = plan

  variables {
    cluster_name                      = "synthetic-satellite"
    resource_group_name               = "fixture-resource-group"
    region                            = "us-south"
    cluster_mode                      = "satellite"
    platform                          = "openshift"
    kube_version                      = "4.17_openshift"
    worker_count                      = 3
    satellite_zones                   = ["us-south-1", "us-south-2", "us-south-3"]
    satellite_location_id             = "location-existing"
    satellite_worker_instance_ids     = ["worker-3", "worker-1", "worker-2"]
    satellite_worker_operating_system = "RHCOS"
  }

  override_data {
    target = data.ibm_satellite_location.satellite[0]
    values = {
      id                  = "location-existing"
      host_attached_count = 3
      zones               = ["us-south-1", "us-south-2", "us-south-3"]
      hosts = [
        { host_id = "host-1", host_name = "worker-1", cluster_name = "", status = "ready", zone = "us-south-1" },
        { host_id = "host-2", host_name = "worker-2", cluster_name = "", status = "ready", zone = "us-south-2" },
        { host_id = "host-3", host_name = "worker-3", cluster_name = "", status = "ready", zone = "us-south-3" },
      ]
    }
  }

  override_data {
    target = data.ibm_is_instances.satellite_worker[0]
    values = {
      instances = [
        { id = "worker-2", name = "worker-2", zone = "us-south-2" },
        { id = "worker-3", name = "worker-3", zone = "us-south-3" },
        { id = "worker-1", name = "worker-1", zone = "us-south-1" },
      ]
    }
  }

  assert {
    condition     = length(ibm_is_vpc.satellite) == 0 && length(ibm_is_subnet.satellite) == 0 && length(ibm_is_public_gateway.satellite) == 0 && length(ibm_is_subnet_public_gateway_attachment.satellite) == 0 && length(ibm_is_ssh_key.satellite) == 0 && length(ibm_satellite_location.satellite) == 0 && length(data.ibm_is_image.satellite_host) == 0 && length(data.ibm_satellite_attach_host_script.satellite_worker) == 0 && length(ibm_is_instance.satellite_worker) == 0 && length(ibm_satellite_host.satellite_worker) == 3
    error_message = "Reused workers must not create or discover VPC, image, key, or VSI infrastructure."
  }

  assert {
    condition     = ibm_satellite_host.satellite_worker[0].host_id == "host-1" && ibm_satellite_host.satellite_worker[0].zone == "us-south-1" && ibm_satellite_host.satellite_worker[1].host_id == "host-2" && ibm_satellite_host.satellite_worker[1].zone == "us-south-2" && ibm_satellite_host.satellite_worker[2].host_id == "host-3" && ibm_satellite_host.satellite_worker[2].zone == "us-south-3"
    error_message = "Reused workers must be assigned by their reported IDs and zones, not input position."
  }
}

run "satellite_reused_worker_requires_ready_unassigned_location_host" {
  command = plan

  variables {
    cluster_name                      = "synthetic-satellite"
    resource_group_name               = "fixture-resource-group"
    region                            = "us-south"
    cluster_mode                      = "satellite"
    platform                          = "openshift"
    kube_version                      = "4.17_openshift"
    worker_count                      = 1
    satellite_zones                   = ["us-south-1", "us-south-2", "us-south-3"]
    satellite_location_id             = "location-existing"
    satellite_worker_instance_ids     = ["worker-1"]
    satellite_worker_operating_system = "RHCOS"
  }

  override_data {
    target = data.ibm_satellite_location.satellite[0]
    values = {
      id                  = "location-existing"
      host_attached_count = 3
      zones               = ["us-south-1", "us-south-2", "us-south-3"]
      hosts               = [{ host_id = "host-1", host_name = "worker-1", cluster_name = "other-cluster", status = "ready", zone = "us-south-1" }]
    }
  }

  override_data {
    target = data.ibm_is_instances.satellite_worker[0]
    values = { instances = [{ id = "worker-1", name = "worker-1", zone = "us-south-1" }] }
  }

  expect_failures = [ibm_satellite_cluster.satellite]
}

run "satellite_reused_location_without_three_attached_hosts_fails_plan" {
  command = plan

  variables {
    cluster_name                      = "synthetic-satellite"
    resource_group_name               = "fixture-resource-group"
    region                            = "us-south"
    cluster_mode                      = "satellite"
    platform                          = "openshift"
    kube_version                      = "4.17_openshift"
    worker_count                      = 1
    satellite_zones                   = ["us-south-1", "us-south-2", "us-south-3"]
    satellite_location_id             = "location-existing"
    satellite_host_image              = "rhel-8-synthetic"
    satellite_host_profile            = "bx2-4x16"
    satellite_ssh_public_key          = "synthetic-public-key"
    satellite_worker_operating_system = "RHCOS"
  }

  override_data {
    target = data.ibm_satellite_location.satellite[0]
    values = { id = "location-existing", host_attached_count = 2, zones = ["us-south-1", "us-south-2", "us-south-3"] }
  }

  expect_failures = [ibm_satellite_cluster.satellite]
}
