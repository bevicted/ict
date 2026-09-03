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
