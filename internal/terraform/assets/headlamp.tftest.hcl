mock_provider "ibm" {
  mock_data "ibm_resource_group" {
    defaults = {
      id = "resource-group-existing"
    }
  }
}

run "headlamp_is_absent_by_default" {
  command = plan

  variables {
    cluster_name        = "synthetic-vpc"
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
    condition     = length(ibm_container_addons.headlamp) == 0
    error_message = "Headlamp must be absent when it is not selected."
  }
}

run "headlamp_uses_the_vpc_cluster" {
  command = plan

  variables {
    cluster_name        = "synthetic-vpc"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "kubernetes"
    kube_version        = "1.30"
    worker_count        = 1
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
    headlamp            = true
  }

  override_resource {
    target          = ibm_container_vpc_cluster.cluster[0]
    override_during = plan
    values = {
      id = "vpc-cluster"
    }
  }

  assert {
    condition     = length(ibm_container_addons.headlamp) == 1 && ibm_container_addons.headlamp[0].cluster == "vpc-cluster" && ibm_container_addons.headlamp[0].resource_group_id == "resource-group-existing" && !ibm_container_addons.headlamp[0].manage_all_addons && one(ibm_container_addons.headlamp[0].addons).name == "headlamp"
    error_message = "Headlamp must manage only the VPC cluster add-on in the selected resource group."
  }
}

run "headlamp_uses_the_classic_cluster" {
  command = plan

  variables {
    cluster_name        = "synthetic-classic"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "classic"
    platform            = "kubernetes"
    kube_version        = "1.30"
    worker_count        = 1
    datacenter          = "dal10"
    machine_type        = "bx2.2x8"
    public_vlan_id      = "123"
    private_vlan_id     = "456"
    headlamp            = true
  }

  override_resource {
    target          = ibm_container_cluster.cluster[0]
    override_during = plan
    values = {
      id = "classic-cluster"
    }
  }

  assert {
    condition     = length(ibm_container_addons.headlamp) == 1 && ibm_container_addons.headlamp[0].cluster == "classic-cluster" && ibm_container_addons.headlamp[0].resource_group_id == "resource-group-existing" && !ibm_container_addons.headlamp[0].manage_all_addons && one(ibm_container_addons.headlamp[0].addons).name == "headlamp"
    error_message = "Headlamp must manage only the Classic cluster add-on in the selected resource group."
  }
}

run "headlamp_rejects_openshift_vpc" {
  command = plan

  variables {
    cluster_name        = "synthetic-vpc"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "vpc"
    platform            = "openshift"
    kube_version        = "4.18_openshift"
    worker_count        = 2
    zone                = "us-south-1"
    flavor              = "bx2.2x8"
    headlamp            = true
  }

  expect_failures = [ibm_container_vpc_cluster.cluster]
}

run "headlamp_rejects_openshift_classic" {
  command = plan

  variables {
    cluster_name        = "synthetic-classic"
    resource_group_name = "fixture-resource-group"
    region              = "us-south"
    cluster_mode        = "classic"
    platform            = "openshift"
    kube_version        = "4.18_openshift"
    worker_count        = 2
    datacenter          = "dal10"
    machine_type        = "bx2.2x8"
    public_vlan_id      = "123"
    private_vlan_id     = "456"
    headlamp            = true
  }

  expect_failures = [ibm_container_cluster.cluster]
}
