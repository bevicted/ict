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

data "ibm_is_vpc" "cluster" {
  count = var.cluster_mode == "vpc" && var.vpc_id != null ? 1 : 0

  identifier = var.vpc_id
}

data "ibm_is_subnet" "cluster" {
  count = var.cluster_mode == "vpc" && length(coalesce(var.subnet_ids, [])) == 1 ? 1 : 0

  identifier = var.subnet_ids[0]
}

data "ibm_is_public_gateways" "cluster" {
  count = var.cluster_mode == "vpc" && length(coalesce(var.public_gateway_ids, [])) == 1 ? 1 : 0
}

data "ibm_is_vpc" "satellite" {
  count = local.satellite_managed_infrastructure_needed && var.vpc_id != null ? 1 : 0

  identifier = var.vpc_id
}

data "ibm_is_subnet" "satellite" {
  for_each = local.satellite_managed_infrastructure_needed ? toset(coalesce(var.subnet_ids, [])) : []

  identifier = each.value
}

data "ibm_is_public_gateways" "satellite" {
  count = local.satellite_managed_infrastructure_needed && length(coalesce(var.public_gateway_ids, [])) > 0 ? 1 : 0
}

data "ibm_is_ssh_key" "satellite" {
  count = local.satellite_managed_infrastructure_needed && var.satellite_ssh_key_id != null ? 1 : 0

  id = var.satellite_ssh_key_id
}

data "ibm_satellite_location" "satellite" {
  count = var.cluster_mode == "satellite" && var.satellite_location_id != null ? 1 : 0

  location = var.satellite_location_id
}

data "ibm_is_instances" "satellite_worker" {
  count = var.cluster_mode == "satellite" && length(coalesce(var.satellite_worker_instance_ids, [])) > 0 ? 1 : 0
}

locals {
  satellite_workers_reused                 = var.cluster_mode == "satellite" && length(coalesce(var.satellite_worker_instance_ids, [])) > 0
  satellite_managed_infrastructure_needed  = var.cluster_mode == "satellite" && !local.satellite_workers_reused
  supplied_satellite_worker_instance_ids   = local.satellite_workers_reused ? sort(var.satellite_worker_instance_ids) : []
  supplied_satellite_workers               = local.satellite_workers_reused ? [for instance in data.ibm_is_instances.satellite_worker[0].instances : instance if contains(local.supplied_satellite_worker_instance_ids, instance.id)] : []
  supplied_satellite_workers_by_id         = { for instance in local.supplied_satellite_workers : instance.id => instance }
  supplied_satellite_worker_hosts_by_id    = local.satellite_workers_reused ? { for id, instance in local.supplied_satellite_workers_by_id : id => try(one([for host in data.ibm_satellite_location.satellite[0].hosts : host if host.host_id == instance.id || host.host_name == instance.name]), null) } : {}
  effective_satellite_worker_host_id_by_id = { for id, host in local.supplied_satellite_worker_hosts_by_id : id => try(host.host_id, "") }
  effective_satellite_worker_zone_by_id    = { for id, instance in local.supplied_satellite_workers_by_id : id => instance.zone }
  supplied_public_gateway = var.cluster_mode == "vpc" && length(coalesce(var.public_gateway_ids, [])) == 1 ? try(one([
    for gateway in data.ibm_is_public_gateways.cluster[0].public_gateways : gateway
    if gateway.id == var.public_gateway_ids[0]
  ]), null) : null
  existing_subnet_public_gateway = var.cluster_mode == "vpc" && length(coalesce(var.subnet_ids, [])) == 1 ? data.ibm_is_subnet.cluster[0].public_gateway : ""
  managed_public_gateway_needed = var.cluster_mode == "vpc" && length(coalesce(var.public_gateway_ids, [])) == 0 && (
    length(coalesce(var.subnet_ids, [])) == 0 || local.existing_subnet_public_gateway == ""
  )
  managed_attachment_needed = var.cluster_mode == "vpc" && (
    length(coalesce(var.subnet_ids, [])) == 0 || local.existing_subnet_public_gateway == ""
  )
  effective_vpc_id = var.cluster_mode == "vpc" ? (
    var.vpc_id != null ? data.ibm_is_vpc.cluster[0].id :
    length(coalesce(var.subnet_ids, [])) == 1 ? data.ibm_is_subnet.cluster[0].vpc :
    length(coalesce(var.public_gateway_ids, [])) == 1 ? try(local.supplied_public_gateway.vpc, "") :
    ibm_is_vpc.cluster[0].id
  ) : null
  effective_subnet_id = var.cluster_mode == "vpc" ? (
    length(coalesce(var.subnet_ids, [])) == 1 ? data.ibm_is_subnet.cluster[0].id : ibm_is_subnet.cluster[0].id
  ) : null
  effective_public_gateway_id = var.cluster_mode == "vpc" ? (
    length(coalesce(var.public_gateway_ids, [])) == 1 ? try(local.supplied_public_gateway.id, "") :
    local.existing_subnet_public_gateway != "" ? local.existing_subnet_public_gateway :
    ibm_is_public_gateway.cluster[0].id
  ) : null

  supplied_satellite_subnets_by_zone = var.cluster_mode == "satellite" ? {
    for zone in var.satellite_zones : zone => try(one([
      for subnet in values(data.ibm_is_subnet.satellite) : subnet
      if subnet.zone == zone
    ]), null)
  } : {}
  supplied_satellite_gateways = var.cluster_mode == "satellite" && length(coalesce(var.public_gateway_ids, [])) > 0 ? [
    for gateway in data.ibm_is_public_gateways.satellite[0].public_gateways : gateway
    if contains(var.public_gateway_ids, gateway.id)
  ] : []
  supplied_satellite_gateways_by_zone = var.cluster_mode == "satellite" ? {
    for zone in var.satellite_zones : zone => try(one([
      for gateway in local.supplied_satellite_gateways : gateway
      if gateway.zone == zone
    ]), null)
  } : {}
  managed_satellite_subnet_zones = local.satellite_managed_infrastructure_needed && length(coalesce(var.subnet_ids, [])) == 0 ? var.satellite_zones : []
  existing_satellite_public_gateway_by_zone = var.cluster_mode == "satellite" ? {
    for zone in var.satellite_zones : zone => try(local.supplied_satellite_subnets_by_zone[zone].public_gateway, "")
  } : {}
  managed_satellite_gateway_zone_list = local.satellite_managed_infrastructure_needed && length(coalesce(var.public_gateway_ids, [])) == 0 ? [
    for zone in var.satellite_zones : zone
    if try(local.existing_satellite_public_gateway_by_zone[zone], "") == ""
  ] : []
  satellite_attachment_zone_list = local.satellite_managed_infrastructure_needed ? [
    for zone in var.satellite_zones : zone
    if try(local.existing_satellite_public_gateway_by_zone[zone], "") == ""
  ] : []
  effective_satellite_vpc_id = local.satellite_managed_infrastructure_needed ? (
    var.vpc_id != null ? data.ibm_is_vpc.satellite[0].id :
    length(coalesce(var.subnet_ids, [])) > 0 ? try(one(distinct([for subnet in values(data.ibm_is_subnet.satellite) : subnet.vpc])), "") :
    length(coalesce(var.public_gateway_ids, [])) > 0 ? try(one(distinct([for gateway in local.supplied_satellite_gateways : gateway.vpc])), "") :
    ibm_is_vpc.satellite[0].id
  ) : null
  effective_satellite_subnet_id_by_zone = local.satellite_managed_infrastructure_needed ? {
    for zone in var.satellite_zones : zone => length(coalesce(var.subnet_ids, [])) > 0 ? try(local.supplied_satellite_subnets_by_zone[zone].id, "") : ibm_is_subnet.satellite[index(local.managed_satellite_subnet_zones, zone)].id
  } : {}
  effective_satellite_gateway_id_by_zone = local.satellite_managed_infrastructure_needed ? {
    for zone in var.satellite_zones : zone => length(coalesce(var.public_gateway_ids, [])) > 0 ? try(local.supplied_satellite_gateways_by_zone[zone].id, "") : (
      local.existing_satellite_public_gateway_by_zone[zone] != "" ? local.existing_satellite_public_gateway_by_zone[zone] : ibm_is_public_gateway.satellite[index(local.managed_satellite_gateway_zone_list, zone)].id
    )
  } : {}
  effective_satellite_ssh_key_id  = local.satellite_managed_infrastructure_needed ? (var.satellite_ssh_key_id != null ? data.ibm_is_ssh_key.satellite[0].id : ibm_is_ssh_key.satellite[0].id) : null
  effective_satellite_location_id = var.cluster_mode == "satellite" ? (var.satellite_location_id != null ? data.ibm_satellite_location.satellite[0].id : ibm_satellite_location.satellite[0].id) : null
}

resource "ibm_is_vpc" "cluster" {
  count = var.cluster_mode == "vpc" && var.vpc_id == null && length(coalesce(var.subnet_ids, [])) == 0 && length(coalesce(var.public_gateway_ids, [])) == 0 ? 1 : 0

  name           = "${var.cluster_name}-vpc"
  resource_group = data.ibm_resource_group.selected.id
}

resource "ibm_is_subnet" "cluster" {
  count = var.cluster_mode == "vpc" && length(coalesce(var.subnet_ids, [])) == 0 ? 1 : 0

  name                     = "${var.cluster_name}-subnet"
  vpc                      = local.effective_vpc_id
  zone                     = var.zone
  resource_group           = data.ibm_resource_group.selected.id
  total_ipv4_address_count = 256
}

resource "ibm_is_public_gateway" "cluster" {
  count = local.managed_public_gateway_needed ? 1 : 0

  name = "${var.cluster_name}-gateway"
  vpc  = local.effective_vpc_id
  zone = var.zone
}

resource "ibm_is_subnet_public_gateway_attachment" "cluster" {
  count = local.managed_attachment_needed ? 1 : 0

  subnet         = local.effective_subnet_id
  public_gateway = local.effective_public_gateway_id
}

resource "ibm_container_vpc_cluster" "cluster" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  depends_on = [ibm_is_subnet_public_gateway_attachment.cluster]

  name              = var.cluster_name
  offering          = var.platform
  kube_version      = var.kube_version
  flavor            = var.flavor
  worker_count      = var.worker_count
  vpc_id            = local.effective_vpc_id
  resource_group_id = data.ibm_resource_group.selected.id
  wait_till         = "OneWorkerNodeReady"

  zones {
    name      = var.zone
    subnet_id = local.effective_subnet_id
  }

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z][a-z0-9-]{0,31}$", var.cluster_name))
      error_message = "VPC cluster name must be 32 or fewer characters, begin with a letter, and contain only lowercase letters, digits, and hyphens."
    }

    precondition {
      condition     = length(coalesce(var.public_gateway_ids, [])) == 0 || local.supplied_public_gateway != null
      error_message = "The supplied public gateway ID was not found."
    }

    precondition {
      condition     = var.vpc_id == null || length(coalesce(var.subnet_ids, [])) == 0 || data.ibm_is_vpc.cluster[0].id == data.ibm_is_subnet.cluster[0].vpc
      error_message = "The supplied VPC and subnet must belong to the same VPC."
    }

    precondition {
      condition     = var.vpc_id == null || length(coalesce(var.public_gateway_ids, [])) == 0 || data.ibm_is_vpc.cluster[0].id == try(local.supplied_public_gateway.vpc, "")
      error_message = "The supplied VPC and public gateway must belong to the same VPC."
    }

    precondition {
      condition     = length(coalesce(var.subnet_ids, [])) == 0 || length(coalesce(var.public_gateway_ids, [])) == 0 || data.ibm_is_subnet.cluster[0].vpc == try(local.supplied_public_gateway.vpc, "")
      error_message = "The supplied subnet and public gateway must belong to the same VPC."
    }

    precondition {
      condition     = length(coalesce(var.subnet_ids, [])) == 0 || data.ibm_is_subnet.cluster[0].zone == var.zone
      error_message = "The supplied subnet must be in the requested zone."
    }

    precondition {
      condition     = length(coalesce(var.public_gateway_ids, [])) == 0 || try(local.supplied_public_gateway.zone, "") == var.zone
      error_message = "The supplied public gateway must be in the requested zone."
    }

    precondition {
      condition     = length(coalesce(var.subnet_ids, [])) == 0 || local.existing_subnet_public_gateway == "" || local.existing_subnet_public_gateway == local.effective_public_gateway_id
      error_message = "The supplied subnet already has a different public gateway attachment."
    }
  }
}

resource "ibm_container_cluster" "cluster" {
  count = var.cluster_mode == "classic" ? 1 : 0

  name              = var.cluster_name
  datacenter        = var.datacenter
  kube_version      = var.kube_version
  machine_type      = var.machine_type
  default_pool_size = var.worker_count
  hardware          = "shared"
  public_vlan_id    = var.public_vlan_id
  private_vlan_id   = var.private_vlan_id
  no_subnet         = true
  resource_group_id = data.ibm_resource_group.selected.id
  wait_till         = "OneWorkerNodeReady"
}

resource "ibm_is_vpc" "satellite" {
  count = local.satellite_managed_infrastructure_needed && var.vpc_id == null && length(coalesce(var.subnet_ids, [])) == 0 && length(coalesce(var.public_gateway_ids, [])) == 0 ? 1 : 0

  name           = "${var.cluster_name}-satellite-vpc"
  resource_group = data.ibm_resource_group.selected.id
}

resource "ibm_is_subnet" "satellite" {
  count = length(local.managed_satellite_subnet_zones)

  name                     = "${var.cluster_name}-satellite-subnet-${count.index + 1}"
  vpc                      = local.effective_satellite_vpc_id
  zone                     = local.managed_satellite_subnet_zones[count.index]
  resource_group           = data.ibm_resource_group.selected.id
  total_ipv4_address_count = 256
}

resource "ibm_is_public_gateway" "satellite" {
  count = length(local.managed_satellite_gateway_zone_list)

  name = "${var.cluster_name}-satellite-gateway-${count.index + 1}"
  vpc  = local.effective_satellite_vpc_id
  zone = local.managed_satellite_gateway_zone_list[count.index]
}

resource "ibm_is_subnet_public_gateway_attachment" "satellite" {
  count = length(local.satellite_attachment_zone_list)

  subnet         = local.effective_satellite_subnet_id_by_zone[local.satellite_attachment_zone_list[count.index]]
  public_gateway = local.effective_satellite_gateway_id_by_zone[local.satellite_attachment_zone_list[count.index]]
}

resource "ibm_is_ssh_key" "satellite" {
  count = local.satellite_managed_infrastructure_needed && var.satellite_ssh_key_id == null ? 1 : 0

  name           = "${var.cluster_name}-satellite-ssh"
  resource_group = data.ibm_resource_group.selected.id
  public_key     = var.satellite_ssh_public_key
}

resource "ibm_satellite_location" "satellite" {
  count = var.cluster_mode == "satellite" && var.satellite_location_id == null ? 1 : 0

  location          = "${var.cluster_name}-satellite"
  managed_from      = var.satellite_managed_from
  zones             = var.satellite_zones
  coreos_enabled    = true
  resource_group_id = data.ibm_resource_group.selected.id

  lifecycle {
    precondition {
      condition = alltrue([
        var.satellite_managed_from != null,
        var.satellite_host_image != null,
        var.satellite_host_profile != null,
        var.satellite_worker_operating_system != null,
        var.satellite_zones != null,
      ])
      error_message = "A new Satellite location requires management location, three VPC zones, host image/profile, and worker operating system."
    }
  }
}

data "ibm_is_image" "satellite_host" {
  count = local.satellite_managed_infrastructure_needed ? 1 : 0

  name = var.satellite_host_image
}

data "ibm_satellite_attach_host_script" "satellite_control_plane" {
  count = var.cluster_mode == "satellite" && var.satellite_location_id == null ? 1 : 0

  location      = local.effective_satellite_location_id
  labels        = ["satellite-role:control-plane"]
  host_provider = "ibm"
}

data "ibm_satellite_attach_host_script" "satellite_worker" {
  count = local.satellite_managed_infrastructure_needed ? 1 : 0

  location      = local.effective_satellite_location_id
  labels        = ["satellite-role:cluster-worker"]
  host_provider = "ibm"
}

resource "ibm_is_instance" "satellite_control_plane" {
  count = var.cluster_mode == "satellite" && var.satellite_location_id == null ? 3 : 0

  depends_on = [ibm_is_subnet_public_gateway_attachment.satellite]

  name           = "${var.cluster_name}-satellite-control-${count.index + 1}"
  vpc            = local.effective_satellite_vpc_id
  zone           = var.satellite_zones[count.index]
  image          = data.ibm_is_image.satellite_host[0].id
  profile        = var.satellite_host_profile
  keys           = [local.effective_satellite_ssh_key_id]
  resource_group = data.ibm_resource_group.selected.id
  user_data      = data.ibm_satellite_attach_host_script.satellite_control_plane[0].host_script

  primary_network_interface {
    subnet = local.effective_satellite_subnet_id_by_zone[var.satellite_zones[count.index]]
  }
}

resource "ibm_satellite_host" "satellite_control_plane" {
  count = var.cluster_mode == "satellite" && var.satellite_location_id == null ? 3 : 0

  location      = local.effective_satellite_location_id
  host_id       = ibm_is_instance.satellite_control_plane[count.index].name
  labels        = ["satellite-role:control-plane"]
  zone          = var.satellite_zones[count.index]
  host_provider = "ibm"
  wait_till     = "location_normal"
}

resource "ibm_is_instance" "satellite_worker" {
  count = local.satellite_managed_infrastructure_needed ? var.worker_count : 0

  depends_on = [ibm_is_subnet_public_gateway_attachment.satellite]

  name           = "${var.cluster_name}-satellite-worker-${count.index + 1}"
  vpc            = local.effective_satellite_vpc_id
  zone           = var.satellite_zones[count.index % length(var.satellite_zones)]
  image          = data.ibm_is_image.satellite_host[0].id
  profile        = var.satellite_host_profile
  keys           = [local.effective_satellite_ssh_key_id]
  resource_group = data.ibm_resource_group.selected.id
  user_data      = data.ibm_satellite_attach_host_script.satellite_worker[0].host_script

  primary_network_interface {
    subnet = local.effective_satellite_subnet_id_by_zone[var.satellite_zones[count.index % length(var.satellite_zones)]]
  }
}

resource "ibm_satellite_cluster" "satellite" {
  count = var.cluster_mode == "satellite" ? 1 : 0

  depends_on = [ibm_satellite_host.satellite_control_plane]

  name                    = var.cluster_name
  location                = local.effective_satellite_location_id
  resource_group_id       = data.ibm_resource_group.selected.id
  kube_version            = var.kube_version
  operating_system        = var.satellite_worker_operating_system
  worker_count            = var.worker_count
  infrastructure_topology = "single-replica"
  enable_config_admin     = true
  wait_for_worker_update  = true

  zones {
    id = var.satellite_zones[0]
  }

  default_worker_pool_labels = {
    "satellite-role" = "cluster-worker"
  }

  lifecycle {
    precondition {
      condition     = local.satellite_workers_reused || length(coalesce(var.subnet_ids, [])) == 0 || (length(data.ibm_is_subnet.satellite) == length(var.satellite_zones) && alltrue([for zone in var.satellite_zones : try(local.supplied_satellite_subnets_by_zone[zone].id, "") != ""]))
      error_message = "Supplied Satellite subnet IDs must provide exactly one subnet in every requested zone."
    }

    precondition {
      condition     = local.satellite_workers_reused || length(coalesce(var.public_gateway_ids, [])) == 0 || (length(local.supplied_satellite_gateways) == length(var.satellite_zones) && alltrue([for zone in var.satellite_zones : try(local.supplied_satellite_gateways_by_zone[zone].id, "") != ""]))
      error_message = "Supplied Satellite public gateway IDs must provide exactly one gateway in every requested zone."
    }

    precondition {
      condition = local.satellite_workers_reused || length(distinct(compact(concat(
        var.vpc_id != null ? [data.ibm_is_vpc.satellite[0].id] : [],
        [for subnet in values(data.ibm_is_subnet.satellite) : subnet.vpc],
        [for gateway in local.supplied_satellite_gateways : gateway.vpc],
      )))) <= 1
      error_message = "Supplied Satellite VPC, subnets, and public gateways must belong to one VPC."
    }

    precondition {
      condition     = local.satellite_workers_reused || alltrue([for zone in var.satellite_zones : length(coalesce(var.subnet_ids, [])) == 0 || try(local.supplied_satellite_subnets_by_zone[zone].zone, "") == zone])
      error_message = "Supplied Satellite subnets must match the requested zones."
    }

    precondition {
      condition     = local.satellite_workers_reused || alltrue([for zone in var.satellite_zones : length(coalesce(var.public_gateway_ids, [])) == 0 || try(local.supplied_satellite_gateways_by_zone[zone].zone, "") == zone])
      error_message = "Supplied Satellite public gateways must match the requested zones."
    }

    precondition {
      condition     = local.satellite_workers_reused || alltrue([for zone in var.satellite_zones : try(local.existing_satellite_public_gateway_by_zone[zone], "") == "" || local.existing_satellite_public_gateway_by_zone[zone] == local.effective_satellite_gateway_id_by_zone[zone]])
      error_message = "A supplied Satellite subnet already has a different public gateway attachment."
    }

    precondition {
      condition     = var.satellite_location_id == null || (data.ibm_satellite_location.satellite[0].host_attached_count >= 3 && length(setsubtract(toset(var.satellite_zones), data.ibm_satellite_location.satellite[0].zones)) == 0)
      error_message = "The supplied Satellite location must have at least three attached hosts and cover every requested zone."
    }

    precondition {
      condition     = !local.satellite_workers_reused || (var.satellite_location_id != null && var.vpc_id == null && length(coalesce(var.subnet_ids, [])) == 0 && length(coalesce(var.public_gateway_ids, [])) == 0 && var.satellite_host_image == null && var.satellite_host_profile == null && var.satellite_ssh_public_key == null && var.satellite_ssh_key_id == null)
      error_message = "Reused Satellite workers require an existing location and cannot use networking, image, profile, or SSH key inputs."
    }

    precondition {
      condition     = !local.satellite_workers_reused || (length(local.supplied_satellite_workers) == length(local.supplied_satellite_worker_instance_ids) && alltrue([for id in local.supplied_satellite_worker_instance_ids : length([for instance in data.ibm_is_instances.satellite_worker[0].instances : instance if instance.id == id]) == 1]) && alltrue([for instance in local.supplied_satellite_workers : contains(var.satellite_zones, instance.zone)]) && length(distinct([for instance in local.supplied_satellite_workers : instance.zone])) == length(local.supplied_satellite_workers))
      error_message = "Each supplied Satellite worker VSI must resolve exactly once and occupy a distinct requested zone."
    }

    precondition {
      condition     = !local.satellite_workers_reused || alltrue([for id in local.supplied_satellite_worker_instance_ids : try(local.supplied_satellite_worker_hosts_by_id[id].host_id, "") != "" && lower(try(local.supplied_satellite_worker_hosts_by_id[id].status, "")) == "ready" && trimspace(try(local.supplied_satellite_worker_hosts_by_id[id].cluster_name, "")) == ""])
      error_message = "Each supplied Satellite worker VSI must be registered in the location, unassigned, and ready."
    }
  }
}

resource "ibm_satellite_host" "satellite_worker" {
  count = var.cluster_mode == "satellite" ? var.worker_count : 0

  depends_on = [ibm_satellite_cluster.satellite]

  location      = local.effective_satellite_location_id
  cluster       = ibm_satellite_cluster.satellite[0].id
  worker_pool   = "default"
  host_id       = local.satellite_workers_reused ? local.effective_satellite_worker_host_id_by_id[local.supplied_satellite_worker_instance_ids[count.index]] : ibm_is_instance.satellite_worker[count.index].name
  labels        = ["satellite-role:cluster-worker"]
  zone          = local.satellite_workers_reused ? local.effective_satellite_worker_zone_by_id[local.supplied_satellite_worker_instance_ids[count.index]] : var.satellite_zones[count.index % length(var.satellite_zones)]
  host_provider = "ibm"
}
