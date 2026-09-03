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

resource "ibm_is_vpc" "cluster" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  name           = "${var.cluster_name}-vpc"
  resource_group = data.ibm_resource_group.selected.id
}

resource "ibm_is_subnet" "cluster" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  name                     = "${var.cluster_name}-subnet"
  vpc                      = ibm_is_vpc.cluster[0].id
  zone                     = var.zone
  resource_group           = data.ibm_resource_group.selected.id
  total_ipv4_address_count = 256
}

resource "ibm_is_public_gateway" "cluster" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  name = "${var.cluster_name}-gateway"
  vpc  = ibm_is_vpc.cluster[0].id
  zone = var.zone
}

resource "ibm_is_subnet_public_gateway_attachment" "cluster" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  subnet         = ibm_is_subnet.cluster[0].id
  public_gateway = ibm_is_public_gateway.cluster[0].id
}

resource "ibm_container_vpc_cluster" "cluster" {
  count = var.cluster_mode == "vpc" ? 1 : 0

  depends_on = [ibm_is_subnet_public_gateway_attachment.cluster]

  name              = var.cluster_name
  offering          = var.platform
  kube_version      = var.kube_version
  flavor            = var.flavor
  worker_count      = var.worker_count
  vpc_id            = ibm_is_vpc.cluster[0].id
  resource_group_id = data.ibm_resource_group.selected.id
  wait_till         = "OneWorkerNodeReady"

  zones {
    name      = var.zone
    subnet_id = ibm_is_subnet.cluster[0].id
  }

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z][a-z0-9-]{0,31}$", var.cluster_name))
      error_message = "VPC cluster name must be 32 or fewer characters, begin with a letter, and contain only lowercase letters, digits, and hyphens."
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
  count = var.cluster_mode == "satellite" ? 1 : 0

  name           = "${var.cluster_name}-satellite-vpc"
  resource_group = data.ibm_resource_group.selected.id
}

resource "ibm_is_subnet" "satellite" {
  count = var.cluster_mode == "satellite" ? length(var.satellite_zones) : 0

  name                     = "${var.cluster_name}-satellite-subnet-${count.index + 1}"
  vpc                      = ibm_is_vpc.satellite[0].id
  zone                     = var.satellite_zones[count.index]
  resource_group           = data.ibm_resource_group.selected.id
  total_ipv4_address_count = 256
}

resource "ibm_is_public_gateway" "satellite" {
  count = var.cluster_mode == "satellite" ? length(var.satellite_zones) : 0

  name = "${var.cluster_name}-satellite-gateway-${count.index + 1}"
  vpc  = ibm_is_vpc.satellite[0].id
  zone = var.satellite_zones[count.index]
}

resource "ibm_is_subnet_public_gateway_attachment" "satellite" {
  count = var.cluster_mode == "satellite" ? length(var.satellite_zones) : 0

  subnet         = ibm_is_subnet.satellite[count.index].id
  public_gateway = ibm_is_public_gateway.satellite[count.index].id
}

resource "ibm_is_ssh_key" "satellite" {
  count = var.cluster_mode == "satellite" ? 1 : 0

  name           = "${var.cluster_name}-satellite-ssh"
  resource_group = data.ibm_resource_group.selected.id
  public_key     = var.satellite_ssh_public_key
}

resource "ibm_satellite_location" "satellite" {
  count = var.cluster_mode == "satellite" ? 1 : 0

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
        var.satellite_ssh_public_key != null,
        var.satellite_worker_operating_system != null,
        var.satellite_zones != null,
      ])
      error_message = "Satellite mode requires management location, three VPC zones, host image/profile, worker operating system, and an SSH public key."
    }
  }
}

data "ibm_is_image" "satellite_host" {
  count = var.cluster_mode == "satellite" ? 1 : 0

  name = var.satellite_host_image
}

data "ibm_satellite_attach_host_script" "satellite_control_plane" {
  count = var.cluster_mode == "satellite" ? 1 : 0

  location      = ibm_satellite_location.satellite[0].id
  labels        = ["satellite-role:control-plane"]
  host_provider = "ibm"
}

data "ibm_satellite_attach_host_script" "satellite_worker" {
  count = var.cluster_mode == "satellite" ? 1 : 0

  location      = ibm_satellite_location.satellite[0].id
  labels        = ["satellite-role:cluster-worker"]
  host_provider = "ibm"
}

resource "ibm_is_instance" "satellite_control_plane" {
  count = var.cluster_mode == "satellite" ? 3 : 0

  depends_on = [ibm_is_subnet_public_gateway_attachment.satellite]

  name           = "${var.cluster_name}-satellite-control-${count.index + 1}"
  vpc            = ibm_is_vpc.satellite[0].id
  zone           = var.satellite_zones[count.index]
  image          = data.ibm_is_image.satellite_host[0].id
  profile        = var.satellite_host_profile
  keys           = [ibm_is_ssh_key.satellite[0].id]
  resource_group = data.ibm_resource_group.selected.id
  user_data      = data.ibm_satellite_attach_host_script.satellite_control_plane[0].host_script

  primary_network_interface {
    subnet = ibm_is_subnet.satellite[count.index].id
  }
}

resource "ibm_satellite_host" "satellite_control_plane" {
  count = var.cluster_mode == "satellite" ? 3 : 0

  location      = ibm_satellite_location.satellite[0].id
  host_id       = ibm_is_instance.satellite_control_plane[count.index].name
  labels        = ["satellite-role:control-plane"]
  zone          = var.satellite_zones[count.index]
  host_provider = "ibm"
  wait_till     = "location_normal"
}

resource "ibm_is_instance" "satellite_worker" {
  count = var.cluster_mode == "satellite" ? var.worker_count : 0

  depends_on = [ibm_is_subnet_public_gateway_attachment.satellite]

  name           = "${var.cluster_name}-satellite-worker-${count.index + 1}"
  vpc            = ibm_is_vpc.satellite[0].id
  zone           = var.satellite_zones[count.index % length(var.satellite_zones)]
  image          = data.ibm_is_image.satellite_host[0].id
  profile        = var.satellite_host_profile
  keys           = [ibm_is_ssh_key.satellite[0].id]
  resource_group = data.ibm_resource_group.selected.id
  user_data      = data.ibm_satellite_attach_host_script.satellite_worker[0].host_script

  primary_network_interface {
    subnet = ibm_is_subnet.satellite[count.index % length(var.satellite_zones)].id
  }
}

resource "ibm_satellite_cluster" "satellite" {
  count = var.cluster_mode == "satellite" ? 1 : 0

  depends_on = [ibm_satellite_host.satellite_control_plane]

  name                    = var.cluster_name
  location                = ibm_satellite_location.satellite[0].id
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
}

resource "ibm_satellite_host" "satellite_worker" {
  count = var.cluster_mode == "satellite" ? var.worker_count : 0

  depends_on = [ibm_satellite_cluster.satellite]

  location      = ibm_satellite_location.satellite[0].id
  cluster       = ibm_satellite_cluster.satellite[0].id
  worker_pool   = "default"
  host_id       = ibm_is_instance.satellite_worker[count.index].name
  labels        = ["satellite-role:cluster-worker"]
  zone          = var.satellite_zones[count.index % length(var.satellite_zones)]
  host_provider = "ibm"
}
