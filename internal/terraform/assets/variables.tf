variable "cluster_name" {
  description = "Unique name for this short-lived cluster and its dedicated VPC resources."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{1,55}$", var.cluster_name))
    error_message = "cluster_name must contain only lowercase letters, digits, and hyphens."
  }
}

variable "resource_group_name" {
  description = "Existing IBM Cloud resource group name."
  type        = string
}

variable "region" {
  description = "Provider region. VPC derives this from its selected zone."
  type        = string

  validation {
    condition     = can(regex("^[a-z]+(-[a-z]+)+$", var.region))
    error_message = "region must look like us-south or us-south-ngdc-test."
  }
}

variable "cluster_mode" {
  description = "Infrastructure mode selected by the cluster workflow."
  type        = string

  validation {
    condition     = contains(["vpc", "classic", "satellite"], var.cluster_mode)
    error_message = "cluster_mode must be vpc, classic, or satellite."
  }
}

variable "platform" {
  description = "Kubernetes Service offering."
  type        = string

  validation {
    condition     = contains(["kubernetes", "openshift"], var.platform)
    error_message = "platform must be kubernetes or openshift."
  }
}

variable "kube_version" {
  description = "Provider-formatted major.minor version stream selected from the target Kubernetes Service environment."
  type        = string
}

variable "worker_count" {
  description = "Worker count, with a minimum of one for Kubernetes and two for OpenShift outside Satellite."
  type        = number

  validation {
    condition     = var.worker_count >= (var.platform == "openshift" && var.cluster_mode != "satellite" ? 2 : 1)
    error_message = "worker_count must be at least one for Kubernetes or at least two for OpenShift outside Satellite."
  }
}

variable "zone" {
  description = "VPC Gen 2 zone for the subnet and worker pool."
  type        = string
  default     = null

  validation {
    condition     = var.zone == null || can(regex("^[a-z]+(-[a-z]+)+-[0-9]+$", var.zone))
    error_message = "zone must look like us-south-1 or us-south-ngdc-test-1."
  }
}

variable "flavor" {
  description = "VPC Gen 2 worker flavor selected from the target and zone."
  type        = string
  default     = null
}

variable "vpc_id" {
  description = "Existing VPC Gen 2 ID. Terraform reads it and never manages it."
  type        = string
  default     = null

  validation {
    condition     = var.vpc_id == null || trimspace(var.vpc_id) != ""
    error_message = "vpc_id must not be blank."
  }
}

variable "subnet_ids" {
  description = "Existing VPC Gen 2 subnet IDs. VPC mode accepts one; Satellite mode accepts three unordered IDs."
  type        = list(string)
  default     = null

  validation {
    condition     = var.subnet_ids == null || (contains([1, 3], length(var.subnet_ids)) && length(distinct(var.subnet_ids)) == length(var.subnet_ids) && alltrue([for id in var.subnet_ids : trimspace(id) != ""]))
    error_message = "subnet_ids must contain one or three distinct, non-blank IDs."
  }
}

variable "public_gateway_ids" {
  description = "Existing VPC Gen 2 public gateway IDs. VPC mode accepts one; Satellite mode accepts three unordered IDs."
  type        = list(string)
  default     = null

  validation {
    condition     = var.public_gateway_ids == null || (contains([1, 3], length(var.public_gateway_ids)) && length(distinct(var.public_gateway_ids)) == length(var.public_gateway_ids) && alltrue([for id in var.public_gateway_ids : trimspace(id) != ""]))
    error_message = "public_gateway_ids must contain one or three distinct, non-blank IDs."
  }
}

variable "datacenter" {
  description = "Classic data center selected from the target."
  type        = string
  default     = null

  validation {
    condition     = var.datacenter == null || can(regex("^[a-z]+[0-9]+$", var.datacenter))
    error_message = "datacenter must look like dal10."
  }
}

variable "machine_type" {
  description = "Classic worker machine type selected from the target and data center."
  type        = string
  default     = null
}

variable "public_vlan_id" {
  description = "Existing Classic public VLAN ID. Terraform does not manage this VLAN."
  type        = string
  default     = null

  validation {
    condition     = var.public_vlan_id == null || can(regex("^[0-9]+$", var.public_vlan_id))
    error_message = "public_vlan_id must be a numeric Classic VLAN ID."
  }
}

variable "private_vlan_id" {
  description = "Existing Classic private VLAN ID. Terraform does not manage this VLAN."
  type        = string
  default     = null

  validation {
    condition     = var.private_vlan_id == null || can(regex("^[0-9]+$", var.private_vlan_id))
    error_message = "private_vlan_id must be a numeric Classic VLAN ID."
  }
}

variable "satellite_zones" {
  description = "Three distinct VPC zones for the Satellite location hosts."
  type        = list(string)
  default     = null

  validation {
    condition = var.satellite_zones == null || (
      length(var.satellite_zones) == 3 &&
      length(distinct(var.satellite_zones)) == 3 &&
      alltrue([for zone in var.satellite_zones : can(regex("^[a-z]+(-[a-z]+)+-[0-9]+$", zone))]) &&
      length(distinct([for zone in var.satellite_zones : replace(zone, "/-[0-9]+$/", "")])) == 1
    )
    error_message = "satellite_zones must contain three distinct VPC zones in one region."
  }
}

variable "satellite_managed_from" {
  description = "IBM Cloud multizone location that manages an ICT-created Satellite location."
  type        = string
  default     = null
}

variable "satellite_location_id" {
  description = "Existing Satellite location ID. Terraform reads it and never manages it."
  type        = string
  default     = null

  validation {
    condition     = var.satellite_location_id == null || trimspace(var.satellite_location_id) != ""
    error_message = "satellite_location_id must not be blank."
  }
}

variable "satellite_host_image" {
  description = "Available RHEL host image selected for Satellite VPC hosts."
  type        = string
  default     = null
}

variable "satellite_host_profile" {
  description = "VPC profile for Satellite hosts. The workflow defaults to bx2-4x16."
  type        = string
  default     = null
}

variable "satellite_ssh_public_key" {
  description = "Supplied SSH public key used only for disposable Satellite hosts when no existing key ID is supplied."
  type        = string
  default     = null
}

variable "satellite_ssh_key_id" {
  description = "Existing VPC SSH key ID. Terraform reads it and never manages it."
  type        = string
  default     = null

  validation {
    condition     = var.satellite_ssh_key_id == null || trimspace(var.satellite_ssh_key_id) != ""
    error_message = "satellite_ssh_key_id must not be blank."
  }
}

variable "satellite_worker_operating_system" {
  description = "Operating system for the Satellite OpenShift default worker pool."
  type        = string
  default     = null

  validation {
    condition     = var.satellite_worker_operating_system == null || contains(["RHCOS", "REDHAT_8_64"], var.satellite_worker_operating_system)
    error_message = "satellite_worker_operating_system must be RHCOS or REDHAT_8_64."
  }
}
