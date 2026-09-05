mock_provider "ibm" {
  mock_data "ibm_resource_group" {
    defaults = {
      id = "resource-group-existing"
    }
  }

  mock_data "ibm_is_vpc" {
    defaults = {
      id = "vpc-existing"
    }
  }

  mock_data "ibm_is_subnet" {
    defaults = {
      id             = "subnet-existing"
      vpc            = "vpc-existing"
      zone           = "us-south-1"
      public_gateway = ""
    }
  }

  mock_data "ibm_is_public_gateways" {
    defaults = {
      public_gateways = [{
        id   = "gateway-existing"
        vpc  = "vpc-existing"
        zone = "us-south-1"
      }]
    }
  }
}

run "vpc_create_only_keeps_managed_addresses" {
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
    condition     = length(ibm_is_vpc.cluster) == 1 && length(ibm_is_subnet.cluster) == 1 && length(ibm_is_public_gateway.cluster) == 1 && length(ibm_is_subnet_public_gateway_attachment.cluster) == 1
    error_message = "Create-only VPC networking must retain its managed resource addresses."
  }
}

run "vpc_existing_vpc_creates_only_missing_networking" {
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
    vpc_id              = "vpc-existing"
  }

  assert {
    condition     = length(ibm_is_vpc.cluster) == 0 && length(ibm_is_subnet.cluster) == 1 && length(ibm_is_public_gateway.cluster) == 1 && length(ibm_is_subnet_public_gateway_attachment.cluster) == 1
    error_message = "A supplied VPC must create only the missing subnet, gateway, and attachment."
  }
}

run "vpc_complete_reuse_is_data_only" {
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
    vpc_id              = "vpc-existing"
    subnet_ids          = ["subnet-existing"]
    public_gateway_ids  = ["gateway-existing"]
  }

  assert {
    condition     = length(ibm_is_vpc.cluster) == 0 && length(ibm_is_subnet.cluster) == 0 && length(ibm_is_public_gateway.cluster) == 0 && length(ibm_is_subnet_public_gateway_attachment.cluster) == 1
    error_message = "Complete reuse must not manage VPC, subnet, or gateway, but must attach an unattached supplied subnet."
  }
}

run "vpc_existing_subnet_infers_vpc_and_creates_gateway" {
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
    subnet_ids          = ["subnet-existing"]
  }

  assert {
    condition     = length(ibm_is_vpc.cluster) == 0 && length(ibm_is_subnet.cluster) == 0 && length(ibm_is_public_gateway.cluster) == 1 && length(ibm_is_subnet_public_gateway_attachment.cluster) == 1
    error_message = "A supplied subnet must infer its VPC and receive a managed gateway attachment when unattached."
  }
}

run "vpc_existing_attachment_is_observed" {
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
    subnet_ids          = ["subnet-existing"]
  }

  override_data {
    target = data.ibm_is_subnet.cluster[0]
    values = {
      id             = "subnet-existing"
      vpc            = "vpc-existing"
      zone           = "us-south-1"
      public_gateway = "gateway-external"
    }
  }

  assert {
    condition     = length(ibm_is_vpc.cluster) == 0 && length(ibm_is_subnet.cluster) == 0 && length(ibm_is_public_gateway.cluster) == 0 && length(ibm_is_subnet_public_gateway_attachment.cluster) == 0
    error_message = "An existing subnet attachment must be observed and remain externally owned."
  }
}

run "vpc_missing_gateway_id_fails_plan" {
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
    public_gateway_ids  = ["gateway-missing"]
  }

  expect_failures = [ibm_container_vpc_cluster.cluster]
}

run "vpc_incompatible_gateway_metadata_fails_plan" {
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
    vpc_id              = "vpc-existing"
    public_gateway_ids  = ["gateway-existing"]
  }

  override_data {
    target = data.ibm_is_public_gateways.cluster[0]
    values = {
      public_gateways = [{
        id   = "gateway-existing"
        vpc  = "vpc-other"
        zone = "us-south-2"
      }]
    }
  }

  expect_failures = [ibm_container_vpc_cluster.cluster]
}

run "vpc_conflicting_existing_attachment_fails_plan" {
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
    subnet_ids          = ["subnet-existing"]
    public_gateway_ids  = ["gateway-existing"]
  }

  override_data {
    target = data.ibm_is_subnet.cluster[0]
    values = {
      id             = "subnet-existing"
      vpc            = "vpc-existing"
      zone           = "us-south-1"
      public_gateway = "gateway-other"
    }
  }

  expect_failures = [ibm_container_vpc_cluster.cluster]
}

run "vpc_existing_gateway_infers_vpc_and_creates_subnet" {
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
    public_gateway_ids  = ["gateway-existing"]
  }

  assert {
    condition     = length(ibm_is_vpc.cluster) == 0 && length(ibm_is_subnet.cluster) == 1 && length(ibm_is_public_gateway.cluster) == 0 && length(ibm_is_subnet_public_gateway_attachment.cluster) == 1
    error_message = "A supplied gateway must infer its VPC and receive a managed subnet attachment."
  }
}
