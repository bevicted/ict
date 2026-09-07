mock_provider "ibm" {}

run "vpc_cluster_name_is_within_api_limit" {
  command = plan

  variables {
    cluster_name        = "synthetic-vpc-name-0000000000001"
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
    condition     = ibm_container_vpc_cluster.cluster[0].name == "synthetic-vpc-name-0000000000001" && length(ibm_container_vpc_cluster.cluster[0].name) == 32 && ibm_is_vpc.cluster[0].name == "synthetic-vpc-name-0000000000001-vpc" && ibm_is_subnet.cluster[0].name == "synthetic-vpc-name-0000000000001-subnet" && ibm_is_public_gateway.cluster[0].name == "synthetic-vpc-name-0000000000001-gateway"
    error_message = "VPC cluster names must fit the 32-character API limit and generated resources must inherit the cluster name."
  }
}
