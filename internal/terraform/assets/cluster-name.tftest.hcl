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
    condition     = ibm_container_vpc_cluster.cluster[0].name == "synthetic-vpc-name-0000000000001" && length(ibm_container_vpc_cluster.cluster[0].name) == 32
    error_message = "VPC cluster names must fit the 32-character API limit."
  }
}
