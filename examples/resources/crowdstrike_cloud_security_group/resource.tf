terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}

resource "crowdstrike_cloud_security_group" "example" {
  name        = "production-workloads"
  description = "Production workloads security group"

  business_impact = "high"
  business_unit   = "engineering"
  environment     = "prod"

  owners = [
    "admin@example.com",
    "security@example.com"
  ]

  cloud_resources = [
    {
      cloud_provider = "aws"
      account_ids    = ["123456789012", "123456789013"]

      filters = {
        regions = ["us-east-1", "us-west-2"]
        tags = {
          environment = "production"
          team        = "engineering"
        }
      }
    },
    {
      cloud_provider = "azure"
      account_ids    = ["subscription-id-1", "subscription-id-2"]

      filters = {
        regions = ["eastus", "westus2"]
        tags = {
          environment = "production"
        }
      }
    }
  ]

  images = [
    {
      registry = "registry-1.docker.io"

      filters = {
        repositories = ["mycompany/webapp", "mycompany/api"]
        tags         = ["latest", "v1.*"]
      }
    },
    {
      registry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"

      filters = {
        repositories = ["internal/service"]
        tags         = ["production"]
      }
    }
  ]
}

# Minimal cloud security group
resource "crowdstrike_cloud_security_group" "minimal" {
  name = "dev-testing"
}
