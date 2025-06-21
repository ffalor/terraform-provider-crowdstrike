terraform {
  required_providers {
    crowdstrike = {
      source = "crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  // us-1, us-2, eu-1, us-gov-1
  // cloud = "us-1"
}

resource "crowdstrike_content_update_policy" "example" {
  name        = "Example Content Update Policy"
  description = "An example content update policy managed by Terraform"
  enabled     = true

  system_critical = {
    deployment_ring = "ga"
    delay_hours     = "4"
  }

  sensor_operations = {
    deployment_ring = "ga"
  }

  rapid_response = {
    deployment_ring = "ga"
  }

  vulnerability_management = {
    deployment_ring = "ga"
  }
}