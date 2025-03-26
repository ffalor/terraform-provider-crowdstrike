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


resource "crowdstrike_default_prevention_policy_windows" "example" {}

output "default_prevention_policy_windows" {
  value = crowdstrike_default_prevention_policy_windows.example
}
