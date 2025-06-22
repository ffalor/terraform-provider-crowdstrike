terraform {
  required_providers {
    crowdstrike = {
      source = "crowdstrike/crowdstrike"
    }
  }
}

# Configure the CrowdStrike Provider
provider "crowdstrike" {
  # Configuration options
}

# Create a firewall policy
resource "crowdstrike_firewall_policy" "example" {
  name          = "Example Firewall Policy"
  description   = "An example firewall policy for Windows hosts"
  platform_name = "Windows"
  enabled       = true

  # Optionally assign to host groups
  host_groups = [
    "example-host-group-id-1",
    "example-host-group-id-2"
  ]
}

# Output the policy ID
output "firewall_policy_id" {
  value = crowdstrike_firewall_policy.example.id
}