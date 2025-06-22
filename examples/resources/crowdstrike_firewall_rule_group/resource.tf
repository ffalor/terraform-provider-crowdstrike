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

# Create a firewall rule group
resource "crowdstrike_firewall_rule_group" "example" {
  name          = "Example Firewall Rule Group"
  description   = "An example firewall rule group for Windows hosts"
  platform_name = "Windows"
  enabled       = true

  # Optionally specify rule IDs
  rules = [
    "example-rule-id-1",
    "example-rule-id-2"
  ]
}

# Output the rule group ID
output "firewall_rule_group_id" {
  value = crowdstrike_firewall_rule_group.example.id
}