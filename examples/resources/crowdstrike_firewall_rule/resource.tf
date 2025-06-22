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

# Create a firewall rule
resource "crowdstrike_firewall_rule" "example" {
  name          = "Example Firewall Rule"
  description   = "Allow HTTP traffic on port 80"
  platform_name = "Windows"
  enabled       = true

  # Rule configuration
  action        = "allow"
  direction     = "in"
  protocol      = "tcp"
  address_family = "ip4"
  
  # Allow traffic from any address to any local address on port 80
  remote_address = "any"
  local_address  = "any"
  remote_port    = "any"
  local_port     = "80"
  
  # Enable logging for this rule
  log = true
  monitor = false
}

# Output the rule ID
output "firewall_rule_id" {
  value = crowdstrike_firewall_rule.example.id
}