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

# Create a sensor visibility exclusion for a specific file path
resource "crowdstrike_sensor_visibility_exclusion" "example_file" {
  value   = "C:\\Program Files\\MyApp\\*.exe"
  comment = "Exclude MyApp executables from sensor monitoring"
  groups  = ["all"]
}

# Create a sensor visibility exclusion for a specific host group
resource "crowdstrike_sensor_visibility_exclusion" "example_group" {
  value   = "/opt/myapp/*"
  comment = "Exclude myapp directory for specific host group"
  groups  = ["group-id-123"]
}

# Create a sensor visibility exclusion without specifying groups (will be applied globally)
resource "crowdstrike_sensor_visibility_exclusion" "example_global" {
  value   = "*.log"
  comment = "Exclude all log files from sensor monitoring"
}

output "sensor_visibility_exclusions" {
  value = {
    file_exclusion   = crowdstrike_sensor_visibility_exclusion.example_file
    group_exclusion  = crowdstrike_sensor_visibility_exclusion.example_group
    global_exclusion = crowdstrike_sensor_visibility_exclusion.example_global
  }
}
