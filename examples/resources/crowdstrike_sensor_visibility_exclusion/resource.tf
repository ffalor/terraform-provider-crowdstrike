resource "crowdstrike_sensor_visibility_exclusion" "example" {
  value                 = "C:\\Program Files\\TestApp\\test.exe"
  comment               = "Example exclusion for test application"
  is_descendant_process = false
  groups                = ["example-group-id"]
} 