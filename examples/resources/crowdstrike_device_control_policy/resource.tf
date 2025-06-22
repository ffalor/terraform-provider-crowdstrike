resource "crowdstrike_device_control_policy" "example" {
  name         = "Example Device Control Policy"
  description  = "Example device control policy managed by Terraform"
  platform_name = "Windows"
  
  # Notification and enforcement settings
  end_user_notification = "NOTIFY_USER"
  enforcement_mode = "MONITOR_ENFORCE"
  enhanced_file_metadata = true
  
  # USB device class settings
  classes = [
    {
      # Mass Storage devices
      id     = "08"
      action = "BLOCK_EXECUTE"
      exceptions = [
        {
          action = "FULL_ACCESS"
          vendor_name = "SanDisk"
          product_name = "Cruzer Blade"
          description = "Allow SanDisk Cruzer Blade devices"
        },
        {
          action = "READ_ONLY"
          vendor_id = "0781"
          product_id = "5567"
          description = "Allow specific SanDisk device in read-only mode"
        }
      ]
    },
    {
      # Human Interface Devices (keyboards, mice)
      id     = "03"
      action = "FULL_ACCESS"
    },
    {
      # Audio devices
      id     = "01"
      action = "FULL_ACCESS"
    }
  ]
  
  # Optional: Attach to specific host groups
  # host_groups = ["host-group-id-1", "host-group-id-2"]
}