package contentupdatepolicy_test

import (
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

const defaultResourceName = "crowdstrike_default_content_update_policy.default"

func TestAccDefaultContentUpdatePolicyResourceWindows(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.4.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_content_update_policy" "default" {
  platform_name = "Windows"
  enabled       = true
  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(defaultResourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(defaultResourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(defaultResourceName, "sensor_operations.ring_assignment", "ga"),
					resource.TestCheckResourceAttr(defaultResourceName, "sensor_operations.delay_hours", "0"),
					resource.TestCheckResourceAttr(defaultResourceName, "system_critical.ring_assignment", "ga"),
					resource.TestCheckResourceAttr(defaultResourceName, "system_critical.delay_hours", "0"),
					resource.TestCheckResourceAttr(defaultResourceName, "vulnerability_management.ring_assignment", "ga"),
					resource.TestCheckResourceAttr(defaultResourceName, "vulnerability_management.delay_hours", "0"),
					resource.TestCheckResourceAttr(defaultResourceName, "rapid_response.ring_assignment", "ga"),
					resource.TestCheckResourceAttr(defaultResourceName, "rapid_response.delay_hours", "0"),
					resource.TestCheckResourceAttrSet(defaultResourceName, "id"),
					resource.TestCheckResourceAttrSet(defaultResourceName, "last_updated"),
				),
			},
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_content_update_policy" "default" {
  platform_name = "Windows"
  enabled       = true
  sensor_operations = {
    ring_assignment = "ea"
  }
  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 12
  }
  vulnerability_management = {
    ring_assignment = "pause"
  }
  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 24
  }
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(defaultResourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(defaultResourceName, "enabled", "true"),
					resource.TestCheckResourceAttr(defaultResourceName, "sensor_operations.ring_assignment", "ea"),
					resource.TestCheckResourceAttr(defaultResourceName, "system_critical.ring_assignment", "ga"),
					resource.TestCheckResourceAttr(defaultResourceName, "system_critical.delay_hours", "12"),
					resource.TestCheckResourceAttr(defaultResourceName, "vulnerability_management.ring_assignment", "pause"),
					resource.TestCheckResourceAttr(defaultResourceName, "rapid_response.ring_assignment", "ga"),
					resource.TestCheckResourceAttr(defaultResourceName, "rapid_response.delay_hours", "24"),
				),
			},
		},
	})
}

func TestAccDefaultContentUpdatePolicyResourceLinux(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.4.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_content_update_policy" "default" {
  platform_name = "Linux"
  enabled       = true
  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(defaultResourceName, "platform_name", "Linux"),
					resource.TestCheckResourceAttr(defaultResourceName, "enabled", "true"),
					resource.TestCheckResourceAttrSet(defaultResourceName, "id"),
					resource.TestCheckResourceAttrSet(defaultResourceName, "last_updated"),
				),
			},
		},
	})
}

func TestAccDefaultContentUpdatePolicyResourceMac(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.4.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_content_update_policy" "default" {
  platform_name = "Mac"
  enabled       = true
  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(defaultResourceName, "platform_name", "Mac"),
					resource.TestCheckResourceAttr(defaultResourceName, "enabled", "true"),
					resource.TestCheckResourceAttrSet(defaultResourceName, "id"),
					resource.TestCheckResourceAttrSet(defaultResourceName, "last_updated"),
				),
			},
		},
	})
}

func TestAccDefaultContentUpdatePolicyResourceValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(version.Must(version.NewVersion("1.4.0"))),
		},
		Steps: []resource.TestStep{
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_content_update_policy" "default" {
  platform_name = "Windows"
  enabled       = true
  sensor_operations = {
    ring_assignment = "ea"
    delay_hours     = 12  # This should cause an error because delay_hours can only be set for 'ga'
  }
  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}`,
				ExpectError: regexp.MustCompile("(?i)delay_hours can only be set when ring_assignment is 'ga'"),
			},
			{
				Config: acctest.ProviderConfig + `
resource "crowdstrike_default_content_update_policy" "default" {
  platform_name = "Windows"
  enabled       = true
  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  system_critical = {
    ring_assignment = "pause"  # This should cause an error because 'pause' is not allowed for system_critical
    delay_hours     = 0
  }
  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}`,
				ExpectError: regexp.MustCompile("(?i)system_critical.*pause.*not allowed"),
			},
		},
	})
}