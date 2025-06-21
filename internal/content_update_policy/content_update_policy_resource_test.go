package contentupdatepolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccContentUpdatePolicy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccContentUpdatePolicyConfig("Terraform Acceptance Test", "Terraform Acceptance Test", true, "ga"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", "Terraform Acceptance Test"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "description", "Terraform Acceptance Test"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", "true"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "system_critical.deployment_ring", "ga"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "sensor_operations.deployment_ring", "ga"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "rapid_response.deployment_ring", "ga"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "vulnerability_management.deployment_ring", "ga"),
				),
			},
			// Update and Read testing
			{
				Config: testAccContentUpdatePolicyConfig("Terraform Acceptance Test Updated", "Terraform Acceptance Test Updated", false, "ea"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", "Terraform Acceptance Test Updated"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "description", "Terraform Acceptance Test Updated"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", "false"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "system_critical.deployment_ring", "ea"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "sensor_operations.deployment_ring", "ga"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "rapid_response.deployment_ring", "ga"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "vulnerability_management.deployment_ring", "ga"),
				),
			},
			// Test delay_hours
			{
				Config: testAccContentUpdatePolicyConfigWithDelay("Terraform Acceptance Test Delayed", "Terraform Acceptance Test Delayed", true, 12),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", "Terraform Acceptance Test Delayed"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "description", "Terraform Acceptance Test Delayed"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", "true"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "system_critical.deployment_ring", "ga"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "system_critical.delay_hours", "12"),
				),
			},
			// Test updating description to empty string
			{
				Config: testAccContentUpdatePolicyConfig("Terraform Acceptance Test Delayed", "", true, "ga"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", "Terraform Acceptance Test Delayed"),
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "description", ""),
				),
			},
			// Test removing description
			{
				Config: testAccContentUpdatePolicyConfigNoDescription("Terraform Acceptance Test Delayed", true, "ga"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", "Terraform Acceptance Test Delayed"),
					testAccCheckDescriptionIsNull("crowdstrike_content_update_policy.test"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "crowdstrike_content_update_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccContentUpdatePolicyConfig(name, description string, enabled bool, systemCriticalRing string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = "%s"
  description = "%s"
  enabled     = %t
  system_critical = {
    deployment_ring = "%s"
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
`, name, description, enabled, systemCriticalRing)
}

func testAccCheckDescriptionIsNull(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Primary.Attributes["description"] != "" {
			return fmt.Errorf("description not null, got: %s", rs.Primary.Attributes["description"])
		}
		return nil
	}
}

func testAccContentUpdatePolicyConfigNoDescription(name string, enabled bool, systemCriticalRing string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = "%s"
  enabled     = %t
  system_critical = {
    deployment_ring = "%s"
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
`, name, enabled, systemCriticalRing)
}

func testAccContentUpdatePolicyConfigWithDelay(name, description string, enabled bool, delayHours int) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = "%s"
  description = "%s"
  enabled     = %t
  system_critical = {
    deployment_ring = "ga"
    delay_hours     = %d
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
`, name, description, enabled, delayHours)
}
