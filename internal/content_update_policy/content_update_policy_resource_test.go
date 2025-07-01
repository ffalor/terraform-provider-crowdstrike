package contentupdatepolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccContentUpdatePolicyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccContentUpdatePolicyResourceConfig("test-policy"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"name",
						"test-policy",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"description",
						"Test content update policy",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"enabled",
						"true",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.delay_hours",
						"0",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.delay_hours",
						"24",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"vulnerability_management.ring_assignment",
						"ea",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"rapid_response.ring_assignment",
						"pause",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_content_update_policy.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_content_update_policy.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:      "crowdstrike_content_update_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
			// Update and Read testing
			{
				Config: testAccContentUpdatePolicyResourceConfigUpdate("test-policy-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"name",
						"test-policy-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"description",
						"Updated test content update policy",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"enabled",
						"false",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.ring_assignment",
						"ea",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.delay_hours",
						"48",
					),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccContentUpdatePolicyResourceWithHostGroups(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccContentUpdatePolicyResourceConfigWithHostGroups("test-policy-hg"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"name",
						"test-policy-hg",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"host_groups.#",
						"1",
					),
					resource.TestCheckTypeSetElemAttrPair(
						"crowdstrike_content_update_policy.test",
						"host_groups.*",
						"crowdstrike_host_group.test",
						"id",
					),
				),
			},
			// Update host groups
			{
				Config: testAccContentUpdatePolicyResourceConfigWithHostGroupsUpdate("test-policy-hg-updated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"name",
						"test-policy-hg-updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"host_groups.#",
						"2",
					),
				),
			},
		},
	})
}

func TestAccContentUpdatePolicyResourceVariousRingConfigurations(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test all GA with various delays
			{
				Config: testAccContentUpdatePolicyResourceConfigAllGA("test-policy-all-ga"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.delay_hours",
						"0",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.delay_hours",
						"24",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"vulnerability_management.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"vulnerability_management.delay_hours",
						"48",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"rapid_response.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"rapid_response.delay_hours",
						"72",
					),
				),
			},
			// Test all EA
			{
				Config: testAccContentUpdatePolicyResourceConfigAllEA("test-policy-all-ea"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.ring_assignment",
						"ea",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.ring_assignment",
						"ea",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"vulnerability_management.ring_assignment",
						"ea",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"rapid_response.ring_assignment",
						"ea",
					),
				),
			},
			// Test mixed configuration
			{
				Config: testAccContentUpdatePolicyResourceConfigMixed("test-policy-mixed"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"sensor_operations.delay_hours",
						"12",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"system_critical.ring_assignment",
						"ea",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"vulnerability_management.ring_assignment",
						"pause",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"rapid_response.ring_assignment",
						"ga",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_content_update_policy.test",
						"rapid_response.delay_hours",
						"2",
					),
				),
			},
		},
	})
}

func TestAccContentUpdatePolicyResourceValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Test invalid delay_hours with non-GA ring
			{
				Config:      testAccContentUpdatePolicyResourceConfigInvalidDelay("test-policy-invalid"),
				ExpectError: regexp.MustCompile("delay_hours can only be set when ring_assignment is 'ga'"),
			},
		},
	})
}

func testAccContentUpdatePolicyResourceConfig(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment = "ea"
  }

  rapid_response = {
    ring_assignment = "pause"
  }
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigUpdate(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Updated test content update policy"
  enabled     = false

  sensor_operations = {
    ring_assignment = "ea"
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 48
  }

  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 12
  }

  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 0
  }
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigWithHostGroups(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "test-host-group"
  description = "Test host group for content update policy"
  type        = "static"
  hostnames   = ["test-host1", "test-host2"]
}

resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy with host groups"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment = "ea"
  }

  rapid_response = {
    ring_assignment = "pause"
  }

  host_groups = [
    crowdstrike_host_group.test.id
  ]
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigWithHostGroupsUpdate(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_host_group" "test" {
  name        = "test-host-group"
  description = "Test host group for content update policy"
  type        = "static"
  hostnames   = ["test-host1", "test-host2"]
}

resource "crowdstrike_host_group" "test2" {
  name        = "test-host-group-2"
  description = "Second test host group for content update policy"
  type        = "static"
  hostnames   = ["test-host3", "test-host4"]
}

resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy with host groups"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment = "ea"
  }

  rapid_response = {
    ring_assignment = "pause"
  }

  host_groups = [
    crowdstrike_host_group.test.id,
    crowdstrike_host_group.test2.id
  ]
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigWithHostGroupsRemove(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy without host groups"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment = "ea"
  }

  rapid_response = {
    ring_assignment = "pause"
  }
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigAllGA(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy with all GA rings"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ga"
    delay_hours     = 24
  }

  vulnerability_management = {
    ring_assignment = "ga"
    delay_hours     = 48
  }

  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 72
  }
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigAllEA(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy with all EA rings"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ea"
  }

  system_critical = {
    ring_assignment = "ea"
  }

  vulnerability_management = {
    ring_assignment = "ea"
  }

  rapid_response = {
    ring_assignment = "ea"
  }
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigMixed(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy with mixed ring assignments"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 12
  }

  system_critical = {
    ring_assignment = "ea"
  }

  vulnerability_management = {
    ring_assignment = "pause"
  }

  rapid_response = {
    ring_assignment = "ga"
    delay_hours     = 2
  }
}
`, name)
}

func testAccContentUpdatePolicyResourceConfigInvalidDelay(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_content_update_policy" "test" {
  name        = %[1]q
  description = "Test content update policy with invalid delay configuration"
  enabled     = true

  sensor_operations = {
    ring_assignment = "ga"
    delay_hours     = 0
  }

  system_critical = {
    ring_assignment = "ea"
    delay_hours     = 24  # This should cause a validation error
  }

  vulnerability_management = {
    ring_assignment = "ea"
  }

  rapid_response = {
    ring_assignment = "pause"
  }
}
`, name)
}
