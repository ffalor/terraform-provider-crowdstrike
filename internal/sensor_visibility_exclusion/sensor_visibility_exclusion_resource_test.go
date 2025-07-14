package sensorvisibilityexclusion_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorVisibilityExclusionResource(t *testing.T) {
	rValue := sdkacctest.RandomWithPrefix("tf-test-") + "*.exe"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = "%s"
  comment = "made with terraform"
  groups  = ["all"]
}
`, rValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"comment",
						"made with terraform",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"groups.#",
						"1",
					),
					resource.TestCheckTypeSetElemAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"groups.*",
						"all",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"last_updated",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"regexp_value",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value_hash",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"applied_globally",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"created_on",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"created_by",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_sensor_visibility_exclusion.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			// Update and Read testing
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = "%s"
  comment = "made with terraform updated"
  groups  = ["all"]
}
`, rValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"comment",
						"made with terraform updated",
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"groups.#",
						"1",
					),
					resource.TestCheckTypeSetElemAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"groups.*",
						"all",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"last_updated",
					),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_WithoutGroups(t *testing.T) {
	rValue := sdkacctest.RandomWithPrefix("tf-test-") + "*.log"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing without groups
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = "%s"
  comment = "made with terraform no groups"
}
`, rValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"comment",
						"made with terraform no groups",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"last_updated",
					),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_WithoutComment(t *testing.T) {
	rValue := sdkacctest.RandomWithPrefix("tf-test-") + "*.tmp"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing without comment
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value  = "%s"
  groups = ["all"]
}
`, rValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"groups.#",
						"1",
					),
					resource.TestCheckTypeSetElemAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"groups.*",
						"all",
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"last_updated",
					),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_MinimalConfig(t *testing.T) {
	rValue := sdkacctest.RandomWithPrefix("tf-test-") + "*.bak"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing with minimal configuration (only value)
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value = "%s"
}
`, rValue),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue,
					),
					// Verify dynamic values have any value set in the state.
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"id",
					),
					resource.TestCheckResourceAttrSet(
						"crowdstrike_sensor_visibility_exclusion.test",
						"last_updated",
					),
				),
			},
			// ImportState testing
			{
				ResourceName:            "crowdstrike_sensor_visibility_exclusion.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_UpdateValue(t *testing.T) {
	rValue1 := sdkacctest.RandomWithPrefix("tf-test-") + "*.old"
	rValue2 := sdkacctest.RandomWithPrefix("tf-test-") + "*.new"
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps: []resource.TestStep{
			// Create with initial value
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = "%s"
  comment = "initial value"
  groups  = ["all"]
}
`, rValue1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue1,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"comment",
						"initial value",
					),
				),
			},
			// Update the value
			{
				Config: acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = "%s"
  comment = "updated value"
  groups  = ["all"]
}
`, rValue2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"value",
						rValue2,
					),
					resource.TestCheckResourceAttr(
						"crowdstrike_sensor_visibility_exclusion.test",
						"comment",
						"updated value",
					),
				),
			},
		},
	})
}
