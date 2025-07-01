package sensorvisibilityexclusion_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSensorVisibilityExclusionResource_basic(t *testing.T) {
	groupID := os.Getenv("HOST_GROUP_ID")
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccSensorVisibilityExclusionConfig(rName, groupID, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "false"),
					resource.TestCheckResourceAttr(resourceName, "groups.0", groupID),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "regexp_value"),
					resource.TestCheckResourceAttrSet(resourceName, "applied_globally"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "created_on"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "last_modified"),
				),
			},
			// ImportState testing
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated", "comment"},
			},
			// Update and Read testing
			{
				Config: testAccSensorVisibilityExclusionConfig(rName+"-updated", groupID, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "comment", "Acceptance test exclusion updated"),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "true"),
					resource.TestCheckResourceAttr(resourceName, "groups.0", groupID),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_withDescendantProcess(t *testing.T) {
	groupID := os.Getenv("HOST_GROUP_ID")
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test-desc")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionConfig(rName, groupID, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "true"),
					resource.TestCheckResourceAttr(resourceName, "groups.0", groupID),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_withComment(t *testing.T) {
	groupID := os.Getenv("HOST_GROUP_ID")
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test-comment")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionConfigWithComment(rName, groupID, "Test comment for exclusion"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName),
					resource.TestCheckResourceAttr(resourceName, "comment", "Acceptance test exclusion"),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "false"),
					resource.TestCheckResourceAttr(resourceName, "groups.0", groupID),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_windowsPath(t *testing.T) {
	groupID := os.Getenv("HOST_GROUP_ID")
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"
	rName := "C:/Program Files/TestApp/test.exe"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionConfigWithComment(rName, groupID, "Windows path test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName),
					resource.TestCheckResourceAttr(resourceName, "groups.0", groupID),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_linuxPath(t *testing.T) {
	groupID := os.Getenv("HOST_GROUP_ID")
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"
	rName := "/opt/testapp/bin/testapp"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSensorVisibilityExclusionConfigWithComment(rName, groupID, "Linux path test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName),
					resource.TestCheckResourceAttr(resourceName, "groups.0", groupID),
				),
			},
		},
	})
}

func TestAccSensorVisibilityExclusionResource_multipleUpdates(t *testing.T) {
	groupID := os.Getenv("HOST_GROUP_ID")
	resourceName := "crowdstrike_sensor_visibility_exclusion.test"
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test-multi")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Initial creation
			{
				Config: testAccSensorVisibilityExclusionConfig(rName, groupID, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "false"),
				),
			},
			// First update - change value and descendant process
			{
				Config: testAccSensorVisibilityExclusionConfig(rName+"-update1", groupID, true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName+"-update1"),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "true"),
				),
			},
			// Second update - change back to false
			{
				Config: testAccSensorVisibilityExclusionConfig(rName+"-update2", groupID, false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "value", rName+"-update2"),
					resource.TestCheckResourceAttr(resourceName, "is_descendant_process", "false"),
				),
			},
		},
	})
}

func testAccSensorVisibilityExclusionConfig(value, groupID string, isDescendant bool) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value                 = "%s"
  comment               = "Acceptance test exclusion"
  is_descendant_process = %t
  groups                = ["%s"]
}
`, value, isDescendant, groupID)
}

func testAccSensorVisibilityExclusionConfigWithComment(value, groupID, comment string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value                 = "%s"
  comment               = "%s"
  is_descendant_process = false
  groups                = ["%s"]
}
`, value, comment, groupID)
}
