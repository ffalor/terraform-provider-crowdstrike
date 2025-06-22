package devicecontrolpolicy_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestAccDeviceControlPolicyResource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_device_control_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDeviceControlPolicyConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckDeviceControlPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test device control policy created by Terraform"),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "end_user_notification", "SILENT"),
					resource.TestCheckResourceAttr(resourceName, "enforcement_mode", "MONITOR_ONLY"),
					resource.TestCheckResourceAttr(resourceName, "enhanced_file_metadata", "false"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "created_by"),
					resource.TestCheckResourceAttrSet(resourceName, "created_timestamp"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_by"),
					resource.TestCheckResourceAttrSet(resourceName, "modified_timestamp"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			},
		},
	})
}

func TestAccDeviceControlPolicyResource_withClasses(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_device_control_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDeviceControlPolicyConfig_withClasses(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckDeviceControlPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "platform_name", "Windows"),
					resource.TestCheckResourceAttr(resourceName, "enforcement_mode", "MONITOR_ENFORCE"),
					resource.TestCheckResourceAttr(resourceName, "end_user_notification", "NOTIFY_USER"),
					resource.TestCheckResourceAttr(resourceName, "enhanced_file_metadata", "true"),
					resource.TestCheckResourceAttr(resourceName, "classes.#", "2"),
				),
			},
		},
	})
}

func TestAccDeviceControlPolicyResource_update(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acceptance-test")
	resourceName := "crowdstrike_device_control_policy.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDeviceControlPolicyConfig_basic(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckDeviceControlPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "end_user_notification", "SILENT"),
					resource.TestCheckResourceAttr(resourceName, "enforcement_mode", "MONITOR_ONLY"),
				),
			},
			{
				Config: testAccDeviceControlPolicyConfig_updated(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckDeviceControlPolicyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName+"-updated"),
					resource.TestCheckResourceAttr(resourceName, "description", "Updated device control policy description"),
					resource.TestCheckResourceAttr(resourceName, "end_user_notification", "NOTIFY_USER"),
					resource.TestCheckResourceAttr(resourceName, "enforcement_mode", "MONITOR_ENFORCE"),
					resource.TestCheckResourceAttr(resourceName, "enhanced_file_metadata", "true"),
				),
			},
		},
	})
}

func testAccCheckDeviceControlPolicyExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Device Control Policy ID is set")
		}

		return nil
	}
}

func testAccDeviceControlPolicyConfig_basic(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name         = "%s"
  description  = "Test device control policy created by Terraform"
  platform_name = "Windows"
  
  end_user_notification = "SILENT"
  enforcement_mode = "MONITOR_ONLY"
  enhanced_file_metadata = false
}
`, rName)
}

func testAccDeviceControlPolicyConfig_withClasses(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name         = "%s"
  description  = "Test device control policy with USB classes"
  platform_name = "Windows"
  
  end_user_notification = "NOTIFY_USER"
  enforcement_mode = "MONITOR_ENFORCE"
  enhanced_file_metadata = true
  
  classes = [
    {
      id     = "MASS_STORAGE"
      action = "BLOCK_EXECUTE"
      exceptions = [
        {
          action = "FULL_ACCESS"
          vendor_name = "SanDisk"
          product_name = "Cruzer"
        }
      ]
    },
    {
      id     = "HID"
      action = "FULL_ACCESS"
    }
  ]
}
`, rName)
}

func testAccDeviceControlPolicyConfig_updated(rName string) string {
	return acctest.ProviderConfig + fmt.Sprintf(`
resource "crowdstrike_device_control_policy" "test" {
  name         = "%s-updated"
  description  = "Updated device control policy description"
  platform_name = "Windows"
  
  end_user_notification = "NOTIFY_USER"
  enforcement_mode = "MONITOR_ENFORCE"
  enhanced_file_metadata = true
}
`, rName)
}
