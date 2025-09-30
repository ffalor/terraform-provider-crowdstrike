package cloud_security_group_test

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
)

func TestAccCloudSecurityGroupResource_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	resourceName := "crowdstrike_cloud_security_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
		},
	})
}

func TestAccCloudSecurityGroupResource_complete(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix("tf-acc-test")
	rNameUpdated := sdkacctest.RandomWithPrefix("tf-acc-test-updated")
	resourceName := "crowdstrike_cloud_security_group.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSecurityGroupConfig_complete(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "description", "Test cloud security group"),
					resource.TestCheckResourceAttr(resourceName, "business_impact", "high"),
					resource.TestCheckResourceAttr(resourceName, "business_unit", "engineering"),
					resource.TestCheckResourceAttr(resourceName, "environment", "prod"),
					resource.TestCheckResourceAttr(resourceName, "owners.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "owners.0", "test@example.com"),
					resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
				),
			},
			{
				Config: testAccCloudSecurityGroupConfig_complete(rNameUpdated),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", rNameUpdated),
				),
			},
		},
	})
}

func testAccCloudSecurityGroupConfig_basic(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_group" "test" {
  name = %[1]q
}
`, name)
}

func testAccCloudSecurityGroupConfig_complete(name string) string {
	return fmt.Sprintf(`
resource "crowdstrike_cloud_security_group" "test" {
  name            = %[1]q
  description     = "Test cloud security group"
  business_impact = "high"
  business_unit   = "engineering"
  environment     = "prod"
  owners          = ["test@example.com"]

  cloud_resources = [{
    cloud_provider = "aws"
    account_ids    = ["123456789012"]
    
    filters = {
      regions = ["us-east-1"]
      tags    = {
        environment = "test"
      }
    }
  }]

  images = [{
    registry = "registry-1.docker.io"
    
    filters = {
      repositories = ["test/app"]
      tags         = ["latest"]
    }
  }]
}
`, name)
}
