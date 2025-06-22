package firewall_test

import (
	"fmt"
	"os"
	"testing"

	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
)

// PreCheck for firewall tests
func testAccFirewallPreCheck(t *testing.T) {
	if v := os.Getenv("FALCON_CLIENT_ID"); v == "" {
		t.Fatal("FALCON_CLIENT_ID must be set for acceptance tests")
	}
	if v := os.Getenv("FALCON_CLIENT_SECRET"); v == "" {
		t.Fatal("FALCON_CLIENT_SECRET must be set for acceptance tests")
	}
}

func TestAccFirewallPolicyResource_basic(t *testing.T) {
	name1 := fmt.Sprintf("tf-acc-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))
	name2 := fmt.Sprintf("tf-acc-%s", sdkacctest.RandStringFromCharSet(10, sdkacctest.CharSetAlpha))

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccFirewallPreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccFirewallPolicyConfig(name1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_firewall_policy.test", "name", name1),
					resource.TestCheckResourceAttr("crowdstrike_firewall_policy.test", "platform_name", "Windows"),
				),
			},
			{
				ResourceName:            "crowdstrike_firewall_policy.test",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},
			{
				Config: testAccFirewallPolicyConfig(name2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("crowdstrike_firewall_policy.test", "name", name2),
				),
			},
		},
	})
}

func testAccFirewallPolicyConfig(name string) string {
	return fmt.Sprintf(`
provider "crowdstrike" {}

resource "crowdstrike_firewall_policy" "test" {
  name          = "%s"
  description   = "Terraform acceptance test firewall policy"
  platform_name = "Windows"
  enabled       = false
  host_groups   = []
}
`, name)
}
