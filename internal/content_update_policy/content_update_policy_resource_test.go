package contentupdatepolicy_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// ringConfig represents a ring assignment configuration.
type ringConfig struct {
	RingAssignment       string
	DelayHours           *int
	PinnedContentVersion *string
}

// policyConfig represents a complete policy configuration.
type policyConfig struct {
	Name                    string
	Description             string
	Enabled                 *bool
	SensorOperations        ringConfig
	SystemCritical          ringConfig
	VulnerabilityManagement ringConfig
	RapidResponse           ringConfig
	HostGroupCount          int
}

// String implements the Stringer interface and generates Terraform configuration from policyConfig.
func (config *policyConfig) String() string {
	var hostGroupResources string
	var hostGroupsBlock string

	randomSuffix := sdkacctest.RandString(8)
	config.Name = fmt.Sprintf("%s-%s", config.Name, randomSuffix)

	if config.HostGroupCount > 0 {
		var hostGroupRefs []string
		for i := 0; i < config.HostGroupCount; i++ {
			hostGroupName := fmt.Sprintf("hg-%s-%d", randomSuffix, i)

			hostGroupResources += fmt.Sprintf(`
resource "crowdstrike_host_group" "hg_%d" {
  name        = "%s"
  description = "Test host group %d for content update policy"
  type        = "static"
  hostnames   = ["test-host%d-1", "test-host%d-2"]
}
`, i, hostGroupName, i, i, i)
			hostGroupRefs = append(hostGroupRefs, fmt.Sprintf("crowdstrike_host_group.hg_%d.id", i))
		}

		hostGroupsBlock = fmt.Sprintf(`
  host_groups = [%s]`, strings.Join(hostGroupRefs, ", "))
	}

	// Include data source for content update versions when pinned versions are used
	dataSourceBlock := ""
	if config.needsDataSource() {
		dataSourceBlock = `
data "crowdstrike_content_update_versions" "available" {}
`
	}

	return fmt.Sprintf(`%s%s
resource "crowdstrike_content_update_policy" "test" {
  name        = %q
  description = %q
  %s

  sensor_operations = {
    ring_assignment = %q
	%s
  }

  system_critical = {
    ring_assignment = %q
	%s
  }

  vulnerability_management = {
    ring_assignment = %q
	%s
  }

  rapid_response = {
    ring_assignment = %q
	%s
  }
  
  %s
}
`, dataSourceBlock, hostGroupResources, config.Name, config.Description, config.formatEnabled(),
		config.SensorOperations.RingAssignment, config.SensorOperations.formatDelayHours(),
		config.SystemCritical.RingAssignment, config.SystemCritical.formatDelayHours(),
		config.VulnerabilityManagement.RingAssignment, config.VulnerabilityManagement.formatDelayHours(),
		config.RapidResponse.RingAssignment, config.RapidResponse.formatDelayHours(),
		hostGroupsBlock)
}

func (config policyConfig) formatEnabled() string {
	if config.Enabled == nil {
		return ""
	}

	return fmt.Sprintf("enabled = %t", *config.Enabled)
}

func (config ringConfig) formatDelayHours() string {
	var parts []string

	if config.DelayHours != nil {
		parts = append(parts, fmt.Sprintf("delay_hours     = %d", *config.DelayHours))
	}

	if config.PinnedContentVersion != nil {
		parts = append(parts, fmt.Sprintf("pinned_content_version = %q", *config.PinnedContentVersion))
	}

	return strings.Join(parts, "\n    ")
}

func (config policyConfig) needsDataSource() bool {
	return config.SensorOperations.PinnedContentVersion != nil ||
		config.SystemCritical.PinnedContentVersion != nil ||
		config.VulnerabilityManagement.PinnedContentVersion != nil ||
		config.RapidResponse.PinnedContentVersion != nil
}

func (config policyConfig) resourceName() string {
	return "crowdstrike_content_update_policy.test"
}

// TestChecks generates all appropriate test checks based on the policy configuration.
func (config policyConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "name", config.Name),
		resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "description", config.Description),
		resource.TestCheckResourceAttrSet("crowdstrike_content_update_policy.test", "id"),
		resource.TestCheckResourceAttrSet("crowdstrike_content_update_policy.test", "last_updated"),
	)

	if config.Enabled != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", fmt.Sprintf("%t", *config.Enabled)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "enabled", "true"))
	}

	checks = append(checks, config.SensorOperations.generateChecks("sensor_operations")...)
	checks = append(checks, config.SystemCritical.generateChecks("system_critical")...)
	checks = append(checks, config.VulnerabilityManagement.generateChecks("vulnerability_management")...)
	checks = append(checks, config.RapidResponse.generateChecks("rapid_response")...)

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", "host_groups.#", fmt.Sprintf("%d", config.HostGroupCount)))

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// generateChecks creates appropriate test checks for a ring configuration.
func (ring ringConfig) generateChecks(category string) []resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".ring_assignment", ring.RingAssignment))

	if ring.RingAssignment != "ga" {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_content_update_policy.test", category+".delay_hours"))
	} else {
		if ring.DelayHours != nil {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".delay_hours", fmt.Sprintf("%d", *ring.DelayHours)))
		} else {
			checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".delay_hours", "0"))
		}
	}

	// Check pinned content version
	if ring.PinnedContentVersion != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_content_update_policy.test", category+".pinned_content_version", *ring.PinnedContentVersion))
	} else {
		checks = append(checks, resource.TestCheckNoResourceAttr("crowdstrike_content_update_policy.test", category+".pinned_content_version"))
	}

	return checks
}

func TestAccContentUpdatePolicyResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "basic_policy",
			config: policyConfig{
				Name:        "test-policy-basic",
				Description: "Test content update policy",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "updated_policy",
			config: policyConfig{
				Name:        "test-policy-updated",
				Description: "Updated test content update policy",
				Enabled:     utils.Addr(false),
				SensorOperations: ringConfig{
					RingAssignment: "ea",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(48),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(12),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			steps = append(steps, resource.TestStep{
				ResourceName:      testCases[0].config.resourceName(),
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}

func TestAccContentUpdatePolicyResource_HostGroups(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "single_host_group",
			config: policyConfig{
				Name:           "test-policy-hg",
				Description:    "Test content update policy with host groups",
				Enabled:        utils.Addr(true),
				HostGroupCount: 1,
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "multiple_host_groups",
			config: policyConfig{
				Name:           "test-policy-hg-updated",
				Description:    "Test content update policy with host groups",
				Enabled:        utils.Addr(true),
				HostGroupCount: 2,
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "empty_host_groups",
			config: policyConfig{
				Name:           "test-policy-empty-hg",
				Description:    "Test content update policy with empty host groups",
				Enabled:        utils.Addr(true),
				HostGroupCount: 0,
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccContentUpdatePolicyResource_PinnedContentVersions(t *testing.T) {
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "basic_pinned_versions",
			config: policyConfig{
				Name:        "test-policy-pinned-basic",
				Description: "Test content update policy with basic pinned versions",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("2025.07.22.1028"),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(12),
					PinnedContentVersion: utils.Addr("2025.07.29.070"),
				},
				RapidResponse: ringConfig{
					RingAssignment:       "ga",
					PinnedContentVersion: utils.Addr("2025.07.30.0531"),
				},
			},
		},
		{
			name: "all_categories_pinned",
			config: policyConfig{
				Name:        "test-policy-all-pinned",
				Description: "Test content update policy with all categories pinned",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(48),
					PinnedContentVersion: utils.Addr("2025.07.22.1028"),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("2025.07.22.104"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "pause",
					PinnedContentVersion: utils.Addr("2025.07.29.070"),
				},
				RapidResponse: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0),
					PinnedContentVersion: utils.Addr("2025.07.30.0531"),
				},
			},
		},
		{
			name: "updated_pinned_versions",
			config: policyConfig{
				Name:        "test-policy-pinned-updated",
				Description: "Test content update policy with updated pinned versions",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(24),
					PinnedContentVersion: utils.Addr("2025.05.01.1234"),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(12),
					// No pinned version - should be removed if it was previously set
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("2025.04.15.0999"),
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
					// No pinned version
				},
			},
		},
		{
			name: "mixed_configurations",
			config: policyConfig{
				Name:        "test-policy-mixed-pinned",
				Description: "Test content update policy with mixed pinned and unpinned configurations",
				Enabled:     utils.Addr(false),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(2),
					// No pinned version
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(8),
					PinnedContentVersion: utils.Addr("2025.03.01.0777"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "pause",
					// No pinned version
				},
				RapidResponse: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("2025.02.28.0888"),
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			// Test import functionality with pinned versions
			steps = append(steps, resource.TestStep{
				ResourceName:      testCases[0].config.resourceName(),
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"last_updated",
				},
			})
			return steps
		}(),
	})
}

func TestAccContentUpdatePolicyResource_PinnedVersionTransitions(t *testing.T) {
	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "no_pinned_versions",
			config: policyConfig{
				Name:        "test-policy-transitions-no-pin",
				Description: "Test content update policy starting without pinned versions",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "add_pinned_versions",
			config: policyConfig{
				Name:        "test-policy-transitions-add-pin",
				Description: "Test content update policy adding pinned versions",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(0),
					PinnedContentVersion: utils.Addr("2025.06.01.1111"),
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("2025.05.15.2222"),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
					// Still no pinned version
				},
				RapidResponse: ringConfig{
					RingAssignment:       "pause",
					PinnedContentVersion: utils.Addr("2025.04.30.3333"),
				},
			},
		},
		{
			name: "remove_some_pinned_versions",
			config: policyConfig{
				Name:        "test-policy-transitions-remove-pin",
				Description: "Test content update policy removing some pinned versions",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
					// Removed pinned version
				},
				SystemCritical: ringConfig{
					RingAssignment:       "ea",
					PinnedContentVersion: utils.Addr("2025.05.20.4444"), // Updated version
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment:       "ga",
					DelayHours:           utils.Addr(24),
					PinnedContentVersion: utils.Addr("2025.05.10.5555"), // Added pinned version
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
					// Removed pinned version
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccContentUpdatePolicyResource_RingConfigurations(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "all_ga_rings",
			config: policyConfig{
				Name:        "test-policy-all-ga",
				Description: "Test content update policy with all GA rings",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(48),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(72),
				},
			},
		},
		{
			name: "all_ea_rings",
			config: policyConfig{
				Name:        "test-policy-all-ea",
				Description: "Test content update policy with all EA rings",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ea",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "ea",
				},
			},
		},
		{
			name: "mixed_configuration",
			config: policyConfig{
				Name:        "test-policy-mixed",
				Description: "Test content update policy with mixed ring assignments",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(12),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "pause",
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(2),
				},
			},
		},
		{
			name: "various_delay_hours",
			config: policyConfig{
				Name:        "test-policy-delay-variations",
				Description: "Test content update policy with various delay hours",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(1),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(4),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(8),
				},
				RapidResponse: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(72),
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccContentUpdatePolicyResource_StateTransitions(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "disabled_policy",
			config: policyConfig{
				Name:        "test-policy-transitions-disabled",
				Description: "Test disabled content update policy",
				Enabled:     utils.Addr(false),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "enabled_policy",
			config: policyConfig{
				Name:        "test-policy-transitions-enabled",
				Description: "Test enabled content update policy",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "ea_rings_no_delay",
			config: policyConfig{
				Name:        "test-policy-transitions-ea",
				Description: "Test content update policy with null delay hours for EA rings",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ea",
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}

func TestAccContentUpdatePolicyResource_Validation(t *testing.T) {

	validationTests := []struct {
		name        string
		config      policyConfig
		expectError *regexp.Regexp
	}{
		{
			name: "invalid_delay_with_ea_ring",
			config: policyConfig{
				Name:        "test-policy-invalid",
				Description: "Test content update policy with invalid delay configuration",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ea",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("delay_hours can only be set when ring_assignment is 'ga'"),
		},
		{
			name: "system_critical_cannot_use_pause",
			config: policyConfig{
				Name:        "test-policy-invalid-pause",
				Description: "Test content update policy with invalid system_critical pause",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "pause",
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile(`(?s).*Attribute system_critical.ring_assignment value must be one of.*"pause"`),
		},
		{
			name: "invalid_delay_hours_too_high",
			config: policyConfig{
				Name:        "test-policy-invalid-delay-high",
				Description: "Test content update policy with invalid high delay hours",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(73),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("Attribute sensor_operations.delay_hours value must be one of"),
		},
		{
			name: "multiple_validation_errors",
			config: policyConfig{
				Name:        "test-policy-multi-errors",
				Description: "Test content update policy with multiple validation errors",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ea",
					DelayHours:     utils.Addr(24),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "pause",
					DelayHours:     utils.Addr(12),
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile("delay_hours can only be set when ring_assignment is 'ga'"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config.String(),
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}

func TestAccContentUpdatePolicyResource_FieldBoundaries(t *testing.T) {

	testCases := []struct {
		name   string
		config policyConfig
	}{
		{
			name: "minimum_description",
			config: policyConfig{
				Name:        "test-policy-min-desc",
				Description: "1",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "long_description",
			config: policyConfig{
				Name:        "test-policy-long-desc",
				Description: "This is a very long description that tests the boundary limits of the description field. It contains multiple sentences and should be quite lengthy to test how the system handles long descriptions. This description is intentionally verbose to ensure we test the maximum field length handling properly. It includes various punctuation marks, numbers like 123 and 456, and special characters to ensure comprehensive testing of the field boundaries and validation logic.",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
		{
			name: "special_characters",
			config: policyConfig{
				Name:        "test-policy-special-chars_123",
				Description: "Test policy with special characters: !@#$%^&*()_+-={}[]|;:,.<>?",
				Enabled:     utils.Addr(true),
				SensorOperations: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(0),
				},
				SystemCritical: ringConfig{
					RingAssignment: "ga",
					DelayHours:     utils.Addr(24),
				},
				VulnerabilityManagement: ringConfig{
					RingAssignment: "ea",
				},
				RapidResponse: ringConfig{
					RingAssignment: "pause",
				},
			},
		},
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(t) },
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps: func() []resource.TestStep {
			var steps []resource.TestStep
			for _, tc := range testCases {
				steps = append(steps, resource.TestStep{
					Config: tc.config.String(),
					Check:  tc.config.TestChecks(),
				})
			}
			return steps
		}(),
	})
}
