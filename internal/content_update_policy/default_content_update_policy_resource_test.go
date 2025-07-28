package contentupdatepolicy_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// defaultPolicyRingConfig represents a ring assignment configuration for default policies.
type defaultPolicyRingConfig struct {
	RingAssignment string
	DelayHours     *int
}

// defaultPolicyConfig represents a default content update policy configuration.
type defaultPolicyConfig struct {
	Name                    string
	SensorOperations        defaultPolicyRingConfig
	SystemCritical          defaultPolicyRingConfig
	VulnerabilityManagement defaultPolicyRingConfig
	RapidResponse           defaultPolicyRingConfig
}

// String generates Terraform configuration for default content update policy.
func (config *defaultPolicyConfig) String() string {
	randomSuffix := sdkacctest.RandString(8)
	resourceName := fmt.Sprintf("%s-%s", config.Name, randomSuffix)

	return fmt.Sprintf(`
# Note: Default content update policies must be imported before they can be managed
# terraform import crowdstrike_default_content_update_policy.%s <policy-id>

resource "crowdstrike_default_content_update_policy" "%s" {
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
}
`, resourceName, resourceName,
		config.SensorOperations.RingAssignment, config.SensorOperations.formatDelayHours(),
		config.SystemCritical.RingAssignment, config.SystemCritical.formatDelayHours(),
		config.VulnerabilityManagement.RingAssignment, config.VulnerabilityManagement.formatDelayHours(),
		config.RapidResponse.RingAssignment, config.RapidResponse.formatDelayHours())
}

func (config defaultPolicyRingConfig) formatDelayHours() string {
	if config.DelayHours == nil {
		return ""
	}
	return fmt.Sprintf("delay_hours = %d", *config.DelayHours)
}

func (config defaultPolicyConfig) resourceName() string {
	return fmt.Sprintf("crowdstrike_default_content_update_policy.%s-%s", config.Name, sdkacctest.RandString(8))
}

// TestChecks generates all appropriate test checks based on the policy configuration.
func (config defaultPolicyConfig) TestChecks(resourceName string) resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttrSet(resourceName, "id"),
		resource.TestCheckResourceAttrSet(resourceName, "last_updated"),
	)

	checks = append(checks, config.SensorOperations.generateChecks(resourceName, "sensor_operations")...)
	checks = append(checks, config.SystemCritical.generateChecks(resourceName, "system_critical")...)
	checks = append(checks, config.VulnerabilityManagement.generateChecks(resourceName, "vulnerability_management")...)
	checks = append(checks, config.RapidResponse.generateChecks(resourceName, "rapid_response")...)

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

// generateChecks creates appropriate test checks for a ring configuration.
func (ring defaultPolicyRingConfig) generateChecks(resourceName, category string) []resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks, resource.TestCheckResourceAttr(resourceName, category+".ring_assignment", ring.RingAssignment))

	if ring.RingAssignment != "ga" {
		checks = append(checks, resource.TestCheckNoResourceAttr(resourceName, category+".delay_hours"))
	} else {
		if ring.DelayHours != nil {
			checks = append(checks, resource.TestCheckResourceAttr(resourceName, category+".delay_hours", fmt.Sprintf("%d", *ring.DelayHours)))
		} else {
			checks = append(checks, resource.TestCheckResourceAttr(resourceName, category+".delay_hours", "0"))
		}
	}

	return checks
}

func TestAccDefaultContentUpdatePolicyResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config defaultPolicyConfig
	}{
		{
			name: "all_ga_configuration",
			config: defaultPolicyConfig{
				Name: "test-default-basic",
				SensorOperations: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(0),
				},
				SystemCritical: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(24),
				},
				VulnerabilityManagement: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(12),
				},
				RapidResponse: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(48),
				},
			},
		},
		{
			name: "mixed_configuration",
			config: defaultPolicyConfig{
				Name: "test-default-mixed",
				SensorOperations: defaultPolicyRingConfig{
					RingAssignment: "ea",
				},
				SystemCritical: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(0),
				},
				VulnerabilityManagement: defaultPolicyRingConfig{
					RingAssignment: "pause",
				},
				RapidResponse: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(72),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config.String(),
						ExpectError: regexp.MustCompile("Default content update policy must be imported"),
					},
				},
			})
		})
	}
}

func TestAccDefaultContentUpdatePolicyResource_Validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      defaultPolicyConfig
		expectError *regexp.Regexp
	}{
		{
			name: "invalid_delay_with_ea_ring",
			config: defaultPolicyConfig{
				Name: "test-default-invalid",
				SensorOperations: defaultPolicyRingConfig{
					RingAssignment: "ea",
					DelayHours:     ptrInt(24), // Invalid: delay_hours with EA ring
				},
				SystemCritical: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(0),
				},
				VulnerabilityManagement: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(0),
				},
				RapidResponse: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(0),
				},
			},
			expectError: regexp.MustCompile("delay_hours can only be set when ring_assignment is 'ga'"),
		},
		{
			name: "system_critical_cannot_use_pause",
			config: defaultPolicyConfig{
				Name: "test-default-invalid-pause",
				SensorOperations: defaultPolicyRingConfig{
					RingAssignment: "ga",
					DelayHours:     ptrInt(0),
				},
				SystemCritical: defaultPolicyRingConfig{
					RingAssignment: "pause", // Invalid: pause not allowed for system_critical
				},
				VulnerabilityManagement: defaultPolicyRingConfig{
					RingAssignment: "ea",
				},
				RapidResponse: defaultPolicyRingConfig{
					RingAssignment: "pause",
				},
			},
			expectError: regexp.MustCompile(`(?s).*Attribute system_critical.ring_assignment value must be one of.*"pause"`),
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

// ptrInt returns a pointer to an int.
func ptrInt(i int) *int {
	return &i
}