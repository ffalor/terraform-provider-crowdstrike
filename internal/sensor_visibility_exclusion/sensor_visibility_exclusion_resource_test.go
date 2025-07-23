package sensorvisibilityexclusion_test

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

// exclusionConfig represents a complete sensor visibility exclusion configuration.
type exclusionConfig struct {
	Value                      string
	Comment                    string
	ApplyToDescendantProcesses *bool
	HostGroupCount             int
}

// String implements the Stringer interface and generates Terraform configuration from exclusionConfig.
func (config *exclusionConfig) String() string {
	var hostGroupResources string
	var hostGroupsBlock string

	randomSuffix := sdkacctest.RandString(8)

	if config.HostGroupCount > 0 {
		var hostGroupRefs []string
		for i := 0; i < config.HostGroupCount; i++ {
			hostGroupName := fmt.Sprintf("hg-%s-%d", randomSuffix, i)

			hostGroupResources += fmt.Sprintf(`
resource "crowdstrike_host_group" "hg_%d" {
  name        = "%s"
  description = "Test host group %d for sensor visibility exclusion"
  type        = "static"
  hostnames   = ["test-host%d-1", "test-host%d-2"]
}
`, i, hostGroupName, i, i, i)
			hostGroupRefs = append(hostGroupRefs, fmt.Sprintf("crowdstrike_host_group.hg_%d.id", i))
		}

		hostGroupsBlock = fmt.Sprintf(`
  host_groups = [%s]`, strings.Join(hostGroupRefs, ", "))
	}

	return fmt.Sprintf(`%s
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = %q
  comment = %q
  %s
  %s
}
`, hostGroupResources, config.Value, config.Comment, config.formatApplyToDescendantProcesses(), hostGroupsBlock)
}

func (config exclusionConfig) formatApplyToDescendantProcesses() string {
	if config.ApplyToDescendantProcesses == nil {
		return ""
	}

	return fmt.Sprintf("apply_to_descendant_processes = %t", *config.ApplyToDescendantProcesses)
}

func (config exclusionConfig) resourceName() string {
	return "crowdstrike_sensor_visibility_exclusion.test"
}

// TestChecks generates all appropriate test checks based on the exclusion configuration.
func (config exclusionConfig) TestChecks() resource.TestCheckFunc {
	var checks []resource.TestCheckFunc

	checks = append(checks,
		resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "value", config.Value),
		resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "comment", config.Comment),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "id"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "last_updated"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "regexp_value"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "value_hash"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "created_by"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "created_on"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "modified_by"),
		resource.TestCheckResourceAttrSet("crowdstrike_sensor_visibility_exclusion.test", "last_modified"),
	)

	if config.ApplyToDescendantProcesses != nil {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_to_descendant_processes", fmt.Sprintf("%t", *config.ApplyToDescendantProcesses)))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "apply_to_descendant_processes", "false"))
	}

	checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "host_groups.#", fmt.Sprintf("%d", config.HostGroupCount)))

	// Check applied_globally based on host group count
	if config.HostGroupCount > 0 {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "applied_globally", "false"))
	} else {
		checks = append(checks, resource.TestCheckResourceAttr("crowdstrike_sensor_visibility_exclusion.test", "applied_globally", "true"))
	}

	return resource.ComposeAggregateTestCheckFunc(checks...)
}

func TestAccSensorVisibilityExclusionResource_Basic(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "basic_exclusion",
			config: exclusionConfig{
				Value:   "/tmp/test-basic/*",
				Comment: "Test basic sensor visibility exclusion",
			},
		},
		{
			name: "updated_exclusion",
			config: exclusionConfig{
				Value:   "/tmp/test-updated/*",
				Comment: "Updated test sensor visibility exclusion",
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

func TestAccSensorVisibilityExclusionResource_DescendantProcesses(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "descendant_processes_false",
			config: exclusionConfig{
				Value:                      "/opt/app1/bin/*",
				Comment:                    "Test exclusion without descendant processes",
				ApplyToDescendantProcesses: utils.Addr(false),
			},
		},
		{
			name: "descendant_processes_true",
			config: exclusionConfig{
				Value:                      "/opt/app2/bin/*",
				Comment:                    "Test exclusion with descendant processes",
				ApplyToDescendantProcesses: utils.Addr(true),
			},
		},
		{
			name: "descendant_processes_default",
			config: exclusionConfig{
				Value:   "/opt/app3/bin/*",
				Comment: "Test exclusion with default descendant processes",
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

func TestAccSensorVisibilityExclusionResource_HostGroups(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "single_host_group",
			config: exclusionConfig{
				Value:          "/tmp/test-hg-single/*",
				Comment:        "Test sensor visibility exclusion with single host group",
				HostGroupCount: 1,
			},
		},
		{
			name: "multiple_host_groups",
			config: exclusionConfig{
				Value:          "/tmp/test-hg-multiple/*",
				Comment:        "Test sensor visibility exclusion with multiple host groups",
				HostGroupCount: 2,
			},
		},
		{
			name: "global_exclusion",
			config: exclusionConfig{
				Value:          "/tmp/test-hg-global/*",
				Comment:        "Test global sensor visibility exclusion",
				HostGroupCount: 0,
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

func TestAccSensorVisibilityExclusionResource_ComplexConfigurations(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "complex_with_host_groups_and_descendants",
			config: exclusionConfig{
				Value:                      "/opt/complex-app/bin/*",
				Comment:                    "Complex exclusion with host groups and descendant processes",
				ApplyToDescendantProcesses: utils.Addr(true),
				HostGroupCount:             2,
			},
		},
		{
			name: "windows_path_exclusion",
			config: exclusionConfig{
				Value:   "C:\\Program Files\\MyApp\\*",
				Comment: "Windows path exclusion test",
			},
		},
		{
			name: "wildcard_patterns",
			config: exclusionConfig{
				Value:   "/var/log/*.log",
				Comment: "Wildcard pattern exclusion test",
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

func TestAccSensorVisibilityExclusionResource_FieldBoundaries(t *testing.T) {
	testCases := []struct {
		name   string
		config exclusionConfig
	}{
		{
			name: "minimum_comment",
			config: exclusionConfig{
				Value:   "/tmp/min-comment/*",
				Comment: "1",
			},
		},
		{
			name: "long_comment",
			config: exclusionConfig{
				Value:   "/tmp/long-comment/*",
				Comment: "This is a very long comment that tests the boundary limits of the comment field. It contains multiple sentences and should be quite lengthy to test how the system handles long comments. This comment is intentionally verbose to ensure comprehensive testing of the field boundaries and validation logic. It includes various punctuation marks, numbers like 123 and 456, and special characters to ensure comprehensive testing.",
			},
		},
		{
			name: "special_characters_in_path",
			config: exclusionConfig{
				Value:   "/tmp/special-chars_123/app-name.test/*",
				Comment: "Test path with special characters and numbers",
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

func TestAccSensorVisibilityExclusionResource_Validation(t *testing.T) {
	validationTests := []struct {
		name        string
		config      string
		expectError *regexp.Regexp
	}{
		{
			name: "empty_value",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value   = ""
  comment = "Empty value test"
}`,
			expectError: regexp.MustCompile("Attribute value string length must be at least 1"),
		},
		{
			name: "invalid_host_group_format",
			config: `
resource "crowdstrike_sensor_visibility_exclusion" "test" {
  value       = "/tmp/test/*"
  comment     = "Invalid host group test"
  host_groups = [""]
}`,
			expectError: regexp.MustCompile("Attribute host_groups set element string length must be at least 1"),
		},
	}

	for _, tc := range validationTests {
		t.Run(tc.name, func(t *testing.T) {
			resource.ParallelTest(t, resource.TestCase{
				PreCheck:                 func() { acctest.PreCheck(t) },
				ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config:      tc.config,
						ExpectError: tc.expectError,
					},
				},
			})
		})
	}
}
