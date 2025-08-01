package contentupdatepolicy

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// validateContentUpdatePolicyModifyPlan performs plan-time validation to ensure ring assignment
// changes don't conflict with pinned content versions across all categories.
func validateContentUpdatePolicyModifyPlan(
	currentSettings, plannedSettings *contentUpdatePolicySettings,
) diag.Diagnostics {
	var diags diag.Diagnostics

	validateRingAssignmentWithPinnedVersion(
		"sensor_operations",
		currentSettings.sensorOperations,
		plannedSettings.sensorOperations,
		path.Root("sensor_operations"),
	)

	validateRingAssignmentWithPinnedVersion(
		"system_critical",
		currentSettings.systemCritical,
		plannedSettings.systemCritical,
		path.Root("system_critical"),
	)

	validateRingAssignmentWithPinnedVersion(
		"vulnerability_management",
		currentSettings.vulnerabilityManagement,
		plannedSettings.vulnerabilityManagement,
		path.Root("vulnerability_management"),
	)

	validateRingAssignmentWithPinnedVersion(
		"rapid_response",
		currentSettings.rapidResponse,
		plannedSettings.rapidResponse,
		path.Root("rapid_response"),
	)

	return diags
}

// Validate ring assignment changes against pinned content versions
func validateRingAssignmentWithPinnedVersion(
	categoryName string,
	currentSettings *ringAssignmentModel,
	plannedSettings *ringAssignmentModel,
	attrPath path.Path,
) diag.Diagnostics {
	var diags diag.Diagnostics

	if currentSettings == nil || plannedSettings == nil {
		return diags
	}

	currentRingAssignment := currentSettings.RingAssignment.ValueString()
	plannedRingAssignment := plannedSettings.RingAssignment.ValueString()

	// Only validate if ring assignment is changing
	if currentRingAssignment != plannedRingAssignment {
		// Check if planned configuration will have a pinned version
		if !plannedSettings.PinnedContentVersion.IsNull() &&
			plannedSettings.PinnedContentVersion.ValueString() != "" {
			diags.AddAttributeError(
				attrPath.AtName("ring_assignment"),
				"Cannot change ring assignment with pinned content version",
				fmt.Sprintf(
					"Cannot change ring_assignment for %s from '%s' to '%s' while a pinned_content_version is set. "+
						"To change ring assignments, remove the pinned_content_version (set to null or empty) in the same apply.",
					categoryName,
					currentRingAssignment,
					plannedRingAssignment,
				),
			)
		}
	}

	return diags
}
