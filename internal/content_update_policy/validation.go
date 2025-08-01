package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// validateContentUpdatePolicyModifyPlan performs plan-time validation to ensure ring assignment
// and delay_hours changes don't conflict with pinned content versions across all categories.
func validateContentUpdatePolicyModifyPlan(
	ctx context.Context,
	currentSettings, plannedSettings *contentUpdatePolicySettings,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Starting validateContentUpdatePolicyModifyPlan", map[string]interface{}{
		"currentSettings_nil": currentSettings == nil,
		"plannedSettings_nil": plannedSettings == nil,
	})

	if currentSettings != nil {
		tflog.Debug(ctx, "Current settings state", map[string]interface{}{
			"sensorOperations_nil":        currentSettings.sensorOperations == nil,
			"systemCritical_nil":          currentSettings.systemCritical == nil,
			"vulnerabilityManagement_nil": currentSettings.vulnerabilityManagement == nil,
			"rapidResponse_nil":           currentSettings.rapidResponse == nil,
		})
	}

	if plannedSettings != nil {
		tflog.Debug(ctx, "Planned settings state", map[string]interface{}{
			"sensorOperations_nil":        plannedSettings.sensorOperations == nil,
			"systemCritical_nil":          plannedSettings.systemCritical == nil,
			"vulnerabilityManagement_nil": plannedSettings.vulnerabilityManagement == nil,
			"rapidResponse_nil":           plannedSettings.rapidResponse == nil,
		})
	}

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"sensor_operations",
		currentSettings.sensorOperations,
		plannedSettings.sensorOperations,
		path.Root("sensor_operations"),
	)...)

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"system_critical",
		currentSettings.systemCritical,
		plannedSettings.systemCritical,
		path.Root("system_critical"),
	)...)

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"vulnerability_management",
		currentSettings.vulnerabilityManagement,
		plannedSettings.vulnerabilityManagement,
		path.Root("vulnerability_management"),
	)...)

	diags.Append(validateRingAssignmentWithPinnedVersion(
		ctx,
		"rapid_response",
		currentSettings.rapidResponse,
		plannedSettings.rapidResponse,
		path.Root("rapid_response"),
	)...)

	tflog.Debug(ctx, "Completed validateContentUpdatePolicyModifyPlan", map[string]interface{}{
		"total_errors": len(diags.Errors()),
	})

	return diags
}

// Validate ring assignment and delay_hours changes against pinned content versions
func validateRingAssignmentWithPinnedVersion(
	ctx context.Context,
	categoryName string,
	currentSettings *ringAssignmentModel,
	plannedSettings *ringAssignmentModel,
	attrPath path.Path,
) diag.Diagnostics {
	var diags diag.Diagnostics

	tflog.Debug(ctx, "Validating ring assignment with pinned version", map[string]interface{}{
		"category":            categoryName,
		"currentSettings_nil": currentSettings == nil,
		"plannedSettings_nil": plannedSettings == nil,
	})

	if currentSettings == nil || plannedSettings == nil {
		tflog.Debug(ctx, "Skipping validation - one or both settings are nil", map[string]interface{}{
			"category": categoryName,
		})
		return diags
	}

	tflog.Debug(ctx, "Current and planned settings state", map[string]interface{}{
		"category":                               categoryName,
		"current_ring_assignment_null":           currentSettings.RingAssignment.IsNull(),
		"current_ring_assignment_unknown":        currentSettings.RingAssignment.IsUnknown(),
		"current_delay_hours_null":               currentSettings.DelayHours.IsNull(),
		"current_delay_hours_unknown":            currentSettings.DelayHours.IsUnknown(),
		"current_pinned_content_version_null":    currentSettings.PinnedContentVersion.IsNull(),
		"current_pinned_content_version_unknown": currentSettings.PinnedContentVersion.IsUnknown(),
		"planned_ring_assignment_null":           plannedSettings.RingAssignment.IsNull(),
		"planned_ring_assignment_unknown":        plannedSettings.RingAssignment.IsUnknown(),
		"planned_delay_hours_null":               plannedSettings.DelayHours.IsNull(),
		"planned_delay_hours_unknown":            plannedSettings.DelayHours.IsUnknown(),
		"planned_pinned_content_version_null":    plannedSettings.PinnedContentVersion.IsNull(),
		"planned_pinned_content_version_unknown": plannedSettings.PinnedContentVersion.IsUnknown(),
	})

	// Skip validation if pinned content version is unknown - we can't validate against an unknown value
	if plannedSettings.PinnedContentVersion.IsUnknown() {
		tflog.Debug(ctx, "Skipping validation - pinned content version is unknown", map[string]interface{}{
			"category": categoryName,
		})
		return diags
	}

	// Check if there's a pinned version that would conflict with changes
	hasPinnedVersion := !plannedSettings.PinnedContentVersion.IsNull() &&
		plannedSettings.PinnedContentVersion.ValueString() != ""

	tflog.Debug(ctx, "Pinned version check", map[string]interface{}{
		"category":           categoryName,
		"hasPinnedVersion":   hasPinnedVersion,
		"pinnedVersionValue": plannedSettings.PinnedContentVersion.ValueString(),
	})

	if !hasPinnedVersion {
		tflog.Debug(ctx, "No pinned version, no conflict possible", map[string]interface{}{
			"category": categoryName,
		})
		return diags // No pinned version, no conflict possible
	}

	// Check ring assignment changes
	if !plannedSettings.RingAssignment.IsUnknown() &&
		currentSettings.RingAssignment.ValueString() != plannedSettings.RingAssignment.ValueString() {
		tflog.Error(ctx, "Ring assignment change blocked by pinned version", map[string]interface{}{
			"category":               categoryName,
			"current_ring":           currentSettings.RingAssignment.ValueString(),
			"planned_ring":           plannedSettings.RingAssignment.ValueString(),
			"pinned_content_version": plannedSettings.PinnedContentVersion.ValueString(),
		})
		diags.AddAttributeError(
			attrPath,
			"Cannot change ring assignment with pinned content version",
			fmt.Sprintf(
				"Cannot change ring_assignment for %s from '%s' to '%s' while a pinned_content_version is set. "+
					"To change ring assignments, remove the pinned_content_version.",
				categoryName,
				currentSettings.RingAssignment.ValueString(),
				plannedSettings.RingAssignment.ValueString(),
			),
		)
	}

	// Check delay hours changes
	if !currentSettings.DelayHours.IsUnknown() && !plannedSettings.DelayHours.IsUnknown() {
		currentDelayHours := int64(0)
		plannedDelayHours := int64(0)

		if !currentSettings.DelayHours.IsNull() {
			currentDelayHours = currentSettings.DelayHours.ValueInt64()
		}
		if !plannedSettings.DelayHours.IsNull() {
			plannedDelayHours = plannedSettings.DelayHours.ValueInt64()
		}

		tflog.Debug(ctx, "Delay hours comparison", map[string]interface{}{
			"category":            categoryName,
			"current_delay_hours": currentDelayHours,
			"planned_delay_hours": plannedDelayHours,
		})

		if currentDelayHours != plannedDelayHours {
			tflog.Error(ctx, "Delay hours change blocked by pinned version", map[string]interface{}{
				"category":               categoryName,
				"current_delay_hours":    currentDelayHours,
				"planned_delay_hours":    plannedDelayHours,
				"pinned_content_version": plannedSettings.PinnedContentVersion.ValueString(),
			})
			diags.AddAttributeError(
				attrPath,
				"Cannot change delay hours with pinned content version",
				fmt.Sprintf(
					"Cannot change delay_hours for %s from %v to %v while a pinned_content_version is set. "+
						"To change delay hours, remove the pinned_content_version.",
					categoryName,
					currentSettings.DelayHours.String(),
					plannedSettings.DelayHours.String(),
				),
			)
		}
	}

	return diags
}
