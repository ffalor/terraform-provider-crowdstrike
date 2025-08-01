package contentupdatepolicy

import (
	"context"
	"fmt"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// ringAssignmentModel represents a content category ring assignment.
type ringAssignmentModel struct {
	RingAssignment       types.String `tfsdk:"ring_assignment"`
	DelayHours           types.Int64  `tfsdk:"delay_hours"`
	PinnedContentVersion types.String `tfsdk:"pinned_content_version"`
}

// AttributeTypes returns the attribute types for the ring assignment model.
func (r ringAssignmentModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"ring_assignment":        types.StringType,
		"delay_hours":            types.Int64Type,
		"pinned_content_version": types.StringType,
	}
}

// Valid ring assignments.
var validRingAssignments = []string{
	"ga",    // general availability
	"ea",    // early access
	"pause", // pause updates
}

// Valid ring assignments for system_critical (no pause allowed).
var validSystemCriticalRingAssignments = []string{
	"ga", // general availability
	"ea", // early access
}

// ringAssignmentValidators returns common validators for ring assignment attributes.
func ringAssignmentValidators() map[string][]validator.String {
	return map[string][]validator.String{
		"ring_assignment": {stringvalidator.OneOf(validRingAssignments...)},
		"system_critical": {stringvalidator.OneOf(validSystemCriticalRingAssignments...)},
	}
}

// extractRingAssignments extracts ring assignment objects from terraform objects.
func extractRingAssignments(
	ctx context.Context,
	sensorOps, systemCrit, vulnMgmt, rapidResp types.Object,
) (*contentUpdatePolicySettings, diag.Diagnostics) {
	var diags diag.Diagnostics
	settings := &contentUpdatePolicySettings{}

	if !sensorOps.IsNull() {
		var sensorOperations ringAssignmentModel
		diags.Append(sensorOps.As(ctx, &sensorOperations, basetypes.ObjectAsOptions{})...)
		settings.sensorOperations = &sensorOperations
	}

	if !systemCrit.IsNull() {
		var systemCritical ringAssignmentModel
		diags.Append(systemCrit.As(ctx, &systemCritical, basetypes.ObjectAsOptions{})...)
		settings.systemCritical = &systemCritical
	}

	if !vulnMgmt.IsNull() {
		var vulnerabilityManagement ringAssignmentModel
		diags.Append(vulnMgmt.As(ctx, &vulnerabilityManagement, basetypes.ObjectAsOptions{})...)
		settings.vulnerabilityManagement = &vulnerabilityManagement
	}

	if !rapidResp.IsNull() {
		var rapidResponse ringAssignmentModel
		diags.Append(rapidResp.As(ctx, &rapidResponse, basetypes.ObjectAsOptions{})...)
		settings.rapidResponse = &rapidResponse
	}

	return settings, diags
}

// buildRingAssignmentSettings converts content update policy settings to API model.
func buildRingAssignmentSettings(
	settings *contentUpdatePolicySettings,
) []*models.ContentUpdateRingAssignmentSettingsReqV1 {
	ringAssignmentSettings := make([]*models.ContentUpdateRingAssignmentSettingsReqV1, 0, 4)

	if settings.sensorOperations != nil {
		delayHours := int64(0)
		if !settings.sensorOperations.DelayHours.IsNull() {
			delayHours = settings.sensorOperations.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "sensor_operations"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: settings.sensorOperations.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if settings.systemCritical != nil {
		delayHours := int64(0)
		if !settings.systemCritical.DelayHours.IsNull() {
			delayHours = settings.systemCritical.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "system_critical"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: settings.systemCritical.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if settings.vulnerabilityManagement != nil {
		delayHours := int64(0)
		if !settings.vulnerabilityManagement.DelayHours.IsNull() {
			delayHours = settings.vulnerabilityManagement.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "vulnerability_management"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: settings.vulnerabilityManagement.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	if settings.rapidResponse != nil {
		delayHours := int64(0)
		if !settings.rapidResponse.DelayHours.IsNull() {
			delayHours = settings.rapidResponse.DelayHours.ValueInt64()
		}
		delayHoursStr := fmt.Sprintf("%d", delayHours)
		categoryID := "rapid_response_al_bl_listing"
		setting := &models.ContentUpdateRingAssignmentSettingsReqV1{
			ID:             &categoryID,
			RingAssignment: settings.rapidResponse.RingAssignment.ValueStringPointer(),
			DelayHours:     &delayHoursStr,
		}
		ringAssignmentSettings = append(ringAssignmentSettings, setting)
	}

	return ringAssignmentSettings
}

// populateRingAssignments converts API response to terraform objects.
func populateRingAssignments(
	ctx context.Context,
	policy models.ContentUpdatePolicyV1,
) (sensorOps, systemCrit, vulnMgmt, rapidResp types.Object, diags diag.Diagnostics) {
	// Initialize to null values
	sensorOps = types.ObjectNull(ringAssignmentModel{}.AttributeTypes())
	systemCrit = types.ObjectNull(ringAssignmentModel{}.AttributeTypes())
	vulnMgmt = types.ObjectNull(ringAssignmentModel{}.AttributeTypes())
	rapidResp = types.ObjectNull(ringAssignmentModel{}.AttributeTypes())

	if policy.Settings != nil && policy.Settings.RingAssignmentSettings != nil {
		for _, setting := range policy.Settings.RingAssignmentSettings {
			ringAssignment := ringAssignmentModel{
				RingAssignment: types.StringValue(*setting.RingAssignment),
			}

			if *setting.RingAssignment == "ga" {
				delayHours := int64(0)
				if setting.DelayHours != nil {
					if delayStr := *setting.DelayHours; delayStr != "" {
						if delay, err := strconv.ParseInt(delayStr, 10, 64); err == nil {
							delayHours = delay
						}
					}
				}
				ringAssignment.DelayHours = types.Int64Value(delayHours)
			} else {
				ringAssignment.DelayHours = types.Int64Null()
			}

			// Handle pinned content version
			if setting.PinnedContentVersion != nil && *setting.PinnedContentVersion != "" {
				ringAssignment.PinnedContentVersion = types.StringValue(
					*setting.PinnedContentVersion,
				)
			} else {
				ringAssignment.PinnedContentVersion = types.StringNull()
			}

			objValue, diag := types.ObjectValueFrom(
				ctx,
				ringAssignment.AttributeTypes(),
				ringAssignment,
			)
			diags.Append(diag...)
			if diags.HasError() {
				return
			}

			switch *setting.ID {
			case "sensor_operations":
				sensorOps = objValue
			case "system_critical":
				systemCrit = objValue
			case "vulnerability_management":
				vulnMgmt = objValue
			case "rapid_response_al_bl_listing":
				rapidResp = objValue
			}
		}
	}

	return sensorOps, systemCrit, vulnMgmt, rapidResp, diags
}
