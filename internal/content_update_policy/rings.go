package contentupdatepolicy

import (
	"context"
	"fmt"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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

// extract extracts the Go values from their terraform wrapped values.
func (r *ringAssignmentModel) wrap(
	setting *models.ContentUpdateRingAssignmentSettingsV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	r.RingAssignment = types.StringPointerValue(setting.RingAssignment)

	if *setting.RingAssignment == "ga" {
		delayHours := int64(0)
		if setting.DelayHours != nil {
			if delayStr := *setting.DelayHours; delayStr != "" {
				if delay, err := strconv.ParseInt(delayStr, 10, 64); err == nil {
					delayHours = delay
				}
			}
		}

		r.DelayHours = utils.SetInt64FromAPIIfNotZero(r.DelayHours, delayHours)
	} else {
		r.DelayHours = types.Int64Null()
	}

	r.PinnedContentVersion = utils.OptionalString(setting.PinnedContentVersion)

	return diags
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

	tflog.Debug(ctx, "Starting extractRingAssignments", map[string]interface{}{
		"sensorOps":  sensorOps.String(),
		"systemCrit": systemCrit.String(),
		"vulnMgmt":   vulnMgmt.String(),
		"rapidResp":  rapidResp.String(),
	})

	if !sensorOps.IsNull() {
		tflog.Debug(ctx, "Extracting sensorOperations ring assignment")
		var sensorOperations ringAssignmentModel
		sensorOpsDiags := sensorOps.As(ctx, &sensorOperations, basetypes.ObjectAsOptions{})
		diags.Append(sensorOpsDiags...)
		if sensorOpsDiags.HasError() {
			tflog.Debug(ctx, "Failed to extract sensor operations ring assignment")
		} else {
			tflog.Debug(ctx, "Successfully extracted sensorOperations", map[string]interface{}{
				"ring_assignment":        sensorOperations.RingAssignment.String(),
				"delay_hours":            sensorOperations.DelayHours.String(),
				"pinned_content_version": sensorOperations.PinnedContentVersion.String(),
			})
		}
		settings.sensorOperations = &sensorOperations
	} else {
		tflog.Debug(ctx, "sensorOperations is null, skipping extraction")
	}

	if !systemCrit.IsNull() {
		tflog.Debug(ctx, "Extracting systemCritical ring assignment")
		var systemCritical ringAssignmentModel
		systemCritDiags := systemCrit.As(ctx, &systemCritical, basetypes.ObjectAsOptions{})
		diags.Append(systemCritDiags...)
		if systemCritDiags.HasError() {
			tflog.Debug(ctx, "Failed to extract system critical ring assignment")
		} else {
			tflog.Debug(ctx, "Successfully extracted systemCritical", map[string]interface{}{
				"ring_assignment":        systemCritical.RingAssignment.String(),
				"delay_hours":            systemCritical.DelayHours.String(),
				"pinned_content_version": systemCritical.PinnedContentVersion.String(),
			})
		}
		settings.systemCritical = &systemCritical
	} else {
		tflog.Debug(ctx, "systemCritical is null, skipping extraction")
	}

	if !vulnMgmt.IsNull() {
		tflog.Debug(ctx, "Extracting vulnerabilityManagement ring assignment")
		var vulnerabilityManagement ringAssignmentModel
		vulnMgmtDiags := vulnMgmt.As(ctx, &vulnerabilityManagement, basetypes.ObjectAsOptions{})
		diags.Append(vulnMgmtDiags...)
		if vulnMgmtDiags.HasError() {
			tflog.Debug(ctx, "Failed to extract vulnerability management ring assignment")
		} else {
			tflog.Debug(ctx, "Successfully extracted vulnerabilityManagement", map[string]interface{}{
				"ring_assignment":        vulnerabilityManagement.RingAssignment.String(),
				"delay_hours":            vulnerabilityManagement.DelayHours.String(),
				"pinned_content_version": vulnerabilityManagement.PinnedContentVersion.String(),
			})
		}
		settings.vulnerabilityManagement = &vulnerabilityManagement
	} else {
		tflog.Debug(ctx, "vulnerabilityManagement is null, skipping extraction")
	}

	if !rapidResp.IsNull() {
		tflog.Debug(ctx, "Extracting rapidResponse ring assignment")
		var rapidResponse ringAssignmentModel
		rapidRespDiags := rapidResp.As(ctx, &rapidResponse, basetypes.ObjectAsOptions{})
		diags.Append(rapidRespDiags...)
		if rapidRespDiags.HasError() {
			tflog.Debug(ctx, "Failed to extract rapid response ring assignment")
		} else {
			tflog.Debug(ctx, "Successfully extracted rapidResponse", map[string]interface{}{
				"ring_assignment":        rapidResponse.RingAssignment.String(),
				"delay_hours":            rapidResponse.DelayHours.String(),
				"pinned_content_version": rapidResponse.PinnedContentVersion.String(),
			})
		}
		settings.rapidResponse = &rapidResponse
	} else {
		tflog.Debug(ctx, "rapidResponse is null, skipping extraction")
	}

	tflog.Debug(ctx, "Completed extractRingAssignments", map[string]interface{}{
		"total_errors":                      len(diags.Errors()),
		"sensorOperations_extracted":        settings.sensorOperations != nil,
		"systemCritical_extracted":          settings.systemCritical != nil,
		"vulnerabilityManagement_extracted": settings.vulnerabilityManagement != nil,
		"rapidResponse_extracted":           settings.rapidResponse != nil,
	})

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
