package contentupdatepolicy

import (
	"context"
	"fmt"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

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

// Valid delay hours for GA ring.
var validDelayHours = []int64{0, 1, 2, 4, 8, 12, 24, 48, 72}

// ringAssignmentValidators returns common validators for ring assignment attributes.
func ringAssignmentValidators() map[string][]validator.String {
	return map[string][]validator.String{
		"ring_assignment": {stringvalidator.OneOf(validRingAssignments...)},
		"system_critical": {stringvalidator.OneOf(validSystemCriticalRingAssignments...)},
	}
}

// delayHoursValidators returns common validators for delay hours attributes.
func delayHoursValidators() []validator.Int64 {
	return []validator.Int64{
		int64validator.OneOf(validDelayHours...),
	}
}

// contentUpdatePolicySettings represents the common content update policy settings structure.
type contentUpdatePolicySettings struct {
	sensorOperations        *ringAssignmentModel
	systemCritical          *ringAssignmentModel
	vulnerabilityManagement *ringAssignmentModel
	rapidResponse           *ringAssignmentModel
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
func buildRingAssignmentSettings(settings *contentUpdatePolicySettings) []*models.ContentUpdateRingAssignmentSettingsReqV1 {
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
				ringAssignment.PinnedContentVersion = types.StringValue(*setting.PinnedContentVersion)
			} else {
				ringAssignment.PinnedContentVersion = types.StringNull()
			}

			objValue, diag := types.ObjectValueFrom(ctx, ringAssignment.AttributeTypes(), ringAssignment)
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

// getContentUpdatePolicy retrieves a content update policy by ID.
func getContentUpdatePolicy(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	res, err := client.ContentUpdatePolicies.GetContentUpdatePolicies(
		&content_update_policies.GetContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{policyID},
		},
	)

	if err != nil {
		diags.AddError(
			"Error reading content update policy",
			"Could not read content update policy: "+policyID+": "+err.Error(),
		)
		return nil, diags
	}

	if len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Content update policy not found",
			fmt.Sprintf("Content update policy with ID %s not found", policyID),
		)
		return nil, diags
	}

	return res.Payload.Resources[0], diags
}

// updatePolicyEnabledState enables or disables a content update policy.
func updatePolicyEnabledState(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	enabled bool,
) error {
	actionName := "disable"
	if enabled {
		actionName = "enable"
	}

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: actionName,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{policyID},
			},
		},
	)

	return err
}

// setPinnedContentVersion sets a pinned content version for a specific category in a policy.
func setPinnedContentVersion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	categoryName string,
	version string,
) error {
	actionParams := []*models.MsaspecActionParameter{
		{
			Name:  &categoryName,
			Value: &version,
		},
	}

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: "set-pinned-content-version",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	return err
}

// removePinnedContentVersion removes a pinned content version for a specific category in a policy.
func removePinnedContentVersion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	categoryName string,
) error {
	actionParams := []*models.MsaspecActionParameter{
		{
			Name:  &categoryName,
			Value: &categoryName, // According to API docs, pass the category name as the value
		},
	}

	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			Context:    ctx,
			ActionName: "remove-pinned-content-version",
			Body: &models.MsaEntityActionRequestV2{
				ActionParameters: actionParams,
				Ids:              []string{policyID},
			},
		},
	)

	return err
}

// managePinnedContentVersions handles setting/removing pinned content versions for all categories.
func managePinnedContentVersions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	oldSettings *contentUpdatePolicySettings,
	newSettings *contentUpdatePolicySettings,
) error {
	categoryMap := map[string]struct {
		oldSetting *ringAssignmentModel
		newSetting *ringAssignmentModel
		apiName    string
	}{
		"sensor_operations": {
			oldSetting: getSettingOrNil(oldSettings, "sensor_operations"),
			newSetting: getSettingOrNil(newSettings, "sensor_operations"),
			apiName:    "sensor_operations",
		},
		"system_critical": {
			oldSetting: getSettingOrNil(oldSettings, "system_critical"),
			newSetting: getSettingOrNil(newSettings, "system_critical"),
			apiName:    "system_critical",
		},
		"vulnerability_management": {
			oldSetting: getSettingOrNil(oldSettings, "vulnerability_management"),
			newSetting: getSettingOrNil(newSettings, "vulnerability_management"),
			apiName:    "vulnerability_management",
		},
		"rapid_response": {
			oldSetting: getSettingOrNil(oldSettings, "rapid_response"),
			newSetting: getSettingOrNil(newSettings, "rapid_response"),
			apiName:    "rapid_response_al_bl_listing",
		},
	}

	for category, config := range categoryMap {
		var oldVersion, newVersion string
		
		if config.oldSetting != nil && !config.oldSetting.PinnedContentVersion.IsNull() {
			oldVersion = config.oldSetting.PinnedContentVersion.ValueString()
		}
		
		if config.newSetting != nil && !config.newSetting.PinnedContentVersion.IsNull() {
			newVersion = config.newSetting.PinnedContentVersion.ValueString()
		}

		// If versions are the same, no action needed
		if oldVersion == newVersion {
			continue
		}

		// If new version is empty but old version exists, remove pinning
		if newVersion == "" && oldVersion != "" {
			if err := removePinnedContentVersion(ctx, client, policyID, config.apiName); err != nil {
				return fmt.Errorf("failed to remove pinned content version for %s: %w", category, err)
			}
		}

		// If new version is specified, set pinning
		if newVersion != "" {
			if err := setPinnedContentVersion(ctx, client, policyID, config.apiName, newVersion); err != nil {
				return fmt.Errorf("failed to set pinned content version for %s: %w", category, err)
			}
		}
	}

	return nil
}

// getSettingOrNil is a helper function to safely get settings from contentUpdatePolicySettings.
func getSettingOrNil(settings *contentUpdatePolicySettings, category string) *ringAssignmentModel {
	if settings == nil {
		return nil
	}
	
	switch category {
	case "sensor_operations":
		return settings.sensorOperations
	case "system_critical":
		return settings.systemCritical
	case "vulnerability_management":
		return settings.vulnerabilityManagement
	case "rapid_response":
		return settings.rapidResponse
	default:
		return nil
	}
}
