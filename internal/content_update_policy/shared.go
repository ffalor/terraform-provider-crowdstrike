package contentupdatepolicy

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// Valid delay hours for GA ring.
var validDelayHours = []int64{0, 1, 2, 4, 8, 12, 24, 48, 72}

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

// setPinnedContentVersion sets a pinned content version for a specific category.
func setPinnedContentVersion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID, categoryName, version string,
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

// removePinnedContentVersion removes a pinned content version for a specific category.
func removePinnedContentVersion(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID, categoryName string,
) error {
	// For remove action, we only need the category name as the parameter value
	actionParams := []*models.MsaspecActionParameter{
		{
			Name:  &categoryName,
			Value: &categoryName,
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

// managePinnedContentVersions handles setting and removing pinned content versions for a policy.
func managePinnedContentVersions(
	ctx context.Context,
	client *client.CrowdStrikeAPISpecification,
	policyID string,
	currentSettings, plannedSettings *contentUpdatePolicySettings,
) error {
	categories := map[string]struct {
		current *ringAssignmentModel
		planned *ringAssignmentModel
		apiName string
	}{
		"sensor_operations": {
			currentSettings.sensorOperations,
			plannedSettings.sensorOperations,
			"sensor_operations",
		},
		"system_critical": {
			currentSettings.systemCritical,
			plannedSettings.systemCritical,
			"system_critical",
		},
		"vulnerability_management": {
			currentSettings.vulnerabilityManagement,
			plannedSettings.vulnerabilityManagement,
			"vulnerability_management",
		},
		"rapid_response": {
			currentSettings.rapidResponse,
			plannedSettings.rapidResponse,
			"rapid_response_al_bl_listing",
		},
	}

	for _, category := range categories {
		if category.planned == nil {
			continue
		}

		var currentVersion, plannedVersion string

		if category.current != nil && !category.current.PinnedContentVersion.IsNull() {
			currentVersion = category.current.PinnedContentVersion.ValueString()
		}

		if !category.planned.PinnedContentVersion.IsNull() {
			plannedVersion = category.planned.PinnedContentVersion.ValueString()
		}

		// If versions are different, update accordingly
		if currentVersion != plannedVersion {
			if plannedVersion != "" {
				// Set new pinned version
				if err := setPinnedContentVersion(ctx, client, policyID, category.apiName, plannedVersion); err != nil {
					return fmt.Errorf(
						"failed to set pinned content version for %s: %w",
						category.apiName,
						err,
					)
				}
			} else if currentVersion != "" {
				// Remove pinned version
				if err := removePinnedContentVersion(ctx, client, policyID, category.apiName); err != nil {
					return fmt.Errorf("failed to remove pinned content version for %s: %w", category.apiName, err)
				}
			}
		}
	}

	return nil
}
