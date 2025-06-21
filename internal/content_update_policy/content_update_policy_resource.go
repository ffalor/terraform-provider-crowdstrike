package contentupdatepolicy

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	basetypes "github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &contentUpdatePolicyResource{}
	_ resource.ResourceWithConfigure      = &contentUpdatePolicyResource{}
	_ resource.ResourceWithImportState    = &contentUpdatePolicyResource{}
	_ resource.ResourceWithValidateConfig = &contentUpdatePolicyResource{}
)

// NewContentUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewContentUpdatePolicyResource() resource.Resource {
	return &contentUpdatePolicyResource{}
}

// contentUpdatePolicyResource is the resource implementation.
type contentUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// contentUpdatePolicyResourceModel is the resource model.
type contentUpdatePolicyResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	Name                    types.String `tfsdk:"name"`
	Description             types.String `tfsdk:"description"`
	Enabled                 types.Bool   `tfsdk:"enabled"`
	SystemCritical          types.Object `tfsdk:"system_critical"`
	SensorOperations        types.Object `tfsdk:"sensor_operations"`
	RapidResponse           types.Object `tfsdk:"rapid_response"`
	VulnerabilityManagement types.Object `tfsdk:"vulnerability_management"`
}

type ringAssignmentModel struct {
	DeploymentRing types.String `tfsdk:"deployment_ring"`
	DelayHours     types.String `tfsdk:"delay_hours"`
}

func (m ringAssignmentModel) AttributeTypes(ctx context.Context) map[string]attr.Type {
	return map[string]attr.Type{
		"deployment_ring": types.StringType,
		"delay_hours":     types.StringType,
	}
}

func ringAssignmentBlock() schema.Block {
	return schema.SingleNestedBlock{
		Description: "Settings for a deployment ring.",
		Attributes: map[string]schema.Attribute{
			"deployment_ring": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("ga", "ea"),
				},
			},
			"delay_hours": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("0", "1", "2", "4", "8", "12", "24", "48", "72"),
				},
			},
		},
	}
}

// Metadata returns the resource type name.
func (r *contentUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_content_update_policy"
}

// Schema defines the schema for the resource.
func (r *contentUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Blocks: map[string]schema.Block{
			"system_critical":          ringAssignmentBlock(),
			"sensor_operations":        ringAssignmentBlock(),
			"rapid_response":           ringAssignmentBlock(),
			"vulnerability_management": ringAssignmentBlock(),
		},
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the content update policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the content update policy.",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The description of the content update policy.",
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether the content update policy is enabled.",
			},
		},
		Description: `
This resource manages a content update policy.

*NOTE*: The 'delay_hours' attribute can only be used when 'deployment_ring' is set to 'ga'. The list of valid values for 'delay_hours' is based on user feedback and may be incomplete.
`,
	}
}

// ValidateConfig performs custom validation logic on the resource.
func (r *contentUpdatePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var plan contentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	validateRing := func(planRing types.Object, ringName string) {
		if !planRing.IsNull() && !planRing.IsUnknown() {
			var ringModel ringAssignmentModel
			resp.Diagnostics.Append(planRing.As(ctx, &ringModel, basetypes.ObjectAsOptions{})...)
			if resp.Diagnostics.HasError() {
				return
			}
			isSet := !ringModel.DelayHours.IsNull() && !ringModel.DelayHours.IsUnknown()
			isNonZero := isSet && ringModel.DelayHours.ValueString() != "0"

			if ringModel.DeploymentRing.ValueString() != "ga" && isNonZero {
				resp.Diagnostics.AddAttributeError(
					path.Root(ringName).AtName("delay_hours"),
					"Invalid Attribute Configuration",
					"'delay_hours' can only have a non-zero value when 'deployment_ring' is 'ga'.",
				)
			}
		}
	}

	validateRing(plan.SystemCritical, "system_critical")
	validateRing(plan.SensorOperations, "sensor_operations")
	validateRing(plan.RapidResponse, "rapid_response")
	validateRing(plan.VulnerabilityManagement, "vulnerability_management")
}

// Configure adds the provider configured client to the resource.
func (r *contentUpdatePolicyResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
		)
		return
	}
	r.client = client
}

// Create creates the resource and sets the initial state.
func (r *contentUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan contentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plannedEnabled := plan.Enabled

	settings, diag := planToSettings(ctx, plan)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyParams := content_update_policies.CreateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateCreatePoliciesReqV1{
			Resources: []*models.ContentUpdateCreatePolicyReqV1{
				{
					Name:        plan.Name.ValueStringPointer(),
					Description: plan.Description.ValueString(),
					Settings:    settings,
				},
			},
		},
	}

	tflog.Debug(ctx, "Creating content update policy", map[string]interface{}{"name": plan.Name.ValueString()})
	policy, err := r.client.ContentUpdatePolicies.CreateContentUpdatePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating content update policy",
			"Could not create content update policy, unexpected error: "+err.Error(),
		)
		return
	}

	if err = falcon.AssertNoError(policy.Payload.Errors); err != nil {
		resp.Diagnostics.AddError(
			"Error creating content update policy",
			"Could not create content update policy, unexpected error: "+err.Error(),
		)
		return
	}
	if len(policy.Payload.Resources) == 0 {
		resp.Diagnostics.AddError("Error creating content update policy", "Could not create content update policy, no resources returned")
		return
	}
	newPolicy := policy.Payload.Resources[0]

	if !plannedEnabled.IsNull() && !plannedEnabled.IsUnknown() {
		err = setPolicyEnabled(ctx, r.client, *newPolicy.ID, plannedEnabled.ValueBool())
		if err != nil {
			resp.Diagnostics.AddError("Unable to set initial enabled state for content update policy", err.Error())
			return
		}
	}

	// Read the final state of the policy after all modifications
	finalPolicy, err := getContentUpdatePolicy(ctx, r.client, *newPolicy.ID)
	if err != nil {
		resp.Diagnostics.AddError("Error reading content update policy after create", "Could not read content update policy "+*newPolicy.ID+": "+err.Error())
		return
	}

	diags := plan.wrap(ctx, finalPolicy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the resource state.
func (r *contentUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state contentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, err := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if err != nil {
		if notFound, ok := err.(*content_update_policies.GetContentUpdatePoliciesNotFound); ok {
			tflog.Warn(ctx, "Content update policy not found, removing from state", map[string]interface{}{
				"id":  state.ID.ValueString(),
				"err": notFound,
			})
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading content update policy",
			"Could not read content update policy, unexpected error: "+err.Error(),
		)
		return
	}
	diags := state.wrap(ctx, policy)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource state.
func (r *contentUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan, state contentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	settings, diag := planToSettings(ctx, plan)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyParams := content_update_policies.UpdateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateUpdatePoliciesReqV1{
			Resources: []*models.ContentUpdateUpdatePolicyReqV1{
				{
					ID:          state.ID.ValueStringPointer(),
					Name:        plan.Name.ValueString(),
					Description: plan.Description.ValueString(),
					Settings:    settings,
				},
			},
		},
	}
	tflog.Debug(ctx, "Updating content update policy", map[string]interface{}{"id": state.ID.ValueString()})
	_, err := r.client.ContentUpdatePolicies.UpdateContentUpdatePolicies(&policyParams)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating content update policy",
			"Could not update content update policy, unexpected error: "+err.Error(),
		)
		return
	}

	if !plan.Enabled.Equal(state.Enabled) {
		err = setPolicyEnabled(ctx, r.client, state.ID.ValueString(), plan.Enabled.ValueBool())
		if err != nil {
			resp.Diagnostics.AddError("Unable to update enabled state for content update policy", err.Error())
			return
		}
	}

	finalPolicy, err := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading content update policy after update", "Could not read content update policy "+state.ID.ValueString()+": "+err.Error())
		return
	}
	diags := plan.wrap(ctx, finalPolicy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the state.
func (r *contentUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state contentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Enabled.ValueBool() {
		tflog.Info(ctx, "Disabling content update policy before deletion", map[string]interface{}{"id": state.ID.ValueString()})
		err := setPolicyEnabled(ctx, r.client, state.ID.ValueString(), false)
		if err != nil {
			resp.Diagnostics.AddError("Unable to disable content update policy before deletion", err.Error())
			return
		}
	}

	tflog.Debug(ctx, "Deleting content update policy", map[string]interface{}{"id": state.ID.ValueString()})
	deleteParams := content_update_policies.DeleteContentUpdatePoliciesParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}
	_, err := r.client.ContentUpdatePolicies.DeleteContentUpdatePolicies(&deleteParams)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting content update policy",
			"Could not delete content update policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState imports the resource into the state.
func (r *contentUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func getContentUpdatePolicy(ctx context.Context, client *client.CrowdStrikeAPISpecification, policyId string) (*models.ContentUpdatePolicyV1, error) {
	res, err := client.ContentUpdatePolicies.GetContentUpdatePolicies(
		&content_update_policies.GetContentUpdatePoliciesParams{
			Context: ctx,
			Ids:     []string{policyId},
		},
	)
	if err != nil {
		return nil, err
	}
	return res.Payload.Resources[0], nil
}

func (d *contentUpdatePolicyResourceModel) wrap(ctx context.Context, policy *models.ContentUpdatePolicyV1) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)
	d.Name = types.StringValue(*policy.Name)

	if !d.Description.IsNull() || (policy.Description != nil && *policy.Description != "") {
		d.Description = types.StringValue(*policy.Description)
	}

	if policy.Enabled != nil {
		d.Enabled = types.BoolValue(*policy.Enabled)
	}

	if policy.Settings != nil {
		apiSettings := make(map[string]*models.ContentUpdateRingAssignmentSettingsV1)
		for _, s := range policy.Settings.RingAssignmentSettings {
			apiSettings[*s.ID] = s
		}

		populateBlock := func(ringID string) types.Object {
			apiSetting, ok := apiSettings[ringID]
			if !ok {
				return types.ObjectNull(ringAssignmentModel{}.AttributeTypes(ctx))
			}

			obj, diag := ringAssignmentSettingsToModel(ctx, apiSetting)
			diags.Append(diag...)
			return obj
		}

		d.SystemCritical = populateBlock("system_critical")
		d.SensorOperations = populateBlock("sensor_operations")
		d.RapidResponse = populateBlock("rapid_response_al_bl_listing")
		d.VulnerabilityManagement = populateBlock("vulnerability_management")
	}

	return diags
}

func ringAssignmentSettingsToModel(ctx context.Context, settings *models.ContentUpdateRingAssignmentSettingsV1) (types.Object, diag.Diagnostics) {
	var diags diag.Diagnostics
	if settings == nil {
		return types.ObjectNull(ringAssignmentModel{}.AttributeTypes(ctx)), diags
	}
	model := ringAssignmentModel{
		DeploymentRing: types.StringValue(*settings.RingAssignment),
		DelayHours:     types.StringValue(*settings.DelayHours),
	}

	obj, diag := types.ObjectValueFrom(ctx, ringAssignmentModel{}.AttributeTypes(ctx), model)
	diags.Append(diag...)
	return obj, diags
}

func planToSettings(ctx context.Context, plan contentUpdatePolicyResourceModel) (*models.ContentUpdateContentUpdateSettingsReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics
	var ringAssignments []*models.ContentUpdateRingAssignmentSettingsReqV1

	addRingAssignment := func(planRing types.Object, ringID string) {
		if !planRing.IsNull() && !planRing.IsUnknown() {
			var ringModel ringAssignmentModel
			diags.Append(planRing.As(ctx, &ringModel, basetypes.ObjectAsOptions{})...)
			if diags.HasError() {
				return
			}
			id := ringID
			delay := "0"
			if !ringModel.DelayHours.IsNull() && !ringModel.DelayHours.IsUnknown() {
				delay = ringModel.DelayHours.ValueString()
			}

			ringAssignments = append(ringAssignments, &models.ContentUpdateRingAssignmentSettingsReqV1{
				ID:             &id,
				DelayHours:     &delay,
				RingAssignment: ringModel.DeploymentRing.ValueStringPointer(),
			})
		}
	}

	addRingAssignment(plan.SystemCritical, "system_critical")
	addRingAssignment(plan.SensorOperations, "sensor_operations")
	addRingAssignment(plan.RapidResponse, "rapid_response_al_bl_listing")
	addRingAssignment(plan.VulnerabilityManagement, "vulnerability_management")

	if diags.HasError() {
		return nil, diags
	}

	return &models.ContentUpdateContentUpdateSettingsReqV1{
		RingAssignmentSettings: ringAssignments,
	}, diags
}

func setPolicyEnabled(ctx context.Context, client *client.CrowdStrikeAPISpecification, policyId string, enabled bool) error {
	action := "enable"
	if !enabled {
		action = "disable"
	}

	tflog.Info(ctx, "Setting content update policy enabled state via API", map[string]interface{}{"id": policyId, "action": action})
	_, err := client.ContentUpdatePolicies.PerformContentUpdatePoliciesAction(
		&content_update_policies.PerformContentUpdatePoliciesActionParams{
			ActionName: action,
			Context:    ctx,
			Body: &models.MsaEntityActionRequestV2{
				Ids: []string{
					policyId,
				},
			},
		},
	)

	if err != nil {
		return err
	}
	tflog.Info(ctx, "Successfully set content update policy enabled state", map[string]interface{}{"id": policyId, "action": action})

	return nil
}
