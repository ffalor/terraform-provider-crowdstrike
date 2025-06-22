package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &firewallPolicyResource{}
	_ resource.ResourceWithConfigure      = &firewallPolicyResource{}
	_ resource.ResourceWithImportState    = &firewallPolicyResource{}
	_ resource.ResourceWithValidateConfig = &firewallPolicyResource{}
)

// NewFirewallPolicyResource is a helper function to simplify the provider implementation.
func NewFirewallPolicyResource() resource.Resource {
	return &firewallPolicyResource{}
}

// firewallPolicyResource is the resource implementation.
type firewallPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firewallPolicyResourceModel describes the resource data model.
type firewallPolicyResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	PlatformName types.String `tfsdk:"platform_name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	HostGroups   types.Set    `tfsdk:"host_groups"`
	LastUpdated  types.String `tfsdk:"last_updated"`
}

// Configure adds the provider configured client to the resource.
func (r *firewallPolicyResource) Configure(
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
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *firewallPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy"
}

// Schema defines the schema for the resource.
func (r *firewallPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Firewall Policy Resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Firewall Policy ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Firewall Policy name",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Firewall Policy description",
			},
			"platform_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Operating system platform. Valid values: `Windows`, `Mac`, `Linux`",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether the firewall policy is enabled. Defaults to `false`",
			},
			"host_groups": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Host Groups to assign the firewall policy",
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of when the resource was last updated.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the firewall policy
	res, err := r.client.FirewallPolicies.CreateFirewallPolicies(
		&firewall_policies.CreateFirewallPoliciesParams{
			Context: ctx,
			Body: &models.FirewallCreateFirewallPoliciesReqV1{
				Resources: []*models.FirewallCreateFirewallPolicyReqV1{
					{
						Name:         plan.Name.ValueStringPointer(),
						Description:  plan.Description.ValueString(),
						PlatformName: plan.PlatformName.ValueStringPointer(),
					},
				},
			},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating firewall policy",
			"Could not create firewall policy, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating firewall policy",
			"No firewall policy returned from API",
		)
		return
	}

	firewallPolicy := res.Payload.Resources[0]
	plan.ID = types.StringValue(*firewallPolicy.ID)
	plan.Name = types.StringValue(*firewallPolicy.Name)
	plan.Description = types.StringValue(*firewallPolicy.Description)
	plan.PlatformName = types.StringValue(*firewallPolicy.PlatformName)
	plan.Enabled = types.BoolValue(*firewallPolicy.Enabled)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Enable the policy if requested
	if plan.Enabled.ValueBool() {
		_, err := r.client.FirewallPolicies.PerformFirewallPoliciesAction(
			&firewall_policies.PerformFirewallPoliciesActionParams{
				Context:    ctx,
				ActionName: "enable",
				Body: &models.MsaEntityActionRequestV2{
					Ids: []string{plan.ID.ValueString()},
				},
			},
		)

		if err != nil {
			resp.Diagnostics.AddError(
				"Error enabling firewall policy",
				"Could not enable firewall policy, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// Assign host groups if specified
	if !plan.HostGroups.IsNull() && len(plan.HostGroups.Elements()) > 0 {
		resp.Diagnostics.Append(r.assignHostGroups(ctx, plan.ID.ValueString(), plan.HostGroups)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *firewallPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state firewallPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the firewall policy
	res, err := r.client.FirewallPolicies.GetFirewallPolicies(
		&firewall_policies.GetFirewallPoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading firewall policy",
			"Could not read firewall policy, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, fmt.Sprintf("firewall policy %s not found, removing from state", state.ID.ValueString()))
		resp.State.RemoveResource(ctx)
		return
	}

	firewallPolicy := res.Payload.Resources[0]
	state.ID = types.StringValue(*firewallPolicy.ID)
	state.Name = types.StringValue(*firewallPolicy.Name)
	state.Description = types.StringValue(*firewallPolicy.Description)
	state.PlatformName = types.StringValue(*firewallPolicy.PlatformName)
	state.Enabled = types.BoolValue(*firewallPolicy.Enabled)

	// Get assigned host groups - for now use empty set as this requires more complex logic
	emptySet, setDiags := types.SetValueFrom(ctx, types.StringType, []string{})
	resp.Diagnostics.Append(setDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.HostGroups = emptySet

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *firewallPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan firewallPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state firewallPolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the firewall policy
	res, err := r.client.FirewallPolicies.UpdateFirewallPolicies(
		&firewall_policies.UpdateFirewallPoliciesParams{
			Context: ctx,
			Body: &models.FirewallUpdateFirewallPoliciesReqV1{
				Resources: []*models.FirewallUpdateFirewallPolicyReqV1{
					{
						ID:          plan.ID.ValueStringPointer(),
						Name:        plan.Name.ValueString(),
						Description: plan.Description.ValueString(),
					},
				},
			},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating firewall policy",
			"Could not update firewall policy, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error updating firewall policy",
			"No firewall policy returned from API",
		)
		return
	}

	firewallPolicy := res.Payload.Resources[0]
	plan.ID = types.StringValue(*firewallPolicy.ID)
	plan.Name = types.StringValue(*firewallPolicy.Name)
	plan.Description = types.StringValue(*firewallPolicy.Description)
	plan.PlatformName = types.StringValue(*firewallPolicy.PlatformName)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Handle enabled state changes
	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		action := "disable"
		if plan.Enabled.ValueBool() {
			action = "enable"
		}

		_, err := r.client.FirewallPolicies.PerformFirewallPoliciesAction(
			&firewall_policies.PerformFirewallPoliciesActionParams{
				Context:    ctx,
				ActionName: action,
				Body: &models.MsaEntityActionRequestV2{
					Ids: []string{plan.ID.ValueString()},
				},
			},
		)

		if err != nil {
			resp.Diagnostics.AddError(
				fmt.Sprintf("Error %sing firewall policy", action),
				fmt.Sprintf("Could not %s firewall policy, unexpected error: %s", action, err.Error()),
			)
			return
		}
	}

	plan.Enabled = types.BoolValue(*firewallPolicy.Enabled)

	// Handle host group changes
	resp.Diagnostics.Append(r.syncHostGroups(ctx, plan.ID.ValueString(), state.HostGroups, plan.HostGroups)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *firewallPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state firewallPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Remove all host group assignments first
	if !state.HostGroups.IsNull() && len(state.HostGroups.Elements()) > 0 {
		emptySet, _ := types.SetValueFrom(ctx, types.StringType, []string{})
		resp.Diagnostics.Append(r.syncHostGroups(ctx, state.ID.ValueString(), state.HostGroups, emptySet)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Delete the firewall policy
	_, err := r.client.FirewallPolicies.DeleteFirewallPolicies(
		&firewall_policies.DeleteFirewallPoliciesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting firewall policy",
			"Could not delete firewall policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *firewallPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply
// validate resource is configured as expected.
func (r *firewallPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config firewallPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)
}

// assignHostGroups assigns host groups to the firewall policy
func (r *firewallPolicyResource) assignHostGroups(ctx context.Context, policyID string, hostGroups types.Set) diag.Diagnostics {
	var diags diag.Diagnostics
	var hostGroupList []string

	if !hostGroups.IsNull() {
		diags.Append(hostGroups.ElementsAs(ctx, &hostGroupList, false)...)
		if diags.HasError() {
			return diags
		}
	}

	for _, groupID := range hostGroupList {
		_, err := r.client.FirewallPolicies.PerformFirewallPoliciesAction(
			&firewall_policies.PerformFirewallPoliciesActionParams{
				Context:    ctx,
				ActionName: "add-host-group",
				Body: &models.MsaEntityActionRequestV2{
					ActionParameters: []*models.MsaspecActionParameter{
						{
							Name:  stringPtr("group_id"),
							Value: &groupID,
						},
					},
					Ids: []string{policyID},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error assigning host group to firewall policy",
				fmt.Sprintf("Could not assign host group %s to firewall policy %s: %s", groupID, policyID, err.Error()),
			)
		}
	}

	return diags
}

// syncHostGroups synchronizes host group assignments
func (r *firewallPolicyResource) syncHostGroups(ctx context.Context, policyID string, oldGroups, newGroups types.Set) diag.Diagnostics {
	var diags diag.Diagnostics

	// Get groups to add and remove
	groupsToAdd, groupsToRemove, syncDiags := utils.SetIDsToModify(ctx, newGroups, oldGroups)
	diags.Append(syncDiags...)
	if diags.HasError() {
		return diags
	}

	// Remove groups
	for _, groupID := range groupsToRemove {
		_, err := r.client.FirewallPolicies.PerformFirewallPoliciesAction(
			&firewall_policies.PerformFirewallPoliciesActionParams{
				Context:    ctx,
				ActionName: "remove-host-group",
				Body: &models.MsaEntityActionRequestV2{
					ActionParameters: []*models.MsaspecActionParameter{
						{
							Name:  stringPtr("group_id"),
							Value: &groupID,
						},
					},
					Ids: []string{policyID},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error removing host group from firewall policy",
				fmt.Sprintf("Could not remove host group %s from firewall policy %s: %s", groupID, policyID, err.Error()),
			)
		}
	}

	// Add groups
	for _, groupID := range groupsToAdd {
		_, err := r.client.FirewallPolicies.PerformFirewallPoliciesAction(
			&firewall_policies.PerformFirewallPoliciesActionParams{
				Context:    ctx,
				ActionName: "add-host-group",
				Body: &models.MsaEntityActionRequestV2{
					ActionParameters: []*models.MsaspecActionParameter{
						{
							Name:  stringPtr("group_id"),
							Value: &groupID,
						},
					},
					Ids: []string{policyID},
				},
			},
		)

		if err != nil {
			diags.AddError(
				"Error adding host group to firewall policy",
				fmt.Sprintf("Could not add host group %s to firewall policy %s: %s", groupID, policyID, err.Error()),
			)
		}
	}

	return diags
}

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}