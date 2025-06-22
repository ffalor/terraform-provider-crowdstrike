package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
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
	_ resource.Resource                = &firewallRuleGroupResource{}
	_ resource.ResourceWithConfigure   = &firewallRuleGroupResource{}
	_ resource.ResourceWithImportState = &firewallRuleGroupResource{}
)

// NewFirewallRuleGroupResource is a helper function to simplify the provider implementation.
func NewFirewallRuleGroupResource() resource.Resource {
	return &firewallRuleGroupResource{}
}

// firewallRuleGroupResource is the resource implementation.
type firewallRuleGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firewallRuleGroupResourceModel describes the resource data model.
type firewallRuleGroupResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	PlatformName types.String `tfsdk:"platform_name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Rules        types.Set    `tfsdk:"rules"`
	LastUpdated  types.String `tfsdk:"last_updated"`
}

// Configure adds the provider configured client to the resource.
func (r *firewallRuleGroupResource) Configure(
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
func (r *firewallRuleGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule_group"
}

// Schema defines the schema for the resource.
func (r *firewallRuleGroupResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Firewall Rule Group Resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Firewall Rule Group ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Firewall Rule Group name",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Firewall Rule Group description",
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
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Whether the firewall rule group is enabled. Defaults to `true`",
			},
			"rules": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "List of firewall rule IDs in this rule group",
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of when the resource was last updated.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallRuleGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallRuleGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the firewall rule group
	res, err := r.client.FirewallManagement.CreateRuleGroup(
		&firewall_management.CreateRuleGroupParams{
			Context: ctx,
			Body: &models.FwmgrAPIRuleGroupCreateRequestV1{
				Description:  plan.Description.ValueStringPointer(),
				Enabled:      plan.Enabled.ValueBoolPointer(),
				Name:         plan.Name.ValueStringPointer(),
				Platform:     plan.PlatformName.ValueStringPointer(),
			},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating firewall rule group",
			"Could not create firewall rule group, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating firewall rule group",
			"No firewall rule group ID returned from API",
		)
		return
	}

	plan.ID = types.StringValue(res.Payload.Resources[0])
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// If rules are specified, update the rule group to include them
	if !plan.Rules.IsNull() && len(plan.Rules.Elements()) > 0 {
		resp.Diagnostics.Append(r.updateRuleGroupRules(ctx, plan.ID.ValueString(), plan.Rules)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *firewallRuleGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state firewallRuleGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the firewall rule group
	res, err := r.client.FirewallManagement.GetRuleGroups(
		&firewall_management.GetRuleGroupsParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading firewall rule group",
			"Could not read firewall rule group, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, fmt.Sprintf("firewall rule group %s not found, removing from state", state.ID.ValueString()))
		resp.State.RemoveResource(ctx)
		return
	}

	ruleGroup := res.Payload.Resources[0]
	state.ID = types.StringValue(*ruleGroup.ID)
	state.Name = types.StringValue(*ruleGroup.Name)
	state.Description = types.StringValue(*ruleGroup.Description)
	state.PlatformName = types.StringValue(*ruleGroup.Platform)
	state.Enabled = types.BoolValue(*ruleGroup.Enabled)

	// Get rules in the rule group
	if ruleGroup.RuleIds != nil && len(ruleGroup.RuleIds) > 0 {
		rulesSet, setDiags := types.SetValueFrom(ctx, types.StringType, ruleGroup.RuleIds)
		resp.Diagnostics.Append(setDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Rules = rulesSet
	} else {
		emptySet, setDiags := types.SetValueFrom(ctx, types.StringType, []string{})
		resp.Diagnostics.Append(setDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Rules = emptySet
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *firewallRuleGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan firewallRuleGroupResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state firewallRuleGroupResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the firewall rule group
	_, err := r.client.FirewallManagement.UpdateRuleGroup(
		&firewall_management.UpdateRuleGroupParams{
			Context: ctx,
			Body: &models.FwmgrAPIRuleGroupModifyRequestV1{
				ID: plan.ID.ValueStringPointer(),
			},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating firewall rule group",
			"Could not update firewall rule group, unexpected error: "+err.Error(),
		)
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Handle rule changes if needed
	if !plan.Rules.Equal(state.Rules) {
		resp.Diagnostics.Append(r.updateRuleGroupRules(ctx, plan.ID.ValueString(), plan.Rules)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *firewallRuleGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state firewallRuleGroupResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the firewall rule group
	_, err := r.client.FirewallManagement.DeleteRuleGroups(
		&firewall_management.DeleteRuleGroupsParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting firewall rule group",
			"Could not delete firewall rule group, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *firewallRuleGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// updateRuleGroupRules updates the rules in a rule group
func (r *firewallRuleGroupResource) updateRuleGroupRules(ctx context.Context, ruleGroupID string, rules types.Set) diag.Diagnostics {
	var diags diag.Diagnostics

	if rules.IsNull() {
		return diags
	}

	var rulesList []string
	diags.Append(rules.ElementsAs(ctx, &rulesList, false)...)
	if diags.HasError() {
		return diags
	}

	// Update the rule group with the new rule IDs
	_, err := r.client.FirewallManagement.UpdateRuleGroup(
		&firewall_management.UpdateRuleGroupParams{
			Context: ctx,
			Body: &models.FwmgrAPIRuleGroupModifyRequestV1{
				ID:      &ruleGroupID,
				RuleIds: rulesList,
			},
		},
	)

	if err != nil {
		diags.AddError(
			"Error updating firewall rule group rules",
			fmt.Sprintf("Could not update rules for firewall rule group %s: %s", ruleGroupID, err.Error()),
		)
	}

	return diags
}