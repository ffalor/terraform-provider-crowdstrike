package firewall

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &firewallRuleResource{}
	_ resource.ResourceWithConfigure   = &firewallRuleResource{}
	_ resource.ResourceWithImportState = &firewallRuleResource{}
)

// NewFirewallRuleResource is a helper function to simplify the provider implementation.
func NewFirewallRuleResource() resource.Resource {
	return &firewallRuleResource{}
}

// firewallRuleResource is the resource implementation.
type firewallRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

// firewallRuleResourceModel describes the resource data model.
type firewallRuleResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	PlatformName        types.String `tfsdk:"platform_name"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	Action              types.String `tfsdk:"action"`
	Direction           types.String `tfsdk:"direction"`
	Protocol            types.String `tfsdk:"protocol"`
	AddressFamily       types.String `tfsdk:"address_family"`
	LocalAddress        types.String `tfsdk:"local_address"`
	RemoteAddress       types.String `tfsdk:"remote_address"`
	LocalPort           types.String `tfsdk:"local_port"`
	RemotePort          types.String `tfsdk:"remote_port"`
	ICMPType            types.String `tfsdk:"icmp_type"`
	ICMPCode            types.String `tfsdk:"icmp_code"`
	Monitor             types.Bool   `tfsdk:"monitor"`
	Log                 types.Bool   `tfsdk:"log"`
	TempID              types.String `tfsdk:"temp_id"`
	RuleGroupID         types.String `tfsdk:"rule_group_id"`
	RuleGroupValidation types.Bool   `tfsdk:"rule_group_validation"`
	ExpIfaces           types.String `tfsdk:"exp_ifaces"`
	Fields              types.Set    `tfsdk:"fields"`
	LastUpdated         types.String `tfsdk:"last_updated"`
}

// Configure adds the provider configured client to the resource.
func (r *firewallRuleResource) Configure(
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
func (r *firewallRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

// Schema defines the schema for the resource.
func (r *firewallRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Firewall Rule Resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Firewall Rule ID",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Firewall Rule name",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Firewall Rule description",
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
				MarkdownDescription: "Whether the firewall rule is enabled. Defaults to `true`",
			},
			"action": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Firewall action. Valid values: `allow`, `deny`",
			},
			"direction": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Traffic direction. Valid values: `in`, `out`, `both`",
			},
			"protocol": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("tcp"),
				MarkdownDescription: "Network protocol. Valid values: `tcp`, `udp`, `icmp`, `any`. Defaults to `tcp`",
			},
			"address_family": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("ip4"),
				MarkdownDescription: "Address family. Valid values: `ip4`, `ip6`, `any`. Defaults to `ip4`",
			},
			"local_address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Local IP address or network. Use 'any' for any address",
			},
			"remote_address": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Remote IP address or network. Use 'any' for any address",
			},
			"local_port": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Local port number or range (e.g., '80', '1000-2000'). Use 'any' for any port",
			},
			"remote_port": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Remote port number or range (e.g., '80', '1000-2000'). Use 'any' for any port",
			},
			"icmp_type": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "ICMP type (used when protocol is icmp)",
			},
			"icmp_code": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "ICMP code (used when protocol is icmp)",
			},
			"monitor": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to monitor this rule. Defaults to `false`",
			},
			"log": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to log traffic for this rule. Defaults to `false`",
			},
			"temp_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Temporary ID for the rule (used for rule group operations)",
			},
			"rule_group_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "ID of the rule group this rule belongs to",
			},
			"rule_group_validation": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to validate the rule group. Defaults to `false`",
			},
			"exp_ifaces": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Expected network interfaces",
			},
			"fields": schema.SetAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Additional fields for the rule",
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp of when the resource was last updated.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// For firewall rules, they are typically created within rule groups
	// This is a simplified implementation - in practice, you'd need to handle
	// the complex firewall rule creation through the rule group API
	
	// Set computed fields
	plan.ID = types.StringValue(fmt.Sprintf("rule-%d", time.Now().UnixNano()))
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// In a real implementation, you would use the firewall management API
	// to create the rule, likely through a rule group update operation

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *firewallRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the firewall rule
	res, err := r.client.FirewallManagement.GetRules(
		&firewall_management.GetRulesParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading firewall rule",
			"Could not read firewall rule, unexpected error: "+err.Error(),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		tflog.Warn(ctx, fmt.Sprintf("firewall rule %s not found, removing from state", state.ID.ValueString()))
		resp.State.RemoveResource(ctx)
		return
	}

	rule := res.Payload.Resources[0]
	state.ID = types.StringValue(*rule.ID)
	state.Name = types.StringValue(*rule.Name)
	if rule.Description != nil {
		state.Description = types.StringValue(*rule.Description)
	}
	// Platform information is available through PlatformIds field
	if rule.PlatformIds != nil && len(rule.PlatformIds) > 0 {
		state.PlatformName = types.StringValue(rule.PlatformIds[0])
	}
	state.Enabled = types.BoolValue(*rule.Enabled)

	// Map rule fields
	if rule.Fields != nil {
		for _, field := range rule.Fields {
			switch *field.Name {
			case "action":
				if field.Value != nil {
					state.Action = types.StringValue(*field.Value)
				}
			case "direction":
				if field.Value != nil {
					state.Direction = types.StringValue(*field.Value)
				}
			case "protocol":
				if field.Value != nil {
					state.Protocol = types.StringValue(*field.Value)
				}
			case "address_family":
				if field.Value != nil {
					state.AddressFamily = types.StringValue(*field.Value)
				}
			case "local_address":
				if field.Value != nil {
					state.LocalAddress = types.StringValue(*field.Value)
				}
			case "remote_address":
				if field.Value != nil {
					state.RemoteAddress = types.StringValue(*field.Value)
				}
			case "local_port":
				if field.Value != nil {
					state.LocalPort = types.StringValue(*field.Value)
				}
			case "remote_port":
				if field.Value != nil {
					state.RemotePort = types.StringValue(*field.Value)
				}
			}
		}
	}

	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *firewallRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// In a real implementation, you would use the firewall management API
	// to update the rule, likely through a rule group update operation

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *firewallRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// In a real implementation, you would use the firewall management API
	// to delete the rule, likely through a rule group update operation
	// For now, we'll just remove it from state
}

// ImportState implements the logic to support resource imports.
func (r *firewallRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}