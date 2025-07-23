package sensorvisibilityexclusion

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
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
	_ resource.Resource                = &sensorVisibilityExclusionResource{}
	_ resource.ResourceWithConfigure   = &sensorVisibilityExclusionResource{}
	_ resource.ResourceWithImportState = &sensorVisibilityExclusionResource{}
)

var apiScopes = []scopes.Scope{
	{
		Name:  "Sensor Visibility Exclusions",
		Read:  true,
		Write: true,
	},
}

// NewSensorVisibilityExclusionResource is a helper function to simplify the provider implementation.
func NewSensorVisibilityExclusionResource() resource.Resource {
	return &sensorVisibilityExclusionResource{}
}

// sensorVisibilityExclusionResource is the resource implementation.
type sensorVisibilityExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

// SensorVisibilityExclusionResourceModel maps the resource schema data.
type SensorVisibilityExclusionResourceModel struct {
	ID                         types.String `tfsdk:"id"`
	Value                      types.String `tfsdk:"value"`
	ApplyToDescendantProcesses types.Bool   `tfsdk:"apply_to_descendant_processes"`
	Comment                    types.String `tfsdk:"comment"`
	HostGroups                 types.Set    `tfsdk:"host_groups"`
	RegexpValue                types.String `tfsdk:"regexp_value"`
	ValueHash                  types.String `tfsdk:"value_hash"`
	AppliedGlobally            types.Bool   `tfsdk:"applied_globally"`
	LastModified               types.String `tfsdk:"last_modified"`
	ModifiedBy                 types.String `tfsdk:"modified_by"`
	CreatedOn                  types.String `tfsdk:"created_on"`
	CreatedBy                  types.String `tfsdk:"created_by"`
	LastUpdated                types.String `tfsdk:"last_updated"`
}

// Configure adds the provider configured client to the resource.
func (r *sensorVisibilityExclusionResource) Configure(
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
func (r *sensorVisibilityExclusionResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_sensor_visibility_exclusion"
}

// Schema defines the schema for the resource.
func (r *sensorVisibilityExclusionResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Sensor Visibility Exclusion --- This resource allows you to manage sensor visibility exclusions in the CrowdStrike Falcon Platform.\n\n"+
				"**⚠️ SECURITY WARNING**: Sensor visibility exclusions stop all sensor event collection, detections, and preventions for the specified file paths. "+
				"Use with extreme caution as malware or attacks will not be recorded, detected, or prevented in excluded paths.\n\n%s",
			scopes.GenerateScopeDescription(apiScopes),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for the sensor visibility exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The RFC850 timestamp of the last update to this resource by Terraform.",
			},
			"value": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The file path or pattern to exclude from sensor visibility. Use wildcards (*) for pattern matching.",
			},
			"apply_to_descendant_processes": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether to apply the exclusion to all descendant processes spawned from the specified path. Defaults to `false`.",
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A comment or description for the exclusion.",
			},
			"host_groups": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "A set of host group IDs to apply this exclusion to. If not specified, the exclusion will be applied globally.",
				ElementType:         types.StringType,
			},
			"regexp_value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The regular expression representation of the exclusion value.",
			},
			"value_hash": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The hash of the exclusion value.",
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the exclusion is applied globally or to specific host groups.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the exclusion was last modified.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the exclusion.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when the exclusion was created.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the exclusion.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *sensorVisibilityExclusionResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Creating sensor visibility exclusion", map[string]any{
		"value":   plan.Value.ValueString(),
		"comment": plan.Comment.ValueString(),
	})

	// Build the groups slice
	var groups []string
	if !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown() {
		var groupsList []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &groupsList, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		groups = groupsList
	} else {
		// When no host groups are specified, apply globally using "all"
		groups = []string{"all"}
	}

	// Create the exclusion
	createReq := &models.SvExclusionsCreateReqV1{
		Value:               plan.Value.ValueString(),
		Comment:             plan.Comment.ValueString(),
		Groups:              groups,
		IsDescendantProcess: plan.ApplyToDescendantProcesses.ValueBool(),
	}

	params := sensor_visibility_exclusions.NewCreateSVExclusionsV1ParamsWithContext(ctx)
	params.SetBody(createReq)

	createResp, err := r.client.SensorVisibilityExclusions.CreateSVExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Sensor Visibility Exclusion",
			"An error occurred while creating the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}

	if createResp == nil || createResp.Payload == nil || len(createResp.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Unable to Create Sensor Visibility Exclusion",
			"An error occurred while creating the sensor visibility exclusion. No resource was returned.",
		)
		return
	}

	exclusion := createResp.Payload.Resources[0]

	// Map the response to the state
	plan.ID = types.StringValue(*exclusion.ID)
	plan.Value = types.StringValue(*exclusion.Value)
	plan.RegexpValue = types.StringValue(*exclusion.RegexpValue)
	plan.ValueHash = types.StringValue(*exclusion.ValueHash)
	plan.AppliedGlobally = types.BoolValue(*exclusion.AppliedGlobally)
	plan.LastModified = types.StringValue(exclusion.LastModified.String())
	plan.ModifiedBy = types.StringValue(*exclusion.ModifiedBy)
	plan.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	plan.CreatedBy = types.StringValue(*exclusion.CreatedBy)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Map groups back to host_groups, filtering out "all" for global exclusions
	if exclusion.Groups != nil && !*exclusion.AppliedGlobally {
		groupsSet, diags := types.SetValueFrom(ctx, types.StringType, exclusion.Groups)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.HostGroups = groupsSet
	} else {
		// For global exclusions, host_groups should be null/empty
		plan.HostGroups = types.SetNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *sensorVisibilityExclusionResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Reading sensor visibility exclusion", map[string]any{
		"id": state.ID.ValueString(),
	})

	// Get the exclusion
	params := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	getResp, err := r.client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Sensor Visibility Exclusion",
			"An error occurred while reading the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}

	if getResp == nil || getResp.Payload == nil || len(getResp.Payload.Resources) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	exclusion := getResp.Payload.Resources[0]

	// Map the response to the state
	state.ID = types.StringValue(*exclusion.ID)
	state.Value = types.StringValue(*exclusion.Value)
	state.RegexpValue = types.StringValue(*exclusion.RegexpValue)
	state.ValueHash = types.StringValue(*exclusion.ValueHash)
	state.AppliedGlobally = types.BoolValue(*exclusion.AppliedGlobally)
	state.LastModified = types.StringValue(exclusion.LastModified.String())
	state.ModifiedBy = types.StringValue(*exclusion.ModifiedBy)
	state.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	state.CreatedBy = types.StringValue(*exclusion.CreatedBy)

	// Map groups back to host_groups, filtering out "all" for global exclusions
	if exclusion.Groups != nil && !*exclusion.AppliedGlobally {
		groupsSet, diags := types.SetValueFrom(ctx, types.StringType, exclusion.Groups)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.HostGroups = groupsSet
	} else {
		// For global exclusions, host_groups should be null/empty
		state.HostGroups = types.SetNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *sensorVisibilityExclusionResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Updating sensor visibility exclusion", map[string]any{
		"id":    plan.ID.ValueString(),
		"value": plan.Value.ValueString(),
	})

	// Build the groups slice
	var groups []string
	if !plan.HostGroups.IsNull() && !plan.HostGroups.IsUnknown() {
		var groupsList []string
		resp.Diagnostics.Append(plan.HostGroups.ElementsAs(ctx, &groupsList, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		groups = groupsList
	} else {
		// When no host groups are specified, apply globally using "all"
		groups = []string{"all"}
	}

	// Update the exclusion
	id := plan.ID.ValueString()
	updateReq := &models.SvExclusionsUpdateReqV1{
		ID:                  &id,
		Value:               plan.Value.ValueString(),
		Comment:             plan.Comment.ValueString(),
		Groups:              groups,
		IsDescendantProcess: plan.ApplyToDescendantProcesses.ValueBool(),
	}

	params := sensor_visibility_exclusions.NewUpdateSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	params.SetBody(updateReq)

	updateResp, err := r.client.SensorVisibilityExclusions.UpdateSensorVisibilityExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Sensor Visibility Exclusion",
			"An error occurred while updating the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}

	if updateResp == nil || updateResp.Payload == nil || len(updateResp.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Unable to Update Sensor Visibility Exclusion",
			"An error occurred while updating the sensor visibility exclusion. No resource was returned.",
		)
		return
	}

	exclusion := updateResp.Payload.Resources[0]

	// Map the response to the state
	plan.ID = types.StringValue(*exclusion.ID)
	plan.Value = types.StringValue(*exclusion.Value)
	plan.RegexpValue = types.StringValue(*exclusion.RegexpValue)
	plan.ValueHash = types.StringValue(*exclusion.ValueHash)
	plan.AppliedGlobally = types.BoolValue(*exclusion.AppliedGlobally)
	plan.LastModified = types.StringValue(exclusion.LastModified.String())
	plan.ModifiedBy = types.StringValue(*exclusion.ModifiedBy)
	plan.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	plan.CreatedBy = types.StringValue(*exclusion.CreatedBy)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Map groups back to host_groups, filtering out "all" for global exclusions
	if exclusion.Groups != nil && !*exclusion.AppliedGlobally {
		groupsSet, diags := types.SetValueFrom(ctx, types.StringType, exclusion.Groups)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		plan.HostGroups = groupsSet
	} else {
		// For global exclusions, host_groups should be null/empty
		plan.HostGroups = types.SetNull(types.StringType)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *sensorVisibilityExclusionResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Deleting sensor visibility exclusion", map[string]any{
		"id": state.ID.ValueString(),
	})

	// Delete the exclusion
	params := sensor_visibility_exclusions.NewDeleteSensorVisibilityExclusionsV1ParamsWithContext(ctx)
	params.SetIds([]string{state.ID.ValueString()})

	_, err := r.client.SensorVisibilityExclusions.DeleteSensorVisibilityExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete Sensor Visibility Exclusion",
			"An error occurred while deleting the sensor visibility exclusion. "+
				"Original Error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *sensorVisibilityExclusionResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
