package sensorvisibilityexclusion

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
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
	ID              types.String `tfsdk:"id"`
	Value           types.String `tfsdk:"value"`
	Groups          types.Set    `tfsdk:"groups"`
	Comment         types.String `tfsdk:"comment"`
	RegexpValue     types.String `tfsdk:"regexp_value"`
	ValueHash       types.String `tfsdk:"value_hash"`
	AppliedGlobally types.Bool   `tfsdk:"applied_globally"`
	LastModified    types.String `tfsdk:"last_modified"`
	CreatedOn       types.String `tfsdk:"created_on"`
	ModifiedBy      types.String `tfsdk:"modified_by"`
	CreatedBy       types.String `tfsdk:"created_by"`
	LastUpdated     types.String `tfsdk:"last_updated"`
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
			"Sensor Visibility Exclusion --- This resource allows you to manage sensor visibility exclusions in the CrowdStrike Falcon Platform. "+
				"Sensor visibility exclusions allow you to exclude specific files or processes from sensor monitoring.\n\n%s",
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
				MarkdownDescription: "The file path pattern to exclude from sensor monitoring.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"groups": schema.SetAttribute{
				Optional:            true,
				MarkdownDescription: "A set of host group IDs to apply the exclusion to. Use [\"all\"] to apply globally to all host groups.",
				ElementType:         types.StringType,
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A descriptive comment about the sensor visibility exclusion.",
			},
			"regexp_value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The regular expression version of the exclusion value.",
			},
			"value_hash": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Hash of the exclusion value.",
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the exclusion is applied globally to all host groups.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the exclusion was last modified.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the exclusion was created.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who last modified the exclusion.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "User who created the exclusion.",
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

	// Convert groups set to string slice
	var groups []string
	if !plan.Groups.IsNull() && !plan.Groups.IsUnknown() {
		resp.Diagnostics.Append(plan.Groups.ElementsAs(ctx, &groups, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	createParams := sensor_visibility_exclusions.CreateSVExclusionsV1Params{
		Context: ctx,
		Body: &models.SvExclusionsCreateReqV1{
			Value:   plan.Value.ValueString(),
			Groups:  groups,
			Comment: plan.Comment.ValueString(),
		},
	}

	tflog.Debug(ctx, "Creating sensor visibility exclusion", map[string]any{
		"value":   plan.Value.ValueString(),
		"groups":  groups,
		"comment": plan.Comment.ValueString(),
	})

	exclusion, err := r.client.SensorVisibilityExclusions.CreateSVExclusionsV1(&createParams)
	if err != nil {
		errMsg := fmt.Sprintf(
			"Could not create sensor visibility exclusion (%s): %s",
			plan.Value.ValueString(),
			err.Error(),
		)
		if strings.Contains(err.Error(), "409") {
			errMsg = fmt.Sprintf(
				"Could not create sensor visibility exclusion (%s): An exclusion with this value may already exist.\n\n%s",
				plan.Value.ValueString(),
				err.Error(),
			)
		}

		resp.Diagnostics.AddError("Error creating sensor visibility exclusion", errMsg)
		return
	}

	if exclusion == nil || exclusion.Payload == nil || len(exclusion.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating sensor visibility exclusion",
			"API returned empty response",
		)
		return
	}

	exclusionResource := exclusion.Payload.Resources[0]
	r.mapExclusionToModel(exclusionResource, &plan)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
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

	exclusion, err := r.client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(
		&sensor_visibility_exclusions.GetSensorVisibilityExclusionsV1Params{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		if strings.Contains(err.Error(), "404") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading CrowdStrike sensor visibility exclusion",
			"Could not read CrowdStrike sensor visibility exclusion: "+state.ID.ValueString()+": "+err.Error(),
		)
		return
	}

	if exclusion == nil || exclusion.Payload == nil || len(exclusion.Payload.Resources) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	exclusionResource := exclusion.Payload.Resources[0]
	r.mapSvExclusionToModel(exclusionResource, &state)

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

	// Convert groups set to string slice
	var groups []string
	if !plan.Groups.IsNull() && !plan.Groups.IsUnknown() {
		resp.Diagnostics.Append(plan.Groups.ElementsAs(ctx, &groups, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	updateParams := sensor_visibility_exclusions.UpdateSensorVisibilityExclusionsV1Params{
		Context: ctx,
		Body: &models.SvExclusionsUpdateReqV1{
			ID:      plan.ID.ValueStringPointer(),
			Value:   plan.Value.ValueString(),
			Groups:  groups,
			Comment: plan.Comment.ValueString(),
		},
	}

	tflog.Debug(ctx, "Updating sensor visibility exclusion", map[string]any{
		"id":      plan.ID.ValueString(),
		"value":   plan.Value.ValueString(),
		"groups":  groups,
		"comment": plan.Comment.ValueString(),
	})

	exclusion, err := r.client.SensorVisibilityExclusions.UpdateSensorVisibilityExclusionsV1(&updateParams)
	if err != nil {
		errMsg := fmt.Sprintf(
			"Could not update sensor visibility exclusion (%s): %s",
			plan.ID.ValueString(),
			err.Error(),
		)
		if strings.Contains(err.Error(), "409") {
			errMsg = fmt.Sprintf(
				"Could not update sensor visibility exclusion (%s): An exclusion with this value may already exist.\n\n%s",
				plan.ID.ValueString(),
				err.Error(),
			)
		}

		resp.Diagnostics.AddError("Error updating sensor visibility exclusion", errMsg)
		return
	}

	if exclusion == nil || exclusion.Payload == nil || len(exclusion.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error updating sensor visibility exclusion",
			"API returned empty response",
		)
		return
	}

	exclusionResource := exclusion.Payload.Resources[0]
	r.mapSvExclusionToModel(exclusionResource, &plan)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
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

	_, err := r.client.SensorVisibilityExclusions.DeleteSensorVisibilityExclusionsV1(
		&sensor_visibility_exclusions.DeleteSensorVisibilityExclusionsV1Params{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)

	if err != nil {
		if !strings.Contains(err.Error(), "404") {
			resp.Diagnostics.AddError(
				"Error deleting CrowdStrike sensor visibility exclusion",
				"Could not delete sensor visibility exclusion, unexpected error: "+err.Error(),
			)
		}
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

// mapExclusionToModel maps API response data from ExclusionsExclusionV1 to the resource model.
func (r *sensorVisibilityExclusionResource) mapExclusionToModel(
	exclusion *models.ExclusionsExclusionV1,
	model *SensorVisibilityExclusionResourceModel,
) {
	if exclusion.ID != nil {
		model.ID = types.StringValue(*exclusion.ID)
	}

	if exclusion.Value != nil {
		model.Value = types.StringValue(*exclusion.Value)
	}

	// Note: ExclusionsExclusionV1 doesn't have a Comment field, so we leave it as is
	// model.Comment will retain its current value

	if exclusion.RegexpValue != nil {
		model.RegexpValue = types.StringValue(*exclusion.RegexpValue)
	}

	if exclusion.ValueHash != nil {
		model.ValueHash = types.StringValue(*exclusion.ValueHash)
	}

	if exclusion.AppliedGlobally != nil {
		model.AppliedGlobally = types.BoolValue(*exclusion.AppliedGlobally)
	}

	if exclusion.LastModified != nil {
		model.LastModified = types.StringValue(exclusion.LastModified.String())
	}

	if exclusion.CreatedOn != nil {
		model.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	}

	if exclusion.ModifiedBy != nil {
		model.ModifiedBy = types.StringValue(*exclusion.ModifiedBy)
	}

	if exclusion.CreatedBy != nil {
		model.CreatedBy = types.StringValue(*exclusion.CreatedBy)
	}

	// Handle groups
	if len(exclusion.Groups) > 0 {
		groupStrings := make([]types.String, 0, len(exclusion.Groups))
		for _, group := range exclusion.Groups {
			if group.ID != nil {
				groupStrings = append(groupStrings, types.StringValue(*group.ID))
			}
		}
		groupsSet, _ := types.SetValueFrom(context.Background(), types.StringType, groupStrings)
		model.Groups = groupsSet
	}
}

// mapSvExclusionToModel maps API response data from SvExclusionsSVExclusionV1 to the resource model.
func (r *sensorVisibilityExclusionResource) mapSvExclusionToModel(
	exclusion *models.SvExclusionsSVExclusionV1,
	model *SensorVisibilityExclusionResourceModel,
) {
	if exclusion.ID != nil {
		model.ID = types.StringValue(*exclusion.ID)
	}

	if exclusion.Value != nil {
		model.Value = types.StringValue(*exclusion.Value)
	}

	// Note: SvExclusionsSVExclusionV1 doesn't have a Comment field, so we leave it as is
	// model.Comment will retain its current value

	if exclusion.RegexpValue != nil {
		model.RegexpValue = types.StringValue(*exclusion.RegexpValue)
	}

	if exclusion.ValueHash != nil {
		model.ValueHash = types.StringValue(*exclusion.ValueHash)
	}

	if exclusion.AppliedGlobally != nil {
		model.AppliedGlobally = types.BoolValue(*exclusion.AppliedGlobally)
	}

	if exclusion.LastModified != nil {
		model.LastModified = types.StringValue(exclusion.LastModified.String())
	}

	if exclusion.CreatedOn != nil {
		model.CreatedOn = types.StringValue(exclusion.CreatedOn.String())
	}

	if exclusion.ModifiedBy != nil {
		model.ModifiedBy = types.StringValue(*exclusion.ModifiedBy)
	}

	if exclusion.CreatedBy != nil {
		model.CreatedBy = types.StringValue(*exclusion.CreatedBy)
	}

	// Handle groups
	if len(exclusion.Groups) > 0 {
		groupStrings := make([]types.String, 0, len(exclusion.Groups))
		for _, group := range exclusion.Groups {
			if group.ID != nil {
				groupStrings = append(groupStrings, types.StringValue(*group.ID))
			}
		}
		groupsSet, _ := types.SetValueFrom(context.Background(), types.StringType, groupStrings)
		model.Groups = groupsSet
	}
}
