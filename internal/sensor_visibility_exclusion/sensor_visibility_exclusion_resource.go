package sensorvisibilityexclusion

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_visibility_exclusions"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &sensorVisibilityExclusionResource{}
var _ resource.ResourceWithConfigure = &sensorVisibilityExclusionResource{}
var _ resource.ResourceWithImportState = &sensorVisibilityExclusionResource{}

func NewSensorVisibilityExclusionResource() resource.Resource {
	return &sensorVisibilityExclusionResource{}
}

type sensorVisibilityExclusionResource struct {
	client *client.CrowdStrikeAPISpecification
}

type SensorVisibilityExclusionResourceModel struct {
	ID                  types.String `tfsdk:"id"`
	Value               types.String `tfsdk:"value"`
	Comment             types.String `tfsdk:"comment"`
	IsDescendantProcess types.Bool   `tfsdk:"is_descendant_process"`
	Groups              types.Set    `tfsdk:"groups"`
	RegexpValue         types.String `tfsdk:"regexp_value"`
	AppliedGlobally     types.Bool   `tfsdk:"applied_globally"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedOn           types.String `tfsdk:"created_on"`
	ModifiedBy          types.String `tfsdk:"modified_by"`
	LastModified        types.String `tfsdk:"last_modified"`
}

func (r *sensorVisibilityExclusionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sensor_visibility_exclusion"
}

func (r *sensorVisibilityExclusionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Sensor Visibility Exclusion resource for CrowdStrike Falcon.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for the exclusion.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"value": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The value to exclude.",
			},
			"comment": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A comment for the exclusion. Note: This field can only be set during creation and will force replacement if changed.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},

			"is_descendant_process": schema.BoolAttribute{
				Optional:            true,
				MarkdownDescription: "Whether the exclusion applies to descendant processes.",
			},
			"groups": schema.SetAttribute{
				Required:            true,
				MarkdownDescription: "A set of host group IDs to which this exclusion applies.",
				ElementType:         types.StringType,
			},
			"regexp_value": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The regular expression value for the exclusion.",
			},
			"applied_globally": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the exclusion is applied globally.",
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created the exclusion.",
			},
			"created_on": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The creation timestamp.",
			},
			"modified_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last modified the exclusion.",
			},
			"last_modified": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The last modification timestamp.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *sensorVisibilityExclusionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *sensorVisibilityExclusionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...) // Unmarshal plan
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := &models.SvExclusionsCreateReqV1{
		Value:               plan.Value.ValueString(),
		Comment:             plan.Comment.ValueString(),
		IsDescendantProcess: plan.IsDescendantProcess.ValueBool(),
		Groups:              setToStringSlice(plan.Groups),
	}

	params := sensor_visibility_exclusions.NewCreateSVExclusionsV1Params().WithContext(ctx).WithBody(createReq)
	result, err := r.client.SensorVisibilityExclusions.CreateSVExclusionsV1(params)

	// Handle the case where the API returns 201 (success) but gofalcon treats it as an error
	if err != nil {
		// Check if the error message indicates a 201 status (success)
		if strings.Contains(err.Error(), "status 201") {
			// The API call was successful, we just need to find the created exclusion
			// Query for the exclusion by value to get its ID
			queryParams := sensor_visibility_exclusions.NewQuerySensorVisibilityExclusionsV1Params().WithContext(ctx)
			queryResult, err := r.client.SensorVisibilityExclusions.QuerySensorVisibilityExclusionsV1(queryParams)
			if err != nil {
				resp.Diagnostics.AddError("Error querying sensor visibility exclusions", err.Error())
				return
			}

			// Get all exclusions to find the one with matching value
			if len(queryResult.Payload.Resources) > 0 {
				getParams := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1Params().WithContext(ctx).WithIds(queryResult.Payload.Resources)
				getResult, err := r.client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(getParams)
				if err != nil {
					resp.Diagnostics.AddError("Error getting sensor visibility exclusions", err.Error())
					return
				}

				// Find the exclusion with matching value
				for _, exclusion := range getResult.Payload.Resources {
					if exclusion.Value != nil && *exclusion.Value == plan.Value.ValueString() {
						plan.ID = types.StringPointerValue(exclusion.ID)
						// Read back the resource to populate all fields
						readExclusion(ctx, r, exclusion.ID, &plan, &resp.Diagnostics)
						resp.State.Set(ctx, &plan)
						return
					}
				}
			}

			resp.Diagnostics.AddError("Error creating sensor visibility exclusion", "Created exclusion not found in query results")
			return
		}

		resp.Diagnostics.AddError("Error creating sensor visibility exclusion", err.Error())
		return
	}

	// Handle normal success case (200 status)
	var id *string
	if result.Payload != nil && len(result.Payload.Resources) > 0 {
		id = result.Payload.Resources[0].ID
	} else {
		resp.Diagnostics.AddError("Error creating sensor visibility exclusion", "No resources returned in response")
		return
	}

	plan.ID = types.StringPointerValue(id)
	// Read back the resource to populate all fields
	readExclusion(ctx, r, id, &plan, &resp.Diagnostics)
	resp.State.Set(ctx, &plan)
}

// Read refreshes the Terraform state with the latest data.
func (r *sensorVisibilityExclusionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...) // Unmarshal state
	if resp.Diagnostics.HasError() {
		return
	}
	if state.ID.IsUnknown() || state.ID.IsNull() {
		resp.Diagnostics.AddError("Missing ID", "Cannot read resource without ID")
		return
	}

	// Preserve the comment from state since it's not returned by the API
	comment := state.Comment

	readExclusion(ctx, r, state.ID.ValueStringPointer(), &state, &resp.Diagnostics)

	// Restore the comment from the original state
	state.Comment = comment

	resp.State.Set(ctx, &state)
}

// Update updates the resource and sets the updated Terraform state.
func (r *sensorVisibilityExclusionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...) // Unmarshal plan
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.ID.IsUnknown() || plan.ID.IsNull() {
		resp.Diagnostics.AddError("Missing ID", "Cannot update resource without ID")
		return
	}
	updateReq := &models.SvExclusionsUpdateReqV1{
		ID:                  plan.ID.ValueStringPointer(),
		Value:               plan.Value.ValueString(),
		Comment:             plan.Comment.ValueString(),
		IsDescendantProcess: plan.IsDescendantProcess.ValueBool(),
		Groups:              setToStringSlice(plan.Groups),
	}
	params := sensor_visibility_exclusions.NewUpdateSensorVisibilityExclusionsV1Params().WithContext(ctx).WithBody(updateReq)
	result, err := r.client.SensorVisibilityExclusions.UpdateSensorVisibilityExclusionsV1(params)
	if err != nil || len(result.Payload.Resources) == 0 {
		resp.Diagnostics.AddError("Error updating sensor visibility exclusion", errMsg(err, result))
		return
	}
	readExclusion(ctx, r, plan.ID.ValueStringPointer(), &plan, &resp.Diagnostics)
	resp.State.Set(ctx, &plan)
}

// Delete deletes the resource and removes the Terraform state.
func (r *sensorVisibilityExclusionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state SensorVisibilityExclusionResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...) // Unmarshal state
	if resp.Diagnostics.HasError() {
		return
	}
	if state.ID.IsUnknown() || state.ID.IsNull() {
		resp.Diagnostics.AddError("Missing ID", "Cannot delete resource without ID")
		return
	}
	params := sensor_visibility_exclusions.NewDeleteSensorVisibilityExclusionsV1Params().WithContext(ctx).WithIds([]string{state.ID.ValueString()})
	_, err := r.client.SensorVisibilityExclusions.DeleteSensorVisibilityExclusionsV1(params)
	if err != nil {
		resp.Diagnostics.AddError("Error deleting sensor visibility exclusion", err.Error())
	}
}

// ImportState imports the resource by ID.
func (r *sensorVisibilityExclusionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Helper: readExclusion fetches the exclusion and populates the model.
func readExclusion(ctx context.Context, r *sensorVisibilityExclusionResource, id *string, model *SensorVisibilityExclusionResourceModel, diags *diag.Diagnostics) {
	params := sensor_visibility_exclusions.NewGetSensorVisibilityExclusionsV1Params().WithContext(ctx).WithIds([]string{*id})
	result, err := r.client.SensorVisibilityExclusions.GetSensorVisibilityExclusionsV1(params)
	if err != nil || len(result.Payload.Resources) == 0 {
		diags.AddError("Error reading sensor visibility exclusion", errMsg(err, result))
		return
	}
	ex := result.Payload.Resources[0]
	model.ID = types.StringPointerValue(ex.ID)
	model.Value = types.StringPointerValue(ex.Value)
	// Note: Comment field is not available in API responses, so we preserve it from state
	model.IsDescendantProcess = types.BoolValue(ex.IsDescendantProcess)
	model.Groups = stringSliceToSet(ex.Groups)
	model.RegexpValue = types.StringPointerValue(ex.RegexpValue)
	model.AppliedGlobally = types.BoolPointerValue(ex.AppliedGlobally)
	model.CreatedBy = types.StringPointerValue(ex.CreatedBy)
	if ex.CreatedOn != nil {
		model.CreatedOn = types.StringValue(ex.CreatedOn.String())
	}
	model.ModifiedBy = types.StringPointerValue(ex.ModifiedBy)
	if ex.LastModified != nil {
		model.LastModified = types.StringValue(ex.LastModified.String())
	}
}

// Helper: setToStringSlice converts a types.Set to []string
func setToStringSlice(set types.Set) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	var result []string
	for _, v := range set.Elements() {
		if s, ok := v.(types.String); ok && !s.IsNull() && !s.IsUnknown() {
			result = append(result, s.ValueString())
		}
	}
	return result
}

// Helper: stringSliceToSet converts []*models.HostGroupsHostGroupV1 to types.Set
func stringSliceToSet(groups []*models.HostGroupsHostGroupV1) types.Set {
	var ids []attr.Value
	for _, g := range groups {
		if g != nil && g.ID != nil {
			ids = append(ids, types.StringValue(*g.ID))
		}
	}
	set, _ := types.SetValue(types.StringType, ids)
	return set
}

// Helper: errMsg formats error messages
func errMsg(err error, result interface{}) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("API error: %+v", result)
}
