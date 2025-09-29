package cloud_security_group

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &cloudSecurityGroupResource{}
var _ resource.ResourceWithImportState = &cloudSecurityGroupResource{}

func NewCloudSecurityGroupResource() resource.Resource {
	return &cloudSecurityGroupResource{}
}

type cloudSecurityGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudResourceSelector struct {
	CloudProvider types.String `tfsdk:"cloud_provider"`
	AccountIds    types.List   `tfsdk:"account_ids"`
	Filters       types.Object `tfsdk:"filters"`
}

type cloudResourceFilters struct {
	Regions types.List `tfsdk:"regions"`
	Tags    types.Map  `tfsdk:"tags"`
}

func (c cloudResourceFilters) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"regions": types.ListType{ElemType: types.StringType},
		"tags":    types.MapType{ElemType: types.StringType},
	}
}

type imageSelector struct {
	Registry types.String `tfsdk:"registry"`
	Filters  types.Object `tfsdk:"filters"`
}

type imageFilters struct {
	Repositories types.List `tfsdk:"repositories"`
	Tags         types.List `tfsdk:"tags"`
}

func (i imageFilters) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"repositories": types.ListType{ElemType: types.StringType},
		"tags":         types.ListType{ElemType: types.StringType},
	}
}

type cloudSecurityGroupModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	BusinessImpact types.String `tfsdk:"business_impact"`
	BusinessUnit   types.String `tfsdk:"business_unit"`
	Environment    types.String `tfsdk:"environment"`
	Owners         types.List   `tfsdk:"owners"`
	CloudResources types.List   `tfsdk:"cloud_resources"`
	Images         types.List   `tfsdk:"images"`
	// Computed fields
	CreatedAt types.String `tfsdk:"created_at"`
	CreatedBy types.String `tfsdk:"created_by"`
	UpdatedAt types.String `tfsdk:"updated_at"`
	UpdatedBy types.String `tfsdk:"updated_by"`
}

func (r *cloudSecurityGroupResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_group"
}

func (r *cloudSecurityGroupResource) Configure(
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
			fmt.Sprintf("Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *cloudSecurityGroupResource) getCloudSecurityGroup(
	ctx context.Context,
	groupID string,
) (*models.AssetgroupmanagerV1CloudGroup, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_security.NewListCloudGroupsByIDExternalParams().
		WithContext(ctx).
		WithIds([]string{groupID})

	result, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(params)
	if err != nil {
		diags.AddError(
			"Error reading cloud security group",
			fmt.Sprintf("Could not read cloud security group %s %+v", groupID, falcon.ErrorExplain(err)),
		)
		return nil, diags
	}

	if result.Payload == nil || len(result.Payload.Resources) == 0 {
		diags.Append(
			newNotFoundError(
				fmt.Sprintf("No cloud security group found with ID: %s.", groupID),
			),
		)
		return nil, diags
	}

	return result.Payload.Resources[0], diags
}

func (r *cloudSecurityGroupResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Cloud Security Group Resource",
			"This resource manages cloud security groups in CrowdStrike Falcon Cloud Security.",
			requiredScopes(),
		),

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The unique identifier of the cloud security group.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the cloud security group. Must be unique and is case insensitive.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the cloud security group.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1000),
				},
			},
			"business_impact": schema.StringAttribute{
				MarkdownDescription: "The business impact level of resources in this group.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("high", "moderate", "low"),
				},
			},
			"business_unit": schema.StringAttribute{
				MarkdownDescription: "The business unit that owns resources in this group.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.LengthAtMost(100),
				},
			},
			"environment": schema.StringAttribute{
				MarkdownDescription: "The environment type for resources in this group.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("dev", "test", "stage", "prod"),
				},
			},
			"owners": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "A list of user email addresses who own this cloud security group.",
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
			},
			"cloud_resources": schema.ListNestedAttribute{
				MarkdownDescription: "Cloud resource selectors for selecting cloud resources by provider, account, and filters.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cloud_provider": schema.StringAttribute{
							MarkdownDescription: "The cloud provider for this selector.",
							Required:            true,
							Validators: []validator.String{
								stringvalidator.OneOf("aws", "azure", "gcp"),
							},
						},
						"account_ids": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "A list of account IDs to select (AWS Account IDs, Azure Subscription IDs, or GCP Project IDs).",
							Optional:            true,
							Validators: []validator.List{
								listvalidator.SizeAtMost(100),
							},
						},
						"filters": schema.ObjectAttribute{
							MarkdownDescription: "Additional filters to apply when selecting cloud resources.",
							Optional:            true,
							AttributeTypes:      cloudResourceFilters{}.AttributeTypes(),
						},
					},
				},
			},
			"images": schema.ListNestedAttribute{
				MarkdownDescription: "Image selectors for selecting container images by registry and filters.",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"registry": schema.StringAttribute{
							MarkdownDescription: "The container image registry to select from.",
							Required:            true,
						},
						"filters": schema.ObjectAttribute{
							MarkdownDescription: "Additional filters to apply when selecting images.",
							Optional:            true,
							AttributeTypes:      imageFilters{}.AttributeTypes(),
						},
					},
				},
			},
			// Computed attributes
			"created_at": schema.StringAttribute{
				MarkdownDescription: "The timestamp when the cloud security group was created.",
				Computed:            true,
			},
			"created_by": schema.StringAttribute{
				MarkdownDescription: "The user who created the cloud security group.",
				Computed:            true,
			},
			"updated_at": schema.StringAttribute{
				MarkdownDescription: "The timestamp when the cloud security group was last updated.",
				Computed:            true,
			},
			"updated_by": schema.StringAttribute{
				MarkdownDescription: "The user who last updated the cloud security group.",
				Computed:            true,
			},
		},
	}
}

func (r *cloudSecurityGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var data cloudSecurityGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := &models.AssetgroupmanagerV1CreateCloudGroupRequest{
		Name: data.Name.ValueStringPointer(),
	}

	if !data.Description.IsNull() {
		createReq.Description = data.Description.ValueString()
	}

	if !data.BusinessImpact.IsNull() {
		createReq.BusinessImpact = data.BusinessImpact.ValueString()
	}

	if !data.BusinessUnit.IsNull() {
		createReq.BusinessUnit = data.BusinessUnit.ValueString()
	}

	if !data.Environment.IsNull() {
		createReq.Environment = data.Environment.ValueString()
	}

	if !data.Owners.IsNull() {
		var owners []string
		resp.Diagnostics.Append(data.Owners.ElementsAs(ctx, &owners, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.Owners = owners
	}

	if !data.CloudResources.IsNull() || !data.Images.IsNull() {
		selectors, diags := r.buildSelectors(ctx, &data)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.Selectors = selectors
	}

	tflog.Debug(ctx, "Creating cloud security group", map[string]interface{}{
		"name": data.Name.ValueString(),
	})

	params := cloud_security.NewCreateCloudGroupExternalParams().
		WithContext(ctx).
		WithBody(createReq)

	result, err := r.client.CloudSecurity.CreateCloudGroupExternal(params)
	if err != nil {
		if forbidden, ok := err.(*cloud_security.CreateCloudGroupExternalForbidden); ok {
			resp.Diagnostics.AddError("Permission denied", fmt.Sprintf("Ensure you have the correct API scopes enabled to create cloud security groups. Error: %s", forbidden.Payload.Errors[0].Message))
			return
		}
		resp.Diagnostics.AddError(
			"Error creating cloud security group",
			fmt.Sprintf("Could not create cloud security group %s: %s", data.Name.ValueString(), falcon.ErrorExplain(err)),
		)
		return
	}

	if result.Payload == nil || len(result.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating cloud security group",
			"API returned empty response",
		)
		return
	}

	groupID := result.Payload.Resources[0]
	data.ID = types.StringValue(groupID)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read the complete group details
	cloudGroup, diags := r.getCloudSecurityGroup(ctx, groupID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.fromAPIModel(ctx, cloudGroup)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudSecurityGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var data cloudSecurityGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := data.ID.ValueString()
	tflog.Debug(ctx, "Reading cloud security group", map[string]interface{}{
		"id": groupID,
	})

	cloudGroup, diags := r.getCloudSecurityGroup(ctx, groupID)
	for _, err := range diags.Errors() {
		if err.Summary() == notFoundErrorSummary {
			tflog.Warn(
				ctx,
				fmt.Sprintf(
					"cloud security group %s not found, removing from state",
					groupID,
				),
			)

			resp.State.RemoveResource(ctx)
			return
		}
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.fromAPIModel(ctx, cloudGroup)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudSecurityGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var data cloudSecurityGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := data.ID.ValueString()

	updateReq := &models.AssetgroupmanagerV1UpdateCloudGroupMessage{
		ID:             groupID,
		Name:           data.Name.ValueString(),
		Description:    data.Description.ValueString(),
		BusinessImpact: data.BusinessImpact.ValueString(),
		BusinessUnit:   data.BusinessUnit.ValueString(),
		Environment:    data.Environment.ValueString(),
	}

	var owners []string
	resp.Diagnostics.Append(data.Owners.ElementsAs(ctx, &owners, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateReq.Owners = owners

	selectors, diags := r.buildSelectors(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	updateReq.Selectors = selectors

	tflog.Debug(ctx, "Updating cloud security group", map[string]interface{}{
		"id":   groupID,
		"name": data.Name.ValueString(),
	})

	params := cloud_security.NewUpdateCloudGroupExternalParams().
		WithContext(ctx).
		WithGroup(updateReq)

	result, err := r.client.CloudSecurity.UpdateCloudGroupExternal(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating cloud security group",
			fmt.Sprintf("Could not update cloud security group %s: %s", groupID, err.Error()),
		)
		return
	}

	if result.Payload == nil || len(result.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error updating cloud security group",
			"API returned empty response",
		)
		return
	}

	updatedGroupID := result.Payload.Resources[0]

	cloudGroup, diags := r.getCloudSecurityGroup(ctx, updatedGroupID)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(data.fromAPIModel(ctx, cloudGroup)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *cloudSecurityGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var data cloudSecurityGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := data.ID.ValueString()
	tflog.Debug(ctx, "Deleting cloud security group", map[string]interface{}{
		"id": groupID,
	})

	params := cloud_security.NewDeleteCloudGroupsExternalParams().
		WithContext(ctx).
		WithIds([]string{groupID})

	_, err := r.client.CloudSecurity.DeleteCloudGroupsExternal(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting cloud security group",
			fmt.Sprintf("Could not delete cloud security group %s: %s", groupID, err.Error()),
		)
		return
	}
}

func (r *cloudSecurityGroupResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Helper methods

func (r *cloudSecurityGroupResource) buildSelectors(
	ctx context.Context,
	data *cloudSecurityGroupModel,
) (*models.AssetgroupmanagerV1WriteCloudGroupSelectors, diag.Diagnostics) {
	var diags diag.Diagnostics
	result := &models.AssetgroupmanagerV1WriteCloudGroupSelectors{}

	// Build cloud resources selectors
	if !data.CloudResources.IsNull() {
		var cloudResources []cloudResourceSelector
		diags.Append(data.CloudResources.ElementsAs(ctx, &cloudResources, false)...)
		if diags.HasError() {
			return nil, diags
		}

		for _, cr := range cloudResources {
			selector := &models.AssetgroupmanagerV1CloudResourceSelector{
				CloudProvider: cr.CloudProvider.ValueStringPointer(),
			}

			if !cr.AccountIds.IsNull() {
				var accountIds []string
				diags.Append(cr.AccountIds.ElementsAs(ctx, &accountIds, false)...)
				if diags.HasError() {
					return nil, diags
				}
				selector.AccountIds = accountIds
			}

			if !cr.Filters.IsNull() {
				var filterStruct cloudResourceFilters
				diags.Append(cr.Filters.As(ctx, &filterStruct, basetypes.ObjectAsOptions{})...)
				if diags.HasError() {
					return nil, diags
				}

				filters := &models.AssetgroupmanagerV1CloudResourceFilters{}

				if !filterStruct.Regions.IsNull() {
					var regions []string
					diags.Append(filterStruct.Regions.ElementsAs(ctx, &regions, false)...)
					if diags.HasError() {
						return nil, diags
					}
					filters.Region = regions
				}

				if !filterStruct.Tags.IsNull() {
					var tagsMap map[string]string
					diags.Append(filterStruct.Tags.ElementsAs(ctx, &tagsMap, false)...)
					if diags.HasError() {
						return nil, diags
					}

					// Convert map to slice of "key=value" strings
					var tags []string
					for key, value := range tagsMap {
						tags = append(tags, fmt.Sprintf("%s=%s", key, value))
					}
					filters.Tags = tags
				}

				selector.Filters = filters
			}

			result.CloudResources = append(result.CloudResources, selector)
		}
	}

	// Build image selectors
	if !data.Images.IsNull() {
		var images []imageSelector
		diags.Append(data.Images.ElementsAs(ctx, &images, false)...)
		if diags.HasError() {
			return nil, diags
		}

		for _, img := range images {
			selector := &models.AssetgroupmanagerV1ImageSelector{
				Registry: img.Registry.ValueStringPointer(),
			}

			if !img.Filters.IsNull() {
				var filterStruct imageFilters
				diags.Append(img.Filters.As(ctx, &filterStruct, basetypes.ObjectAsOptions{})...)
				if diags.HasError() {
					return nil, diags
				}

				filters := &models.AssetgroupmanagerV1ImageFilters{}

				if !filterStruct.Repositories.IsNull() {
					var repositories []string
					diags.Append(filterStruct.Repositories.ElementsAs(ctx, &repositories, false)...)
					if diags.HasError() {
						return nil, diags
					}
					filters.Repository = repositories
				}

				if !filterStruct.Tags.IsNull() {
					var tags []string
					diags.Append(filterStruct.Tags.ElementsAs(ctx, &tags, false)...)
					if diags.HasError() {
						return nil, diags
					}
					filters.Tag = tags
				}

				selector.Filters = filters
			}

			result.Images = append(result.Images, selector)
		}
	}

	return result, diags
}

func (m *cloudSecurityGroupModel) fromAPIModel(
	ctx context.Context,
	apiModel *models.AssetgroupmanagerV1CloudGroup,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(apiModel.ID)
	m.Name = types.StringValue(apiModel.Name)

	if apiModel.Description != "" {
		m.Description = types.StringValue(apiModel.Description)
	} else {
		m.Description = types.StringNull()
	}

	if apiModel.BusinessImpact != "" {
		m.BusinessImpact = types.StringValue(apiModel.BusinessImpact)
	} else {
		m.BusinessImpact = types.StringNull()
	}

	if apiModel.BusinessUnit != "" {
		m.BusinessUnit = types.StringValue(apiModel.BusinessUnit)
	} else {
		m.BusinessUnit = types.StringNull()
	}

	if apiModel.Environment != "" {
		m.Environment = types.StringValue(apiModel.Environment)
	} else {
		m.Environment = types.StringNull()
	}

	if len(apiModel.Owners) > 0 {
		ownerValues := make([]attr.Value, len(apiModel.Owners))
		for i, owner := range apiModel.Owners {
			ownerValues[i] = types.StringValue(owner)
		}
		m.Owners = types.ListValueMust(types.StringType, ownerValues)
	} else {
		m.Owners = types.ListValueMust(types.StringType, []attr.Value{})
	}

	// Handle timestamps
	if !apiModel.CreatedAt.IsZero() {
		m.CreatedAt = types.StringValue(apiModel.CreatedAt.String())
	} else {
		m.CreatedAt = types.StringNull()
	}

	if apiModel.CreatedBy != "" {
		m.CreatedBy = types.StringValue(apiModel.CreatedBy)
	} else {
		m.CreatedBy = types.StringNull()
	}

	if !apiModel.UpdatedAt.IsZero() {
		m.UpdatedAt = types.StringValue(apiModel.UpdatedAt.String())
	} else {
		m.UpdatedAt = types.StringNull()
	}

	if apiModel.UpdatedBy != "" {
		m.UpdatedBy = types.StringValue(apiModel.UpdatedBy)
	} else {
		m.UpdatedBy = types.StringNull()
	}

	// TODO: Handle selectors conversion from read-only selectors to write selectors
	// This is complex because the API returns read-only selectors that include computed fields
	// For now, we'll preserve the existing selectors from the state

	return diags
}

// requiredScopes returns the scopes required for this resource.
func requiredScopes() []scopes.Scope {
	return []scopes.Scope{
		{
			Name:  "Cloud security groups",
			Read:  true,
			Write: true,
		},
	}
}
