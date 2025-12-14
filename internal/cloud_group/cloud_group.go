package cloudgroup

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	fwflex "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/flex"
	fwtypes "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/types"
	fwvalidators "github.com/crowdstrike/terraform-provider-crowdstrike/internal/framework/validators"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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
	_ resource.Resource                = &cloudGroupResource{}
	_ resource.ResourceWithConfigure   = &cloudGroupResource{}
	_ resource.ResourceWithImportState = &cloudGroupResource{}
)

// NewCloudGroupResource is a helper function to simplify the provider implementation.
func NewCloudGroupResource() resource.Resource {
	return &cloudGroupResource{}
}

// cloudGroupResource defines the resource implementation.
type cloudGroupResource struct {
	client *client.CrowdStrikeAPISpecification
}

// cloudResourceFiltersModel represents the cloud resource filters.
type cloudResourceFiltersModel struct {
	Region types.List `tfsdk:"region"`
	Tags   types.List `tfsdk:"tags"`
}

// cloudProviderConfigModel represents cloud provider configuration.
type cloudProviderConfigModel struct {
	AccountIds types.List                                       `tfsdk:"account_ids"`
	Filters    fwtypes.ObjectValueOf[cloudResourceFiltersModel] `tfsdk:"filters"`
}

// gcpCloudResourceFiltersModel represents the cloud resource filters for GCP (no tags).
type gcpCloudResourceFiltersModel struct {
	Region types.List `tfsdk:"region"`
}

// gcpCloudProviderConfigModel represents cloud provider configuration for GCP.
type gcpCloudProviderConfigModel struct {
	AccountIds types.List                                          `tfsdk:"account_ids"`
	Filters    fwtypes.ObjectValueOf[gcpCloudResourceFiltersModel] `tfsdk:"filters"`
}

// imageSelectorModel represents an image selector.
type imageSelectorModel struct {
	Registry     types.String `tfsdk:"registry"`
	Repositories types.List   `tfsdk:"repositories"`
	Tags         types.List   `tfsdk:"tags"`
}

// cloudGroupResourceModel describes the resource data model.
type cloudGroupResourceModel struct {
	ID             types.String                                        `tfsdk:"id"`
	Name           types.String                                        `tfsdk:"name"`
	Description    types.String                                        `tfsdk:"description"`
	BusinessImpact types.String                                        `tfsdk:"business_impact"`
	BusinessUnit   types.String                                        `tfsdk:"business_unit"`
	Environment    types.String                                        `tfsdk:"environment"`
	Owners         fwtypes.ListValueOf[types.String]                   `tfsdk:"owners"`
	AWS            fwtypes.ObjectValueOf[cloudProviderConfigModel]     `tfsdk:"aws"`
	Azure          fwtypes.ObjectValueOf[cloudProviderConfigModel]     `tfsdk:"azure"`
	GCP            fwtypes.ObjectValueOf[gcpCloudProviderConfigModel]  `tfsdk:"gcp"`
	Images         fwtypes.ListNestedObjectValueOf[imageSelectorModel] `tfsdk:"images"`
	CreatedAt      types.String                                        `tfsdk:"created_at"`
	LastUpdated    types.String                                        `tfsdk:"last_updated"`
	CreatedBy      types.String                                        `tfsdk:"created_by"`
}

// Metadata returns the resource type name.
func (r *cloudGroupResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_group"
}

// Schema defines the schema for the resource.
func (r *cloudGroupResource) Schema(
	ctx context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Falcon Cloud Security",
			"This resource manages CrowdStrike Cloud Groups for organizing cloud resources and container images.",
			[]scopes.Scope{
				{
					Name:  "Cloud Groups V2",
					Read:  true,
					Write: true,
				},
			},
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The ID of the cloud group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "The name of the cloud group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of the cloud group.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 1000),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"business_impact": schema.StringAttribute{
				Optional:    true,
				Description: "An impact level that reflects how critical the cloud group's assets are to business operations. Valid values: high, moderate, low.",
				Validators: []validator.String{
					stringvalidator.OneOf("high", "moderate", "low"),
				},
			},
			"business_unit": schema.StringAttribute{
				Optional:    true,
				Description: "A free-text label used to associate the cloud group with an internal team.",
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 100),
					fwvalidators.StringNotWhitespace(),
				},
			},
			"environment": schema.StringAttribute{
				Optional:    true,
				Description: "Environment designation for the group. Valid values: dev, test, stage, prod.",
				Validators: []validator.String{
					stringvalidator.OneOf("dev", "test", "stage", "prod"),
				},
			},
			"owners": schema.ListAttribute{
				Optional:    true,
				Description: "Contact information for stakeholders responsible for the cloud group. List of email addresses.",
				ElementType: types.StringType,
				CustomType:  fwtypes.ListOfStringType,
				Validators: []validator.List{
					listvalidator.UniqueValues(),
					listvalidator.NoNullValues(),
					listvalidator.ValueStringsAre(
						fwvalidators.StringIsEmailAddress(),
					),
				},
			},
			"aws": schema.SingleNestedAttribute{
				Description: "AWS cloud resource configuration",
				Optional:    true,
				CustomType:  fwtypes.NewObjectTypeOf[cloudProviderConfigModel](ctx),
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (AWS account IDs) to include in the group. This field limits access to cloud resources in the specified accounts. When not provided, resources across all accounts in the cloud provider are accessible to the group.",
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
							listvalidator.NoNullValues(),
							listvalidator.UniqueValues(),
							listvalidator.ValueStringsAre(
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for AWS cloud resources",
						Optional:    true,
						CustomType:  fwtypes.NewObjectTypeOf[cloudResourceFiltersModel](ctx),
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of AWS regions to include",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
							"tags": schema.ListAttribute{
								Description: "List of tags to filter by (format: key=value)",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
						},
					},
				},
			},
			"azure": schema.SingleNestedAttribute{
				Description: "Azure cloud resource configuration",
				Optional:    true,
				CustomType:  fwtypes.NewObjectTypeOf[cloudProviderConfigModel](ctx),
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (Azure subscription IDs) to include in the group. This field limits access to cloud resources in the specified accounts. When not provided, resources across all accounts in the cloud provider are accessible to the group.",
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
							listvalidator.UniqueValues(),
							listvalidator.NoNullValues(),
							listvalidator.ValueStringsAre(
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for Azure cloud resources",
						Optional:    true,
						CustomType:  fwtypes.NewObjectTypeOf[cloudResourceFiltersModel](ctx),
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of Azure regions to include",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
							"tags": schema.ListAttribute{
								Description: "List of tags to filter by (format: key=value)",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
						},
					},
				},
			},
			"gcp": schema.SingleNestedAttribute{
				Description: "GCP cloud resource configuration",
				Optional:    true,
				CustomType:  fwtypes.NewObjectTypeOf[gcpCloudProviderConfigModel](ctx),
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.ListAttribute{
						Description: "The cloud account identifiers (GCP project IDs) to include in the group. This field limits access to cloud resources in the specified accounts. When not provided, resources across all accounts in the cloud provider are accessible to the group.",
						Optional:    true,
						ElementType: types.StringType,
						Validators: []validator.List{
							listvalidator.SizeAtLeast(1),
							listvalidator.UniqueValues(),
							listvalidator.NoNullValues(),
							listvalidator.ValueStringsAre(
								fwvalidators.StringNotWhitespace(),
							),
						},
					},
					"filters": schema.SingleNestedAttribute{
						Description: "Filters for GCP cloud resources. Note: GCP does not support tag filtering.",
						Optional:    true,
						CustomType:  fwtypes.NewObjectTypeOf[gcpCloudResourceFiltersModel](ctx),
						Attributes: map[string]schema.Attribute{
							"region": schema.ListAttribute{
								Description: "List of GCP regions to include",
								Optional:    true,
								ElementType: types.StringType,
								Validators: []validator.List{
									listvalidator.SizeAtLeast(1),
									listvalidator.UniqueValues(),
									listvalidator.NoNullValues(),
									listvalidator.ValueStringsAre(
										fwvalidators.StringNotWhitespace(),
									),
								},
							},
						},
					},
				},
			},
			"images": schema.ListNestedAttribute{
				Description: "The container images accessible to the group. Each entry includes a registry and filters for repositories and tags.",
				Optional:    true,
				CustomType:  fwtypes.NewListNestedObjectTypeOf[imageSelectorModel](ctx),
				Validators: []validator.List{
					listvalidator.SizeAtLeast(1),
					listvalidator.NoNullValues(),
					fwvalidators.ListObjectUniqueString("registry"),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"registry": schema.StringAttribute{
							Description: "The container registry to include in the group. Must be a complete HTTPS URL for a supported registry. For info about supported registries and URL format, see https://docs.crowdstrike.com/r/ved836f1",
							Required:    true,
							Validators: []validator.String{
								fwvalidators.StringNotWhitespace(),
							},
						},
						"repositories": schema.ListAttribute{
							Description: "The container image repositories within the specified registry to filter by. When specified, only images within these repositories are accessible to the group. When omitted, all repositories in the registry are included.",
							Optional:    true,
							ElementType: types.StringType,
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
								listvalidator.UniqueValues(),
								listvalidator.NoNullValues(),
								listvalidator.ValueStringsAre(
									fwvalidators.StringNotWhitespace(),
								),
							},
						},
						"tags": schema.ListAttribute{
							Description: "The container image tags to filter by. Tag matching is scoped to the specified repositories values, or across all repositories in the given registry if repositories are not provided.",
							Optional:    true,
							ElementType: types.StringType,
							Validators: []validator.List{
								listvalidator.SizeAtLeast(1),
								listvalidator.UniqueValues(),
								listvalidator.NoNullValues(),
								listvalidator.ValueStringsAre(
									fwvalidators.StringNotWhitespace(),
								),
							},
						},
					},
				},
			},
			// Computed attributes
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the group was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "The timestamp when the group was last updated.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "The API client ID that created the group.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *cloudGroupResource) Configure(
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

// Create creates the resource and sets the initial Terraform state.
func (r *cloudGroupResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := &models.AssetgroupmanagerV1CreateCloudGroupRequest{}
	resp.Diagnostics.Append(fwflex.Expand(ctx, plan, request)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Creating cloud group", map[string]interface{}{"name": plan.Name.ValueString()})

	res, err := r.client.CloudSecurity.CreateCloudGroupExternal(
		&cloud_security.CreateCloudGroupExternalParams{
			Context: ctx,
			Body:    request,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to create cloud group",
			fmt.Sprintf("Failed to create cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to create cloud group",
			"No data returned from API",
		)
		return
	}

	groupID := res.Payload.Resources[0]
	getRes, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{groupID},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read created cloud group",
			fmt.Sprintf("Failed to read created cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if getRes == nil || getRes.Payload == nil || len(getRes.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to read created cloud group",
			"API returned empty list after creation",
		)
		return
	}

	// Flatten the API response back into the Terraform model
	// Note: We normally refresh the state to ensure consistency
	resp.Diagnostics.Append(fwflex.Flatten(ctx, getRes.Payload.Resources[0], &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *cloudGroupResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		if falcon.ErrorExplain(err) == "404 Not Found" { // Simplify 404 check for this example is fine
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Failed to read cloud group",
			fmt.Sprintf("Failed to read cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(fwflex.Flatten(ctx, res.Payload.Resources[0], &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state.
func (r *cloudGroupResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudGroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	request := &models.AssetgroupmanagerV1UpdateCloudGroupMessage{}
	resp.Diagnostics.Append(fwflex.Expand(ctx, plan, request)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Expand likely won't map ID since it's not in the plan directly for the update message body usually (or handled by AutoFlex if we name it ID)
	request.ID = plan.ID.ValueString()

	tflog.Info(ctx, "Updating cloud group", map[string]interface{}{"id": plan.ID.ValueString()})

	res, err := r.client.CloudSecurity.UpdateCloudGroupExternal(
		&cloud_security.UpdateCloudGroupExternalParams{
			Context: ctx,
			Group:   request,
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to update cloud group",
			fmt.Sprintf("Failed to update cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if res == nil || res.Payload == nil || res.Payload.Resources == nil || len(res.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to update cloud group",
			"No data returned from API",
		)
		return
	}

	// Refetch the resource to get the latest state
	getRes, err := r.client.CloudSecurity.ListCloudGroupsByIDExternal(
		&cloud_security.ListCloudGroupsByIDExternalParams{
			Context: ctx,
			Ids:     []string{request.ID},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read updated cloud group",
			fmt.Sprintf("Failed to read updated cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}

	if getRes == nil || getRes.Payload == nil || len(getRes.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Failed to read updated cloud group",
			"API returned empty list after update",
		)
		return
	}

	resp.Diagnostics.Append(fwflex.Flatten(ctx, getRes.Payload.Resources[0], &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete deletes the resource.
func (r *cloudGroupResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudGroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Deleting cloud group", map[string]interface{}{"id": state.ID.ValueString()})

	_, err := r.client.CloudSecurity.DeleteCloudGroupsExternal(
		&cloud_security.DeleteCloudGroupsExternalParams{
			Context: ctx,
			Ids:     []string{state.ID.ValueString()},
		},
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to delete cloud group",
			fmt.Sprintf("Failed to delete cloud group: %s", falcon.ErrorExplain(err)),
		)
		return
	}
}

func (r *cloudGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
