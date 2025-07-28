package contentupdatepolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithConfigure      = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithImportState    = &defaultContentUpdatePolicyResource{}
	_ resource.ResourceWithValidateConfig = &defaultContentUpdatePolicyResource{}
)

// NewDefaultContentUpdatePolicyResource is a helper function to simplify the provider implementation.
func NewDefaultContentUpdatePolicyResource() resource.Resource {
	return &defaultContentUpdatePolicyResource{}
}

// defaultContentUpdatePolicyResource is the resource implementation.
type defaultContentUpdatePolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// defaultContentUpdatePolicyResourceModel is the resource model.
type defaultContentUpdatePolicyResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	PlatformName            types.String `tfsdk:"platform_name"`
	SensorOperations        types.Object `tfsdk:"sensor_operations"`
	SystemCritical          types.Object `tfsdk:"system_critical"`
	VulnerabilityManagement types.Object `tfsdk:"vulnerability_management"`
	RapidResponse           types.Object `tfsdk:"rapid_response"`
	LastUpdated             types.String `tfsdk:"last_updated"`

	settings *contentUpdatePolicySettings `tfsdk:"-"`
}



// extract extracts the Go values from their terraform wrapped values.
func (d *defaultContentUpdatePolicyResourceModel) extract(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics

	d.settings, diags = extractRingAssignments(
		ctx,
		d.SensorOperations,
		d.SystemCritical,
		d.VulnerabilityManagement,
		d.RapidResponse,
	)

	return diags
}

// wrap transforms Go values to their terraform wrapped values.
func (d *defaultContentUpdatePolicyResourceModel) wrap(
	ctx context.Context,
	policy models.ContentUpdatePolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	d.ID = types.StringValue(*policy.ID)

	if d.PlatformName.IsNull() {
		d.PlatformName = types.StringValue(*policy.PlatformName)
	}

	if !strings.EqualFold(d.PlatformName.ValueString(), *policy.PlatformName) {
		diags.AddError(
			"Mismatch platform_name",
			fmt.Sprintf(
				"The api returned the following platform_name: %s for default content update policy: %s, the terraform config has a platform_name value of %s. This should not be possible, if you imported this resource ensure you updated the platform_name to the correct value in your terraform config.\n\nIf you believe there is a bug in the provider or need help please let us know by opening a github issue here: https://github.com/CrowdStrike/terraform-provider-crowdstrike/issues",
				*policy.PlatformName,
				d.ID,
				d.PlatformName.ValueString(),
			),
		)
	}

	d.SensorOperations, d.SystemCritical, d.VulnerabilityManagement, d.RapidResponse, diags = populateRingAssignments(ctx, policy)

	return diags
}

// Configure adds the provider configured client to the resource.
func (r *defaultContentUpdatePolicyResource) Configure(
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
func (r *defaultContentUpdatePolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_default_content_update_policy"
}

// Schema defines the schema for the resource.
func (r *defaultContentUpdatePolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Default Content Update Policy --- This resource allows management of the default content update policy in the CrowdStrike Falcon platform. Destruction of this resource *will not* delete the default content update policy or remove any configured settings.\n\n%s",
			scopes.GenerateScopeDescription(
				[]scopes.Scope{
					{
						Name:  "Content update policies",
						Read:  true,
						Write: true,
					},
				},
			),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the default content update policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Chooses which default content update policy to manage. (Windows, Mac, Linux)",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("Windows", "Linux", "Mac"),
				},
			},
			"sensor_operations": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for sensor operations content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"system_critical": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for system critical content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea). Note: 'pause' is not allowed for system_critical.",
						Validators: []validator.String{
							stringvalidator.OneOf(validSystemCriticalRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"vulnerability_management": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for vulnerability management content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
			"rapid_response": schema.SingleNestedAttribute{
				Required:    true,
				Description: "Ring assignment settings for rapid response allow/block listing content category.",
				Attributes: map[string]schema.Attribute{
					"ring_assignment": schema.StringAttribute{
						Required:    true,
						Description: "Ring assignment for the content category (ga, ea, pause).",
						Validators: []validator.String{
							stringvalidator.OneOf(validRingAssignments...),
						},
					},
					"delay_hours": schema.Int64Attribute{
						Optional:    true,
						Description: "Delay in hours when using 'ga' ring assignment. Valid values: 0, 1, 2, 4, 8, 12, 24, 48, 72. Only applicable when ring_assignment is 'ga'.",
						Validators: []validator.Int64{
							int64validator.OneOf(validDelayHours...),
						},
					},
				},
			},
		},
	}
}

// Create imports the resource into state and configures it. The default resource policy can't be created or deleted.
// Users must import the default policy by ID first before managing it.
func (r *defaultContentUpdatePolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.getDefaultPolicy(ctx, plan.PlatformName.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(*policy.ID)
	resp.Diagnostics.Append(
		resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the policy with the planned configuration
	policy, diags = r.updateDefaultPolicy(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *defaultContentUpdatePolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := getContentUpdatePolicy(ctx, r.client, state.ID.ValueString())
	if diags.HasError() {
		for _, diag := range diags {
			if strings.Contains(diag.Summary(), "not found") {
				tflog.Warn(
					ctx,
					fmt.Sprintf("default content update policy %s not found, removing from state", state.ID),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *defaultContentUpdatePolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(plan.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.updateDefaultPolicy(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(plan.wrap(ctx, *policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *defaultContentUpdatePolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	// We can not delete the default content update policy, so we will just remove it from state.
}

// ImportState implements the logic to support resource imports.
func (r *defaultContentUpdatePolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply to validate resource configuration.
func (r *defaultContentUpdatePolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config defaultContentUpdatePolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(config.extract(ctx)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.settings.sensorOperations != nil {
		if config.settings.sensorOperations.RingAssignment.ValueString() != "ga" && !config.settings.sensorOperations.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("sensor_operations").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. sensor_operations has ring_assignment '%s' but delay_hours is set.",
					config.settings.sensorOperations.RingAssignment.ValueString()),
			)
		}
	}

	if config.settings.systemCritical != nil {
		if config.settings.systemCritical.RingAssignment.ValueString() != "ga" && !config.settings.systemCritical.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("system_critical").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. system_critical has ring_assignment '%s' but delay_hours is set.",
					config.settings.systemCritical.RingAssignment.ValueString()),
			)
		}
	}

	if config.settings.vulnerabilityManagement != nil {
		if config.settings.vulnerabilityManagement.RingAssignment.ValueString() != "ga" && !config.settings.vulnerabilityManagement.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("vulnerability_management").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. vulnerability_management has ring_assignment '%s' but delay_hours is set.",
					config.settings.vulnerabilityManagement.RingAssignment.ValueString()),
			)
		}
	}

	if config.settings.rapidResponse != nil {
		if config.settings.rapidResponse.RingAssignment.ValueString() != "ga" && !config.settings.rapidResponse.DelayHours.IsNull() {
			resp.Diagnostics.AddAttributeError(
				path.Root("rapid_response").AtName("delay_hours"),
				"Invalid delay_hours configuration",
				fmt.Sprintf("delay_hours can only be set when ring_assignment is 'ga'. rapid_response has ring_assignment '%s' but delay_hours is set.",
					config.settings.rapidResponse.RingAssignment.ValueString()),
			)
		}
	}
}

func (r *defaultContentUpdatePolicyResource) updateDefaultPolicy(
	ctx context.Context,
	config *defaultContentUpdatePolicyResourceModel,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	ringAssignmentSettings := buildRingAssignmentSettings(config.settings)

	policyParams := content_update_policies.UpdateContentUpdatePoliciesParams{
		Context: ctx,
		Body: &models.ContentUpdateUpdatePoliciesReqV1{
			Resources: []*models.ContentUpdateUpdatePolicyReqV1{
				{
					ID: config.ID.ValueStringPointer(),
					Settings: &models.ContentUpdateContentUpdateSettingsReqV1{
						RingAssignmentSettings: ringAssignmentSettings,
					},
				},
			},
		},
	}

	res, err := r.client.ContentUpdatePolicies.UpdateContentUpdatePolicies(&policyParams)

	if err != nil {
		diags.AddError(
			"Error updating CrowdStrike default content update policy",
			"Could not update default content update policy with ID: "+config.ID.ValueString()+": "+err.Error(),
		)
		return nil, diags
	}

	policy := res.Payload.Resources[0]

	return policy, diags
}

func (r *defaultContentUpdatePolicyResource) getDefaultPolicy(
	ctx context.Context,
	platformName string,
) (*models.ContentUpdatePolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	caser := cases.Title(language.English)
	platformName = caser.String(platformName)

	filter := fmt.Sprintf(
		`platform_name:'%s'+name.raw:'platform_default'+description:'platform'+description:'default'+description:'policy'`,
		platformName,
	)
	sort := "precedence.desc"

	res, err := r.client.ContentUpdatePolicies.QueryCombinedContentUpdatePolicies(
		&content_update_policies.QueryCombinedContentUpdatePoliciesParams{
			Context: ctx,
			Filter:  &filter,
			Sort:    &sort,
		},
	)

	if err != nil {
		diags.AddError(
			"Failed to get default content update policy",
			fmt.Sprintf("Failed to get default content update policy: %s", err),
		)

		return nil, diags
	}

	if res == nil || res.Payload == nil || len(res.Payload.Resources) == 0 {
		diags.AddError(
			"Unable to find default content update policy",
			fmt.Sprintf(
				"No policy matched filter: %s, a default policy should exist. Please report this issue to the provider developers.",
				filter,
			),
		)

		return nil, diags
	}

	// we sort by descending precedence, default policy is always first
	defaultPolicy := res.Payload.Resources[0]

	return defaultPolicy, diags
}


