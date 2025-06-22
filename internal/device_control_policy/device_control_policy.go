package devicecontrolpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	hostgroups "github.com/crowdstrike/terraform-provider-crowdstrike/internal/host_groups"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &deviceControlPolicyResource{}
	_ resource.ResourceWithConfigure      = &deviceControlPolicyResource{}
	_ resource.ResourceWithImportState    = &deviceControlPolicyResource{}
	_ resource.ResourceWithValidateConfig = &deviceControlPolicyResource{}
)

// NewDeviceControlPolicyResource is a helper function to simplify the provider implementation.
func NewDeviceControlPolicyResource() resource.Resource {
	return &deviceControlPolicyResource{}
}

// deviceControlPolicyResource is the resource implementation.
type deviceControlPolicyResource struct {
	client *client.CrowdStrikeAPISpecification
}

// deviceControlPolicyResourceModel is the resource model.
type deviceControlPolicyResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	PlatformName types.String `tfsdk:"platform_name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	HostGroups   types.Set    `tfsdk:"host_groups"`
	LastUpdated  types.String `tfsdk:"last_updated"`

	// Settings
	EndUserNotification  types.String `tfsdk:"end_user_notification"`
	EnforcementMode      types.String `tfsdk:"enforcement_mode"`
	EnhancedFileMetadata types.Bool   `tfsdk:"enhanced_file_metadata"`
	Classes              types.Set    `tfsdk:"classes"`

	// Computed fields
	CreatedBy         types.String `tfsdk:"created_by"`
	CreatedTimestamp  types.String `tfsdk:"created_timestamp"`
	ModifiedBy        types.String `tfsdk:"modified_by"`
	ModifiedTimestamp types.String `tfsdk:"modified_timestamp"`
}

// usbClassModel represents a USB class configuration
type usbClassModel struct {
	ID         types.String `tfsdk:"id"`
	Action     types.String `tfsdk:"action"`
	Exceptions types.Set    `tfsdk:"exceptions"`
}

// exceptionModel represents a device exception
type exceptionModel struct {
	Action       types.String `tfsdk:"action"`
	CombinedID   types.String `tfsdk:"combined_id"`
	Description  types.String `tfsdk:"description"`
	ProductID    types.String `tfsdk:"product_id"`
	ProductName  types.String `tfsdk:"product_name"`
	SerialNumber types.String `tfsdk:"serial_number"`
	VendorID     types.String `tfsdk:"vendor_id"`
	VendorName   types.String `tfsdk:"vendor_name"`
}

// Configure adds the provider configured client to the resource.
func (r *deviceControlPolicyResource) Configure(
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
func (r *deviceControlPolicyResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_device_control_policy"
}

// Schema defines the schema for the resource.
func (r *deviceControlPolicyResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf(
			"Device Control Policy --- This resource allows management of device control policies in the CrowdStrike Falcon platform. Device control policies allow you to control what USB devices and media types can be accessed on endpoints.\n\n%s",
			scopes.GenerateScopeDescription(
				[]scopes.Scope{
					{
						Name:  "Device control policies",
						Read:  true,
						Write: true,
					},
				},
			),
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the device control policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the device control policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the device control policy.",
			},
			"platform_name": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the device control policy (Windows, Mac, Linux).",
				Validators: []validator.String{
					stringvalidator.OneOfCaseInsensitive("Windows", "Mac", "Linux"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the device control policy is enabled.",
			},
			"host_groups": schema.SetAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Host Group ids to attach to the device control policy.",
			},
			"end_user_notification": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the end user receives a notification when the policy is violated (SILENT, NOTIFY_USER).",
				Validators: []validator.String{
					stringvalidator.OneOf("SILENT", "NOTIFY_USER"),
				},
				Default: stringdefault.StaticString("SILENT"),
			},
			"enforcement_mode": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "How the policy is enforced (MONITOR_ONLY, MONITOR_ENFORCE).",
				Validators: []validator.String{
					stringvalidator.OneOf("MONITOR_ONLY", "MONITOR_ENFORCE"),
				},
				Default: stringdefault.StaticString("MONITOR_ONLY"),
			},
			"enhanced_file_metadata": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable enhanced file metadata functionality on the sensor.",
				Default:     booldefault.StaticBool(false),
			},
			"classes": schema.SetNestedAttribute{
				Optional:    true,
				Description: "USB device class settings for the policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Required:    true,
							Description: "USB class identifier (e.g., '01', '03', '08', '09', '0E').",
						},
						"action": schema.StringAttribute{
							Required:    true,
							Description: "Action to take for devices in this class (FULL_ACCESS, FULL_BLOCK, BLOCK_EXECUTE, READ_ONLY). Note: BLOCK_EXECUTE is only valid for MASS_STORAGE devices.",
							Validators: []validator.String{
								stringvalidator.OneOf("FULL_ACCESS", "FULL_BLOCK", "BLOCK_EXECUTE", "READ_ONLY"),
							},
						},
						"exceptions": schema.SetNestedAttribute{
							Optional:    true,
							Description: "Exceptions to the rules of this class setting.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"action": schema.StringAttribute{
										Required:    true,
										Description: "Action for this exception (FULL_ACCESS, FULL_BLOCK, BLOCK_EXECUTE, READ_ONLY).",
										Validators: []validator.String{
											stringvalidator.OneOf("FULL_ACCESS", "FULL_BLOCK", "BLOCK_EXECUTE", "READ_ONLY"),
										},
									},
									"combined_id": schema.StringAttribute{
										Optional:    true,
										Description: "Combined vendor and product ID for this exception.",
									},
									"description": schema.StringAttribute{
										Optional:    true,
										Description: "Description of this exception.",
									},
									"product_id": schema.StringAttribute{
										Optional:    true,
										Description: "Product ID for this exception.",
									},
									"product_name": schema.StringAttribute{
										Optional:    true,
										Description: "Product name for this exception.",
									},
									"serial_number": schema.StringAttribute{
										Optional:    true,
										Description: "Serial number for this exception.",
									},
									"vendor_id": schema.StringAttribute{
										Optional:    true,
										Description: "Vendor ID for this exception.",
									},
									"vendor_name": schema.StringAttribute{
										Optional:    true,
										Description: "Vendor name for this exception.",
									},
								},
							},
						},
					},
				},
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "Email of the user who created the policy.",
			},
			"created_timestamp": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the policy was created.",
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "Email of the user who last modified the policy.",
			},
			"modified_timestamp": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the policy was last modified.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *deviceControlPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan deviceControlPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build the create request
	createReq := &models.DeviceControlCreatePoliciesV1{
		Resources: []*models.DeviceControlCreatePolicyReqV1{
			{
				Name:         plan.Name.ValueStringPointer(),
				Description:  plan.Description.ValueString(),
				PlatformName: plan.PlatformName.ValueStringPointer(),
			},
		},
	}

	// Add settings if any configuration is provided
	if !plan.Classes.IsNull() || !plan.EndUserNotification.IsNull() || !plan.EnforcementMode.IsNull() || !plan.EnhancedFileMetadata.IsNull() {
		settings, diags := r.buildSettingsFromPlan(ctx, plan)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createReq.Resources[0].Settings = settings
	}

	params := &device_control_policies.CreateDeviceControlPoliciesParams{
		Context: ctx,
		Body:    createReq,
	}

	response, err := r.client.DeviceControlPolicies.CreateDeviceControlPolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating device control policy",
			"Could not create device control policy, unexpected error: "+err.Error(),
		)
		return
	}

	if len(response.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error creating device control policy",
			"No policy was returned from the create operation",
		)
		return
	}

	policy := response.Payload.Resources[0]
	plan.ID = types.StringValue(*policy.ID)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Update plan with actual values from API response
	diags = r.updatePlanFromPolicy(ctx, &plan, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle host group assignments
	if !plan.HostGroups.IsNull() {
		emptySet, diags := types.SetValueFrom(ctx, types.StringType, []string{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		diags = r.syncHostGroups(ctx, plan.HostGroups, emptySet, plan.ID.ValueString())
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Enable the policy if it should be enabled by default
	if getBoolValue(policy.Enabled) {
		plan.Enabled = types.BoolValue(true)
	} else {
		plan.Enabled = types.BoolValue(false)
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *deviceControlPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state deviceControlPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policy, diags := r.getDeviceControlPolicy(ctx, state.ID.ValueString())
	if len(diags.Errors()) > 0 {
		for _, err := range diags.Errors() {
			if err.Summary() == "Policy not found" {
				tflog.Warn(
					ctx,
					fmt.Sprintf("device control policy %s not found, removing from state", state.ID.ValueString()),
				)
				resp.State.RemoveResource(ctx)
				return
			}
		}
	}
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update state with values from API
	diags = r.updatePlanFromPolicy(ctx, &state, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *deviceControlPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan deviceControlPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state deviceControlPolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build update request
	settings, diags := r.buildSettingsFromPlan(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := &models.DeviceControlUpdatePoliciesReqV1{
		Resources: []*models.DeviceControlUpdatePolicyReqV1{
			{
				ID:          plan.ID.ValueStringPointer(),
				Name:        plan.Name.ValueString(),
				Description: plan.Description.ValueString(),
				Settings:    settings,
			},
		},
	}

	params := &device_control_policies.UpdateDeviceControlPoliciesParams{
		Context: ctx,
		Body:    updateReq,
	}

	response, err := r.client.DeviceControlPolicies.UpdateDeviceControlPolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating device control policy",
			"Could not update device control policy, unexpected error: "+err.Error(),
		)
		return
	}

	if len(response.Payload.Resources) == 0 {
		resp.Diagnostics.AddError(
			"Error updating device control policy",
			"No policy was returned from the update operation",
		)
		return
	}

	policy := response.Payload.Resources[0]
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Update plan with actual values from API response
	diags = r.updatePlanFromPolicy(ctx, &plan, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle host group changes
	diags = r.syncHostGroups(ctx, plan.HostGroups, state.HostGroups, plan.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *deviceControlPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state deviceControlPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := &device_control_policies.DeleteDeviceControlPoliciesParams{
		Context: ctx,
		Ids:     []string{state.ID.ValueString()},
	}

	_, err := r.client.DeviceControlPolicies.DeleteDeviceControlPolicies(params)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting device control policy",
			"Could not delete device control policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState implements the logic to support resource imports.
func (r *deviceControlPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	// Retrieve import ID and save to id attribute
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ValidateConfig runs during validate, plan, and apply to validate resource configuration.
func (r *deviceControlPolicyResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config deviceControlPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(utils.ValidateEmptyIDs(ctx, config.HostGroups, "host_groups")...)

	// Validate that if classes are provided, each class has at least an ID and action
	if !config.Classes.IsNull() {
		var classes []usbClassModel
		resp.Diagnostics.Append(config.Classes.ElementsAs(ctx, &classes, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		for i, class := range classes {
			if class.ID.IsNull() || class.ID.ValueString() == "" {
				resp.Diagnostics.AddAttributeError(
					path.Root("classes").AtSetValue(types.ObjectValueMust(
						class.AttributeTypes(), class.AttributeValues())),
					"Invalid USB class configuration",
					fmt.Sprintf("USB class at index %d must have a valid ID", i),
				)
			}

			if class.Action.IsNull() || class.Action.ValueString() == "" {
				resp.Diagnostics.AddAttributeError(
					path.Root("classes").AtSetValue(types.ObjectValueMust(
						class.AttributeTypes(), class.AttributeValues())),
					"Invalid USB class configuration",
					fmt.Sprintf("USB class at index %d must have a valid action", i),
				)
			}

			// Validate BLOCK_EXECUTE is only used for MASS_STORAGE
			if class.Action.ValueString() == "BLOCK_EXECUTE" && class.ID.ValueString() != "08" {
				resp.Diagnostics.AddAttributeError(
					path.Root("classes").AtSetValue(types.ObjectValueMust(
						class.AttributeTypes(), class.AttributeValues())),
					"Invalid action for USB class",
					fmt.Sprintf("BLOCK_EXECUTE action can only be used with USB class '08' (Mass Storage), but was used with class '%s'", class.ID.ValueString()),
				)
			}
		}
	}
}

// Helper functions

// getDeviceControlPolicy retrieves a device control policy by ID.
func (r *deviceControlPolicyResource) getDeviceControlPolicy(
	ctx context.Context,
	policyID string,
) (*models.DeviceControlPolicyV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := &device_control_policies.GetDeviceControlPoliciesParams{
		Context: ctx,
		Ids:     []string{policyID},
	}

	response, err := r.client.DeviceControlPolicies.GetDeviceControlPolicies(params)
	if err != nil {
		diags.AddError(
			"Error reading device control policy",
			"Could not read device control policy ID "+policyID+": "+err.Error(),
		)
		return nil, diags
	}

	if len(response.Payload.Resources) == 0 {
		diags.AddError("Policy not found", "Device control policy not found: "+policyID)
		return nil, diags
	}

	return response.Payload.Resources[0], diags
}

// updatePlanFromPolicy updates the plan with values from the API policy response.
func (r *deviceControlPolicyResource) updatePlanFromPolicy(
	ctx context.Context,
	plan *deviceControlPolicyResourceModel,
	policy *models.DeviceControlPolicyV1,
) diag.Diagnostics {
	var diags diag.Diagnostics

	plan.ID = types.StringValue(getStringValue(policy.ID))
	plan.Name = types.StringValue(getStringValue(policy.Name))
	plan.Description = types.StringValue(getStringValue(policy.Description))
	plan.PlatformName = types.StringValue(getStringValue(policy.PlatformName))
	plan.Enabled = types.BoolValue(getBoolValue(policy.Enabled))

	// Set computed fields
	plan.CreatedBy = types.StringValue(getStringValue(policy.CreatedBy))
	plan.ModifiedBy = types.StringValue(getStringValue(policy.ModifiedBy))

	if policy.CreatedTimestamp != nil {
		plan.CreatedTimestamp = types.StringValue(policy.CreatedTimestamp.String())
	}
	if policy.ModifiedTimestamp != nil {
		plan.ModifiedTimestamp = types.StringValue(policy.ModifiedTimestamp.String())
	}

	// Handle host groups
	hostGroupSet, hostGroupDiags := hostgroups.ConvertHostGroupsToSet(ctx, policy.Groups)
	diags.Append(hostGroupDiags...)
	if diags.HasError() {
		return diags
	}

	// Only update host groups if they're not null in the plan (to preserve user config)
	if !plan.HostGroups.IsNull() || len(hostGroupSet.Elements()) != 0 {
		plan.HostGroups = hostGroupSet
	}

	// Handle settings
	if policy.Settings != nil {
		plan.EndUserNotification = types.StringValue(getStringValue(policy.Settings.EndUserNotification))
		plan.EnforcementMode = types.StringValue(getStringValue(policy.Settings.EnforcementMode))
		plan.EnhancedFileMetadata = types.BoolValue(getBoolValue(policy.Settings.EnhancedFileMetadata))

		// Handle classes
		if policy.Settings.Classes != nil && len(policy.Settings.Classes) > 0 {
			classesSet, classesDiags := r.convertClassesToSet(ctx, policy.Settings.Classes)
			diags.Append(classesDiags...)
			if diags.HasError() {
				return diags
			}
			plan.Classes = classesSet
		}
	}

	return diags
}

// buildSettingsFromPlan creates a DeviceControlSettingsReqV1 from the plan.
func (r *deviceControlPolicyResource) buildSettingsFromPlan(
	ctx context.Context,
	plan deviceControlPolicyResourceModel,
) (*models.DeviceControlSettingsReqV1, diag.Diagnostics) {
	var diags diag.Diagnostics

	settings := &models.DeviceControlSettingsReqV1{
		EndUserNotification:  plan.EndUserNotification.ValueStringPointer(),
		EnforcementMode:      plan.EnforcementMode.ValueStringPointer(),
		EnhancedFileMetadata: plan.EnhancedFileMetadata.ValueBool(),
		DeleteExceptions:     []string{}, // Initialize empty - will be handled in a future update if needed
	}

	// Build classes
	var classes []*models.DeviceControlUSBClassExceptionsReqV1
	if !plan.Classes.IsNull() {
		var planClasses []usbClassModel
		diags.Append(plan.Classes.ElementsAs(ctx, &planClasses, false)...)
		if diags.HasError() {
			return nil, diags
		}

		for _, planClass := range planClasses {
			class := &models.DeviceControlUSBClassExceptionsReqV1{
				ID:     planClass.ID.ValueStringPointer(),
				Action: planClass.Action.ValueStringPointer(),
			}

			// Build exceptions for this class
			var exceptions []*models.DeviceControlExceptionReqV1
			if !planClass.Exceptions.IsNull() {
				var planExceptions []exceptionModel
				diags.Append(planClass.Exceptions.ElementsAs(ctx, &planExceptions, false)...)
				if diags.HasError() {
					return nil, diags
				}

				for _, planException := range planExceptions {
					exception := &models.DeviceControlExceptionReqV1{
						Action: planException.Action.ValueString(),
					}

					if !planException.CombinedID.IsNull() {
						exception.CombinedID = planException.CombinedID.ValueString()
					}
					if !planException.Description.IsNull() {
						exception.Description = planException.Description.ValueString()
					}
					if !planException.ProductID.IsNull() {
						exception.ProductID = planException.ProductID.ValueString()
					}
					if !planException.ProductName.IsNull() {
						exception.ProductName = planException.ProductName.ValueString()
					}
					if !planException.SerialNumber.IsNull() {
						exception.SerialNumber = planException.SerialNumber.ValueString()
					}
					if !planException.VendorID.IsNull() {
						exception.VendorID = planException.VendorID.ValueString()
					}
					if !planException.VendorName.IsNull() {
						exception.VendorName = planException.VendorName.ValueString()
					}

					exceptions = append(exceptions, exception)
				}
			}

			class.Exceptions = exceptions
			classes = append(classes, class)
		}
	}

	settings.Classes = classes
	return settings, diags
}

// convertClassesToSet converts API classes to a Terraform set.
func (r *deviceControlPolicyResource) convertClassesToSet(
	ctx context.Context,
	apiClasses []*models.DeviceControlUSBClassExceptionsResponse,
) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	var classes []usbClassModel

	for _, apiClass := range apiClasses {
		class := usbClassModel{
			ID:     types.StringValue(getStringValue(apiClass.ID)),
			Action: types.StringValue(getStringValue(apiClass.Action)),
		}

		// Convert exceptions
		var exceptions []exceptionModel
		if apiClass.Exceptions != nil {
			for _, apiException := range apiClass.Exceptions {
				exception := exceptionModel{
					Action: types.StringValue(apiException.Action),
				}

				if apiException.CombinedID != "" {
					exception.CombinedID = types.StringValue(apiException.CombinedID)
				} else {
					exception.CombinedID = types.StringNull()
				}

				if apiException.Description != "" {
					exception.Description = types.StringValue(apiException.Description)
				} else {
					exception.Description = types.StringNull()
				}

				if apiException.ProductID != "" {
					exception.ProductID = types.StringValue(apiException.ProductID)
				} else {
					exception.ProductID = types.StringNull()
				}

				if apiException.ProductName != "" {
					exception.ProductName = types.StringValue(apiException.ProductName)
				} else {
					exception.ProductName = types.StringNull()
				}

				if apiException.SerialNumber != "" {
					exception.SerialNumber = types.StringValue(apiException.SerialNumber)
				} else {
					exception.SerialNumber = types.StringNull()
				}

				if apiException.VendorID != "" {
					exception.VendorID = types.StringValue(apiException.VendorID)
				} else {
					exception.VendorID = types.StringNull()
				}

				if apiException.VendorName != "" {
					exception.VendorName = types.StringValue(apiException.VendorName)
				} else {
					exception.VendorName = types.StringNull()
				}

				exceptions = append(exceptions, exception)
			}
		}

		exceptionsSet, exceptionsDiags := types.SetValueFrom(ctx, types.ObjectType{
			AttrTypes: exceptionModel{}.AttributeTypes(),
		}, exceptions)
		diags.Append(exceptionsDiags...)
		if diags.HasError() {
			return types.SetNull(types.ObjectType{AttrTypes: usbClassModel{}.AttributeTypes()}), diags
		}

		class.Exceptions = exceptionsSet
		classes = append(classes, class)
	}

	classesSet, classesDiags := types.SetValueFrom(ctx, types.ObjectType{
		AttrTypes: usbClassModel{}.AttributeTypes(),
	}, classes)
	diags.Append(classesDiags...)

	return classesSet, diags
}

// syncHostGroups manages host group assignments.
func (r *deviceControlPolicyResource) syncHostGroups(
	ctx context.Context,
	planHostGroups types.Set,
	stateHostGroups types.Set,
	policyID string,
) diag.Diagnostics {
	var diags diag.Diagnostics

	var planGroups, stateGroups []string

	if !planHostGroups.IsNull() {
		diags.Append(planHostGroups.ElementsAs(ctx, &planGroups, false)...)
	}
	if !stateHostGroups.IsNull() {
		diags.Append(stateHostGroups.ElementsAs(ctx, &stateGroups, false)...)
	}

	if diags.HasError() {
		return diags
	}

	// Determine which groups to add and remove
	toAdd := difference(planGroups, stateGroups)
	toRemove := difference(stateGroups, planGroups)

	// Add new host groups
	if len(toAdd) > 0 {
		for _, groupID := range toAdd {
			addParams := &device_control_policies.PerformDeviceControlPoliciesActionParams{
				Context: ctx,
				Body: &models.MsaEntityActionRequestV2{
					Ids: []string{policyID},
					ActionParameters: []*models.MsaspecActionParameter{
						{
							Name:  stringPtr("group_id"),
							Value: stringPtr(groupID),
						},
					},
				},
				ActionName: "add-host-group",
			}

			_, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(addParams)
			if err != nil {
				diags.AddError(
					"Error adding host group to device control policy",
					fmt.Sprintf("Could not add host group %s to policy %s: %s", groupID, policyID, err.Error()),
				)
			}
		}
	}

	// Remove old host groups
	if len(toRemove) > 0 {
		for _, groupID := range toRemove {
			removeParams := &device_control_policies.PerformDeviceControlPoliciesActionParams{
				Context: ctx,
				Body: &models.MsaEntityActionRequestV2{
					Ids: []string{policyID},
					ActionParameters: []*models.MsaspecActionParameter{
						{
							Name:  stringPtr("group_id"),
							Value: stringPtr(groupID),
						},
					},
				},
				ActionName: "remove-host-group",
			}

			_, err := r.client.DeviceControlPolicies.PerformDeviceControlPoliciesAction(removeParams)
			if err != nil {
				diags.AddError(
					"Error removing host group from device control policy",
					fmt.Sprintf("Could not remove host group %s from policy %s: %s", groupID, policyID, err.Error()),
				)
			}
		}
	}

	return diags
}

// Helper functions for nested attribute types

func (m usbClassModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":         types.StringType,
		"action":     types.StringType,
		"exceptions": types.SetType{ElemType: types.ObjectType{AttrTypes: exceptionModel{}.AttributeTypes()}},
	}
}

func (m usbClassModel) AttributeValues() map[string]attr.Value {
	return map[string]attr.Value{
		"id":         m.ID,
		"action":     m.Action,
		"exceptions": m.Exceptions,
	}
}

func (m exceptionModel) AttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"action":        types.StringType,
		"combined_id":   types.StringType,
		"description":   types.StringType,
		"product_id":    types.StringType,
		"product_name":  types.StringType,
		"serial_number": types.StringType,
		"vendor_id":     types.StringType,
		"vendor_name":   types.StringType,
	}
}

func (m exceptionModel) AttributeValues() map[string]attr.Value {
	return map[string]attr.Value{
		"action":        m.Action,
		"combined_id":   m.CombinedID,
		"description":   m.Description,
		"product_id":    m.ProductID,
		"product_name":  m.ProductName,
		"serial_number": m.SerialNumber,
		"vendor_id":     m.VendorID,
		"vendor_name":   m.VendorName,
	}
}

// Utility functions
func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getBoolValue(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func difference(a, b []string) []string {
	m := make(map[string]bool)
	for _, item := range b {
		m[item] = true
	}

	var diff []string
	for _, item := range a {
		if !m[item] {
			diff = append(diff, item)
		}
	}
	return diff
}

func stringPtr(s string) *string {
	return &s
}
