// Copyright IBM Corp. 2014, 2025
// SPDX-License-Identifier: MPL-2.0

package flex

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/errs/fwdiag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// StringFromFramework converts a Framework String value to a string pointer.
// A null String is converted to a nil string pointer.
func StringFromFramework(ctx context.Context, v basetypes.StringValuable) *string {
	if v.IsUnknown() {
		return nil
	}
	val := fwdiag.Must(v.ToStringValue(ctx))
	return val.ValueStringPointer()
}

// StringValueFromFramework converts a Framework String value to a string.
// A null String is converted to an empty string.
func StringValueFromFramework(ctx context.Context, v basetypes.StringValuable) string {
	val := fwdiag.Must(v.ToStringValue(ctx))
	return val.ValueString()
}

// StringSliceValueFromFramework converts a single Framework String value to a string slice.
// A null String is converted to a nil slice.
func StringSliceValueFromFramework(ctx context.Context, v basetypes.StringValuable) []string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}

	return []string{StringValueFromFramework(ctx, v)}
}

// StringToFramework converts a string pointer to a Framework String value.
// A nil string pointer is converted to a null String.
func StringToFramework(ctx context.Context, v *string) types.String {
	return types.StringPointerValue(v)
}

// StringPointerToFramework converts a string pointer to a Framework String value.
// A nil string pointer is converted to a null String.
func StringPointerToFramework(v *string) types.String {
	return types.StringPointerValue(v)
}

// FrameworkToStringPointer converts a Framework String value to a string pointer.
// A null or unknown String is converted to nil.
func FrameworkToStringPointer(v types.String) *string {
	return v.ValueStringPointer()
}

// StringValueToFramework converts a string value to a Framework String value.
// An empty string is converted to a null String.
func StringValueToFramework[T ~string](v T) types.String {
	if v == "" {
		return types.StringNull()
	}
	return types.StringValue(string(v))
}

// StringValueToFrameworkLegacy converts a string value to a Framework String value.
// An empty string is left as an empty String.
func StringValueToFrameworkLegacy[T ~string](_ context.Context, v T) types.String {
	return types.StringValue(string(v))
}

// StringToFrameworkLegacy converts a string pointer to a Framework String value.
// A nil string pointer is converted to an empty String.
func StringToFrameworkLegacy(_ context.Context, v *string) types.String {
	return types.StringValue(aws.ToString(v))
}

// StringToFrameworkValuable converts a string pointer to a Framework StringValuable value.
// A nil string pointer is converted to a null StringValuable.
func StringToFrameworkValuable[T basetypes.StringValuable](ctx context.Context, v *string) T {
	var output T
	typ := output.Type(ctx)
	styp := typ.(basetypes.StringTypable)

	sv := fwdiag.Must(styp.ValueFromString(ctx, types.StringPointerValue(v)))
	return sv.(T)
}

func EmptyStringAsNull(v types.String) types.String {
	if v.IsNull() || v.IsUnknown() {
		return v
	}

	if v.ValueString() == "" {
		return types.StringNull()
	}

	return v
}
