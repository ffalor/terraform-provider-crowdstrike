package cloud_security_group

import "github.com/hashicorp/terraform-plugin-framework/diag"

const notFoundErrorSummary = "Cloud security group not found."

func newNotFoundError(detail string) diag.ErrorDiagnostic {
	return diag.NewErrorDiagnostic(notFoundErrorSummary, detail)
}
