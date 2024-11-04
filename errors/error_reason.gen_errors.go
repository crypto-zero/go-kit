// Code generated by protoc-gen-kit-errors. DO NOT EDIT.

package errors

// no permission
var ErrNoPermission = New(403, "NO_PERMISSION", "no permission").SetDomainAndCode("kit.errors.v1", 190001)

// no permission
// Deprecated: Use ErrNoPermission instead.
var GeneralErrorReasonNoPermission = ErrNoPermission

// attempt later
var ErrAttemptLater = New(412, "ATTEMPT_LATER", "attempt later").SetDomainAndCode("kit.errors.v1", 190002)

// attempt later
// Deprecated: Use ErrAttemptLater instead.
var GeneralErrorReasonAttemptLater = ErrAttemptLater

// request not valid
var ErrRequestNotValid = New(400, "REQUEST_NOT_VALID", "request not valid").SetDomainAndCode("kit.errors.v1", 190003)

// request not valid
// Deprecated: Use ErrRequestNotValid instead.
var GeneralErrorReasonRequestNotValid = ErrRequestNotValid