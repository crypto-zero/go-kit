package errors

import (
	stderrors "errors"
	"reflect"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

func TestError_Clone(t *testing.T) {
	// Define test cases
	cases := []struct {
		name string
		err  *Error
	}{
		{
			name: "NilError",
			err:  nil,
		},
		{
			name: "EmptyError",
			err:  &Error{},
		},
		{
			name: "FilledError",
			err: &Error{
				Status:  404,
				Message: "not found",
				Info: &errdetails.ErrorInfo{
					Reason: "item_not_found",
					Domain: "test",
					Metadata: map[string]string{
						"key": "value",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the method under test
			cloned := tc.err.Clone()

			// Assert that the cloned error does not share memory with the original
			if tc.err != nil && reflect.ValueOf(tc.err).Pointer() == reflect.ValueOf(cloned).Pointer() {
				t.Error("Clone shares memory with original")
			}

			// Assert that the cloned error is equal to the original
			if !reflect.DeepEqual(tc.err, cloned) {
				t.Error("Clone is not equal to original")
			}
		})
	}
}

func TestError_SetMetadataInitializesMap(t *testing.T) {
	err := New(400, "bad_request", "bad request")

	got := err.SetMetadata("key", "value")

	if got.Info.Metadata["key"] != "value" {
		t.Fatalf("SetMetadata() metadata = %v; want key=value", got.Info.Metadata)
	}
	if err.Info.Metadata != nil {
		t.Fatalf("SetMetadata() mutated original metadata = %v; want nil", err.Info.Metadata)
	}
}

func TestError_SetCauseInitializesMap(t *testing.T) {
	err := New(400, "bad_request", "bad request")

	got := err.SetCause(stderrors.New("root cause"))

	if got.Info.Metadata["cause"] != "root cause" {
		t.Fatalf("SetCause() metadata = %v; want cause=root cause", got.Info.Metadata)
	}
}
