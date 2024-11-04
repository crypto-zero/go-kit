package errors

import (
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
