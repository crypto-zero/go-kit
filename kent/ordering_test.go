package kent

import (
	"testing"

	"entgo.io/ent/dialect/sql"
	"github.com/stretchr/testify/assert"
)

var fieldMap = map[string]string{
	"platformId": "platform_id",
	"userId":     "user_id",
}

var defaultOrdering = []*sql.OrderFieldTerm{
	sql.OrderByField("created_at", sql.OrderDesc()),
}

func TestProcessOrdering(t *testing.T) {
	testCases := []struct {
		name           string
		orderBy        string
		expectedLength int
		expectedFields []string
		expectedDesc   []bool
	}{
		{
			name:           "FieldNameTransform",
			orderBy:        "platformId ASC,userId DESC",
			expectedLength: 2,
			expectedFields: []string{"platform_id", "user_id"},
			expectedDesc:   []bool{false, true},
		},
		{
			name:           "DirectionCaseInsensitive",
			orderBy:        "platformId asc,userId DESC",
			expectedLength: 2,
			expectedFields: []string{"platform_id", "user_id"},
			expectedDesc:   []bool{false, true},
		},
		{
			name:           "EmptyOrderBy",
			orderBy:        "",
			expectedLength: 1,
			expectedFields: []string{"created_at"},
			expectedDesc:   []bool{true},
		},
		{
			name:           "InvalidPart",
			orderBy:        "platformId invalid",
			expectedLength: 1,
			expectedFields: []string{"created_at"},
			expectedDesc:   []bool{true},
		},
		{
			name:           "MissingPart",
			orderBy:        "platformId",
			expectedLength: 1,
			expectedFields: []string{"created_at"},
			expectedDesc:   []bool{true},
		},
		{
			name:           "ComplicatedCase",
			orderBy:        "platformId ASC,userId DESC,invalid ASC,userId invalid",
			expectedLength: 2,
			expectedFields: []string{"platform_id", "user_id"},
			expectedDesc:   []bool{false, true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ordering := ProcessOrdering(tc.orderBy, fieldMap, defaultOrdering)

			assert.Len(t, ordering, tc.expectedLength)
			for i, order := range ordering {
				assert.Equal(t, tc.expectedFields[i], order.Field)
				assert.Equal(t, tc.expectedDesc[i], order.OrderTermOptions.Desc)
			}
		})
	}
}
