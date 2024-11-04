package ent

import (
	"strings"

	"entgo.io/ent/dialect/sql"
)

var directionMap = map[string]sql.OrderTermOption{
	"DESC": sql.OrderDesc(),
	"ASC":  sql.OrderAsc(),
}

// ProcessOrdering 转换排序字段为 []*sql.OrderFieldTerm
func ProcessOrdering(orderBy string, fieldMap map[string]string, defaultOrdering []*sql.OrderFieldTerm) (
	ordering []*sql.OrderFieldTerm,
) {
	if len(orderBy) == 0 {
		return defaultOrdering
	}

	orderByTerms := strings.Split(orderBy, ",")
	for _, term := range orderByTerms {
		if term == "" {
			continue
		}
		parts := strings.Split(term, " ")
		if len(parts) != 2 {
			continue
		}
		field, fieldOk := fieldMap[parts[0]]
		direction, directionOk := directionMap[strings.ToUpper(parts[1])]
		if fieldOk && directionOk {
			ordering = append(ordering, sql.OrderByField(field, direction))
		}
	}
	if len(ordering) == 0 {
		return defaultOrdering
	}
	return
}
