package query

// ConvertList converts a slice of A values into B values.
func ConvertList[A, B any](from []A, convert func(A) B) []B {
	results := make([]B, 0, len(from))
	for _, v := range from {
		results = append(results, convert(v))
	}
	return results
}
