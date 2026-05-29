package query

var (
	// DefaultPageSize is the default number of items per page.
	DefaultPageSize int32 = 10
	// MaxPageSize is the maximum number of items per page.
	MaxPageSize int32 = 1000
)

// ResizePage normalizes page parameters. Page numbers start at zero.
func ResizePage(page, pageSize int32) (int32, int32) {
	if page < 0 {
		page = 0
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return page, pageSize
}
