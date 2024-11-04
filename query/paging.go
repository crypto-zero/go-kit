package query

var (
	// DefaultPageSize 默认每页条数
	DefaultPageSize int32 = 10
	// MaxPageSize 最大每页条数
	MaxPageSize int32 = 1000
)

// ResizePage 修正分页参数, 页码从0开始.
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
