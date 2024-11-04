package query

import (
	"time"

	pbquery "github.com/crypto-zero/go-kit/proto/kit/query/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TimeRange 时间范围
type TimeRange struct {
	Begin, End time.Time
}

// EmptyTimeRange 空时间范围
var EmptyTimeRange = TimeRange{}

// IsEmptyTimeRange 是否为空时间范围
func IsEmptyTimeRange(r TimeRange) bool {
	return r.Begin.IsZero() && r.End.IsZero()
}

func IsEmptyProtoTimestamp(t *timestamppb.Timestamp) bool {
	return t == nil || (t.Seconds == 0 && t.Nanos == 0)
}

// FromProtoTimeRange 从 protobuf 类型转换至 TimeRange.
func FromProtoTimeRange(r *pbquery.TimeRange) TimeRange {
	if r == nil {
		return EmptyTimeRange
	}
	out := TimeRange{}
	if IsEmptyProtoTimestamp(r.Begin) {
		out.Begin = time.Time{}
	} else {
		out.Begin = r.Begin.AsTime()
	}
	if IsEmptyProtoTimestamp(r.End) {
		out.End = time.Time{}
	} else {
		out.End = r.End.AsTime()
	}
	return out
}
