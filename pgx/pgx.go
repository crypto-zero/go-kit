package pgx

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// ent not support for generic types, so we need to declare wrapper types for each type
type (
	// CIDRWrapper is a wrapper for pgx standard sql library types.
	CIDRWrapper StdWrapper[netip.Prefix]
	// DurationWrapper is a wrapper for pgx standard sql library types.
	DurationWrapper StdWrapper[time.Duration]

	// IntsWrapper is a wrapper for pgx standard sql library types.
	IntsWrapper SliceWrapper[int]
	// FloatsWrapper is a wrapper for pgx standard sql library types.
	FloatsWrapper SliceWrapper[float64]
	// StringsWrapper is a wrapper for pgx standard sql library types.
	StringsWrapper SliceWrapper[string]
	// CIDRsWrapper is a wrapper for pgx standard sql library types.
	CIDRsWrapper SliceWrapper[netip.Prefix]
	// DurationsWrapper is a wrapper for pgx standard sql library types.
	DurationsWrapper SliceWrapper[time.Duration]
	// TimestampsWrapper is a wrapper for pgx standard sql library types.
	TimestampsWrapper SliceWrapper[time.Time]
)

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w CIDRWrapper) Value() (driver.Value, error) { return StdWrapper[netip.Prefix](w).Value() }

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *CIDRWrapper) Scan(src any) error { return (*StdWrapper[netip.Prefix])(w).Scan(src) }

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w DurationWrapper) Value() (driver.Value, error) { return StdWrapper[time.Duration](w).Value() }

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *DurationWrapper) Scan(src any) error {
	return (*StdWrapper[time.Duration])(w).Scan(src)
}

// NewIntsWrapper returns a new IntsWrapper.
func NewIntsWrapper() IntsWrapper { return IntsWrapper{V: make([]int, 0)} }

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w IntsWrapper) Value() (driver.Value, error) { return SliceWrapper[int](w).Value() }

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *IntsWrapper) Scan(src any) error { return (*SliceWrapper[int])(w).Scan(src) }

// NewFloatsWrapper returns a new FloatsWrapper.
func NewFloatsWrapper() FloatsWrapper { return FloatsWrapper{V: make([]float64, 0)} }

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w FloatsWrapper) Value() (driver.Value, error) { return SliceWrapper[float64](w).Value() }

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *FloatsWrapper) Scan(src any) error { return (*SliceWrapper[float64])(w).Scan(src) }

// NewStringsWrapper returns a new StringsWrapper.
func NewStringsWrapper() StringsWrapper { return StringsWrapper{V: make([]string, 0)} }

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w StringsWrapper) Value() (driver.Value, error) { return SliceWrapper[string](w).Value() }

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *StringsWrapper) Scan(src any) error { return (*SliceWrapper[string])(w).Scan(src) }

// NewCIDRsWrapper returns a new CIDRsWrapper.
func NewCIDRsWrapper() CIDRsWrapper { return CIDRsWrapper{V: make([]netip.Prefix, 0)} }

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w CIDRsWrapper) Value() (driver.Value, error) { return SliceWrapper[netip.Prefix](w).Value() }

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *CIDRsWrapper) Scan(src any) error { return (*SliceWrapper[netip.Prefix])(w).Scan(src) }

// NewDurationsWrapper returns a new DurationsWrapper.
func NewDurationsWrapper() DurationsWrapper {
	return DurationsWrapper{V: make([]time.Duration, 0)}
}

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w DurationsWrapper) Value() (driver.Value, error) {
	return SliceWrapper[time.Duration](w).Value()
}

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *DurationsWrapper) Scan(src any) error {
	return (*SliceWrapper[time.Duration])(w).Scan(src)
}

// NewTimestampsWrapper returns a new TimestampsWrapper.
func NewTimestampsWrapper() TimestampsWrapper {
	return TimestampsWrapper{V: make([]time.Time, 0)}
}

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w TimestampsWrapper) Value() (driver.Value, error) {
	return SliceWrapper[time.Time](w).Value()
}

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *TimestampsWrapper) Scan(src any) error {
	return (*SliceWrapper[time.Time])(w).Scan(src)
}

var (
	_ driver.Valuer = StdWrapper[netip.Prefix]{}
	_ sql.Scanner   = &StdWrapper[netip.Prefix]{}

	typeMap = pgtype.NewMap()
)

// StdWrapper is a wrapper for pgx standard sql library types.
type StdWrapper[T any] struct {
	V T
}

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w StdWrapper[T]) Value() (driver.Value, error) {
	return w.V, nil
}

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *StdWrapper[T]) Scan(src any) (err error) {
	return typeMapScan(src, &w.V)
}

// SliceWrapper is a wrapper for pgx standard sql library types.
type SliceWrapper[T any] struct {
	V []T
}

// Value implements the database/sql/driver Valuer interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w SliceWrapper[T]) Value() (driver.Value, error) {
	// pgx treats nil slice as NULL, but we want to treat it as an empty array
	if w.V == nil {
		return make([]T, 0), nil
	}
	return w.V, nil
}

// Scan implements the database/sql Scanner interface.
//
//goland:noinspection GoMixedReceiverTypes
func (w *SliceWrapper[T]) Scan(src any) (err error) {
	return typeMapScan(src, &w.V)
}

// typeMapScan is a workaround for pgx standard sql library types.
func typeMapScan[T any](src any, target *T) (err error) {
	var value T
	_, ok := typeMap.TypeForValue(&value)
	if ok {
		if err = typeMap.SQLScanner(&value).Scan(src); err != nil {
			return err
		}
		*target = value
		return nil
	}
	if value, err = guessingScan[T](src); err != nil {
		return err
	}
	*target = value
	return nil
}

// guessingScan is a workaround for pgx standard sql library types.
func guessingScan[T any](src any) (value T, err error) {
	var bufSrc []byte
	if src != nil {
		switch src := src.(type) {
		case string:
			bufSrc = []byte(src)
		case []byte:
			bufSrc = src
		default:
			bufSrc = []byte(fmt.Sprint(bufSrc))
		}
	}

	scan := func(oid uint32, format int16) error {
		plan := typeMap.PlanScan(oid, format, &value)
		if plan == nil {
			return fmt.Errorf("guess scan: unable to find plan scan %T", src)
		}
		return plan.Scan(bufSrc, &value)
	}
	formats := []int16{pgtype.TextFormatCode}
	guessTypes := []uint32{
		pgtype.JSONBOID,
		pgtype.JSONOID,
		pgtype.JSONBArrayOID,
		pgtype.JSONArrayOID,
	}
	for _, guessType := range guessTypes {
		for _, format := range formats {
			if err := scan(guessType, format); err == nil {
				return value, nil
			}
		}
	}
	return value, fmt.Errorf("pgx scan: unable to scan %T", value)
}
