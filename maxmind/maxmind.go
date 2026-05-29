package maxmind

import (
	"net"
	"reflect"

	"github.com/oschwald/maxminddb-golang"
)

// GeoNames is a struct for multiple languages.
type GeoNames struct {
	German              string `maxminddb:"de"`
	English             string `maxminddb:"en"`
	Spanish             string `maxminddb:"es"`
	French              string `maxminddb:"fr"`
	Japanese            string `maxminddb:"ja"`
	BrazilianPortuguese string `maxminddb:"pt-BR"`
	Russia              string `maxminddb:"ru"`
	Chinese             string `maxminddb:"zh-CN"`
}

// GeoCity is a struct for maxminddb city result.
type GeoCity struct {
	City struct {
		Name GeoNames `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Code string   `maxminddb:"code"`
		Name GeoNames `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		ISO   string   `maxminddb:"iso_code"`
		Names GeoNames `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		AccuracyRadius int64   `maxminddb:"accuracy_radius"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
		TimeZone       string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	RegisteredCountry struct {
		ISO   string   `maxminddb:"iso_code"`
		Names GeoNames `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Subdivisions []struct {
		ISO   string   `maxminddb:"iso_code"`
		Names GeoNames `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

var emptyGeoCity = GeoCity{}

// Database reads GeoCity records from a MaxMind database.
type Database interface {
	// Lookup returns GeoCity for given IP.
	Lookup(ip net.IP) (*GeoCity, error)
}

// DatabaseImpl implements Database.
type DatabaseImpl struct {
	db *maxminddb.Reader
}

var _ Database = (*DatabaseImpl)(nil)

// Lookup returns GeoCity for given IP.
func (d *DatabaseImpl) Lookup(ip net.IP) (*GeoCity, error) {
	var record GeoCity
	if err := d.db.Lookup(ip, &record); err != nil {
		return nil, err
	}
	if IsEmptyGeoCity(record) {
		return nil, nil
	}
	return &record, nil
}

// Path is a type for maxminddb path.
type Path string

// ContainerPath returns path to maxminddb container.
func ContainerPath() Path {
	return "/app/bin/GeoLite2-City.mmdb"
}

// NewDatabase opens a MaxMind database.
func NewDatabase(path Path) (*DatabaseImpl, func(), error) {
	db, err := maxminddb.Open(string(path))
	if err != nil {
		return nil, nil, err
	}
	return &DatabaseImpl{db: db}, func() {
		_ = db.Close()
	}, nil
}

// NewDatabaseImpl returns implementation of Database.
//
// Deprecated: Use NewDatabase when a concrete *DatabaseImpl is acceptable.
func NewDatabaseImpl(path Path) (Database, func(), error) {
	database, cleanup, err := NewDatabase(path)
	if err != nil {
		return nil, nil, err
	}
	return database, cleanup, nil
}

// IsEmptyGeoCity checks if GeoCity is empty.
func IsEmptyGeoCity(geoCity GeoCity) bool {
	return reflect.DeepEqual(geoCity, emptyGeoCity)
}
