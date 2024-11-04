package maxmind

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

func TestMaxmindRead(t *testing.T) {
	reader, err := maxminddb.Open("./GeoLite2-City.mmdb")
	if err != nil {
		t.Fatal(err)
	}

	var record GeoCity
	internalIP := net.ParseIP("81.2.69.142")
	if err = reader.Lookup(internalIP, &record); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(record)
	t.Log(string(b), IsEmptyGeoCity(record))
}
