package maxmind

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

func TestMaxmindRead(t *testing.T) {
	reader, err := maxminddb.Open("./GeoLite2-City.mmdb")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("GeoLite2-City.mmdb is not available")
		}
		t.Fatal(err)
	}
	defer reader.Close()

	var record GeoCity
	internalIP := net.ParseIP("81.2.69.142")
	if err = reader.Lookup(internalIP, &record); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b), IsEmptyGeoCity(record))
}
