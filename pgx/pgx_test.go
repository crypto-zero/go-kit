package pgx

import (
	"database/sql"
	"fmt"
	"log"
	"net/netip"
	"os"
	"testing"

	"github.com/ory/dockertest/v3/docker"

	"github.com/ory/dockertest/v3"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var db *sql.DB
var skipPGXTests string

func TestMain(m *testing.M) {
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		skipPGXTests = fmt.Sprintf("could not construct Docker pool: %s", err)
		os.Exit(m.Run())
	}

	// uses pool to try to connect to Docker
	err = pool.Client.Ping()
	if err != nil {
		skipPGXTests = fmt.Sprintf("could not connect to Docker: %s", err)
		os.Exit(m.Run())
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.RunWithOptions(
		&dockertest.RunOptions{
			Repository: "postgres",
			Tag:        "15",
			Env: []string{
				"POSTGRES_PASSWORD=password",
			},
		},
		func(config *docker.HostConfig) {
			// set AutoRemove to true so that stopped container goes away by itself
			config.AutoRemove = true
			config.RestartPolicy = docker.RestartPolicy{
				Name: "no",
			}
		})
	if err != nil {
		skipPGXTests = fmt.Sprintf("could not start PostgreSQL container: %s", err)
		os.Exit(m.Run())
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		var err error
		db, err = sql.Open("pgx", fmt.Sprintf("postgres://postgres:password@localhost:%s/postgres", resource.GetPort("5432/tcp")))
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		skipPGXTests = fmt.Sprintf("could not connect to database: %s", err)
		os.Exit(m.Run())
	}

	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := db.Close(); err != nil {
		log.Fatalf("Could not close database: %s", err)
	}
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func requirePGXDB(t *testing.T) *sql.DB {
	t.Helper()
	if skipPGXTests != "" {
		t.Skip(skipPGXTests)
	}
	return db
}

func TestGuessingScanUsesFallbackSource(t *testing.T) {
	type textJSON string
	type person struct {
		Name string `json:"name"`
	}

	got, err := guessingScan[person](textJSON(`{"name":"John"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "John" {
		t.Fatalf("guessingScan() = %+v; want name John", got)
	}
}

func TestPGXIntArray(t *testing.T) {
	db := requirePGXDB(t)
	input := []int{1, 2, 3}
	var output StdWrapper[[]int]
	if err := db.QueryRow("select $1::int[]", input).Scan(&output); err != nil {
		t.Fatal(err)
	}
	if len(output.V) != len(input) {
		t.Fatalf("Expected %d rows, got %d", len(input), len(output.V))
	}
}

func TestPGXJSON(t *testing.T) {
	db := requirePGXDB(t)
	type person struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	input := person{Name: "John", Age: 42}
	var output StdWrapper[person]
	if err := db.QueryRow("select $1::json", input).Scan(&output); err != nil {
		t.Fatal(err)
	}
	if input.Name != output.V.Name || input.Age != output.V.Age {
		t.Fatalf("Expected %v, got %v", input, output.V)
	}
}

func TestPGXJSONArray(t *testing.T) {
	db := requirePGXDB(t)
	type person struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	input := []person{
		{Name: "John", Age: 42},
		{Name: "Snow", Age: 43},
	}
	var output StdWrapper[[]person]
	if err := db.QueryRow("select $1::json[]", input).Scan(&output); err != nil {
		t.Fatal(err)
	}
	if len(output.V) != len(input) {
		t.Fatalf("Expected %d rows, got %d", len(input), len(output.V))
	}
	for i := range input {
		if input[i].Name != output.V[i].Name || input[i].Age != output.V[i].Age {
			t.Fatalf("Expected %v, got %v", input[i], output.V[i])
		}
	}
}

func TestPGXNetPrefix(t *testing.T) {
	db := requirePGXDB(t)
	input := netip.MustParsePrefix("255.255.255.255/32")
	var output StdWrapper[netip.Prefix]
	if err := db.QueryRow("select $1::cidr", input).Scan(&output); err != nil {
		t.Fatal(err)
	}
	if output.V.String() != input.String() {
		t.Fatalf("Expected %v, got %v", input, output.V)
	}
}

func TestPGXNetPrefixArray(t *testing.T) {
	db := requirePGXDB(t)
	input := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	var output StdWrapper[[]netip.Prefix]
	if err := db.QueryRow("select $1::cidr[]", input).Scan(&output); err != nil {
		t.Fatal(err)
	}
	if len(output.V) != len(input) {
		t.Fatalf("Expected %d rows, got %d", len(input), len(output.V))
	}
	for i := range input {
		if input[i].String() != output.V[i].String() {
			t.Fatalf("Expected %v, got %v", input[i], output.V[i])
		}
	}
}
