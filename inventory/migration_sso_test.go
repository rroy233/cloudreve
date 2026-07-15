package inventory

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
)

func TestInitializeDBClientEnsuresFederatedIdentitySchemaForExistingVersion(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "cloudreve.db")
	client, err := ent.Open("sqlite3", fmt.Sprintf("file:%s?cache=shared&_fk=1", dbPath))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("create initial schema: %v", err)
	}
	if _, err := client.ExecContext(ctx, "DROP TABLE federated_identities"); err != nil {
		t.Fatalf("remove federated identity table to simulate an existing 4.14.0 database: %v", err)
	}
	if _, err := client.Setting.Create().
		SetName(DBVersionPrefix + "4.14.0").
		SetValue("installed").
		Save(ctx); err != nil {
		t.Fatalf("insert version marker: %v", err)
	}

	if _, err := InitializeDBClient(
		logging.NewConsoleLogger(logging.LevelError),
		client,
		cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)),
		"4.14.0",
	); err != nil {
		t.Fatalf("initialize existing database: %v", err)
	}

	if _, err := client.FederatedIdentity.Query().Count(ctx); err != nil {
		t.Fatalf("federated identity table was not restored: %v", err)
	}
	if _, err := InitializeDBClient(
		logging.NewConsoleLogger(logging.LevelError),
		client,
		cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)),
		"4.14.0",
	); err != nil {
		t.Fatalf("repeat initialization was not idempotent: %v", err)
	}
}
