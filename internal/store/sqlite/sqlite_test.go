package sqlite_test

import (
	"path/filepath"
	"testing"

	"github.com/scandeezy/std-login/internal/store"
	"github.com/scandeezy/std-login/internal/store/sqlite"
	"github.com/scandeezy/std-login/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}
