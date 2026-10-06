package memory_test

import (
	"testing"

	"github.com/scandeezy/std-login/internal/store"
	"github.com/scandeezy/std-login/internal/store/memory"
	"github.com/scandeezy/std-login/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return memory.New() })
}
