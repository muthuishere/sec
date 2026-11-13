package cli

import (
	"os"
	"testing"
)

// Tests run from the source tree: imports must not find or write a .sec there.
func TestMain(m *testing.M) {
	os.Setenv("SEC_NO_DOTSEC", "1")
	os.Exit(m.Run())
}
