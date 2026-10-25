package version

import "testing"

func TestVersionIsDefined(t *testing.T) {
	if Version == "" {
		t.Fatal("version must not be empty")
	}
}
