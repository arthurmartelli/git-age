package cli

import (
	"bytes"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	saved := version
	version = "v1.2.3"
	t.Cleanup(func() { version = saved })

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, stderr.String())
	}
	if got, want := stdout.String(), "git-age v1.2.3\n"; got != want {
		t.Errorf("output %q, want %q", got, want)
	}
}
