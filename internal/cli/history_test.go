package cli

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestHistoryInvalidArguments(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"audit"}, `unknown command "audit"`},
		{[]string{"history", "unknown"}, `unknown command "unknown"`},
		{[]string{"history", "audit", "--rekey"}, "unknown flag: --rekey"},
		{[]string{"history", "audit", "--yes"}, "unknown flag: --yes"},
		{[]string{"history", "audit", "--plaintext-only"}, "unknown flag: --plaintext-only"},
		{[]string{"history", "audit", "--keep-undecryptable"}, "unknown flag: --keep-undecryptable"},
		{[]string{"history", "audit", "--recipient", "unused"}, "unknown flag: --recipient"},
		{[]string{"history", "audit", "--identity", "unused"}, "unknown flag: --identity"},
		{[]string{"history", "rekey", "--reflog"}, "unknown flag: --reflog"},
		{[]string{"history", "rekey", "HEAD"}, "takes no revisions"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("exit %d, stdout %q, stderr %q; want %q", code, &stdout, &stderr, test.want)
			}
		})
	}
}

func TestHistoryHelp(t *testing.T) {
	for _, args := range [][]string{{"history"}, {"history", "--help"}, {"help", "history"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "audit") || !strings.Contains(stdout.String(), "rekey") {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", args, code, &stdout, &stderr)
		}
	}
}

func TestHistoryCompletion(t *testing.T) {
	for _, prefix := range [][]string{{"history"}, {"help", "history"}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"__completeNoDesc"}, prefix...)
		if code := Run(append(args, ""), &stdout, &stderr); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, &stderr)
		}
		if got := strings.Fields(stdout.String()); !slices.Equal(got, []string{"audit", "rekey", ":4"}) {
			t.Fatalf("%v: completion %v", args, got)
		}
	}
}
