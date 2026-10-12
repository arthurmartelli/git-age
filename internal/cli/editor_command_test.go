package cli

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

func TestEditorCommand(t *testing.T) {
	for _, test := range []struct {
		editor string
		direct []string
	}{
		{"vim", []string{"vim", "file"}},
		{"code --wait", []string{"code", "--wait", "file"}},
		{"/usr/bin/nano -w", []string{"/usr/bin/nano", "-w", "file"}},
		{"'my editor' -f", nil},
		{"EDITOR_FLAG=1 vim", nil},
		{"vim $FLAGS", nil},
		{"vim; true", nil},
		{"~/bin/edit", nil},
	} {
		command, err := editorCommand(context.Background(), test.editor, "file")
		if err != nil {
			t.Fatalf("%q: %v", test.editor, err)
		}
		if test.direct != nil {
			if filepath.Base(command.Args[0]) != filepath.Base(test.direct[0]) || !slices.Equal(command.Args[1:], test.direct[1:]) {
				t.Errorf("%q: got %q, want direct %q", test.editor, command.Args, test.direct)
			}
			continue
		}
		if len(command.Args) != 5 || command.Args[1] != "-c" || command.Args[2] != test.editor+` "$@"` || command.Args[4] != "file" {
			t.Errorf("%q: got %q, want a shell", test.editor, command.Args)
		}
	}
}
