package repository

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRulesLineEndings(t *testing.T) {
	text := "# comment\n[files]\n*.env\nspace\\ \n!public.env\n[recipients]\nage1recipient\n"
	patterns, recipients, err := parseRules(".gitage", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{strings.ReplaceAll(text, "\n", "\r"), strings.ReplaceAll(text, "\n", "\r\n"), strings.Replace(text, "\n", "\r", 3)} {
		gotPatterns, gotRecipients, err := parseRules(".gitage", []byte(content))
		if err != nil || string(gotPatterns) != string(patterns) || !reflect.DeepEqual(gotRecipients, recipients) {
			t.Fatalf("line endings: %q, %v, %v", gotPatterns, gotRecipients, err)
		}
	}
	if _, _, err := parseRules(".gitage", []byte("# comment\r[files]\r!\r")); err == nil || !strings.Contains(err.Error(), ".gitage:3:") {
		t.Fatalf("CR line number: %v", err)
	}
}
