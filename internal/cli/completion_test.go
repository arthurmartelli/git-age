package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestProtectedPathCompletion(t *testing.T) {
	directory := t.TempDir()
	initKeygenRepo(t, directory)
	writeFile(t, directory, ".gitage", "[files]\n*.env\n!excluded.env\n")
	writeFile(t, directory, ".gitignore", "ignored.env\n")
	for _, path := range []string{"app.env", "excluded.env", "ignored.env", "public.txt", "public/readme.txt", "secrets/a file.env", "secrets/b.env", "secrets/public.txt", "secrets/nested/deep.env"} {
		writeFile(t, directory, path, "fixture")
	}
	for _, command := range []string{"lock", "unlock", "rekey", "edit", "status", "check"} {
		t.Run(command, func(t *testing.T) {
			for _, test := range []struct {
				name      string
				directory string
				args      []string
				prefix    string
				want      []string
				noSpace   bool
			}{
				{name: "root", prefix: "", want: []string{"app.env", "secrets/"}},
				{name: "file", prefix: "app", want: []string{"app.env"}},
				{name: "directory", prefix: "sec", want: []string{"secrets/"}, noSpace: true},
				{name: "nested", prefix: "secrets/", want: []string{"secrets/a file.env", "secrets/b.env", "secrets/nested/"}},
				{name: "space", prefix: "secrets/a ", want: []string{"secrets/a file.env"}},
				{name: "deep", prefix: "secrets/nested/d", want: []string{"secrets/nested/deep.env"}},
				{name: "dot prefix", prefix: "./app", want: []string{"./app.env"}},
				{name: "absolute", prefix: filepath.Join(directory, "app"), want: []string{filepath.ToSlash(filepath.Join(directory, "app.env"))}},
				{name: "subdirectory", directory: filepath.Join(directory, "secrets"), prefix: "", want: []string{"a file.env", "b.env", "nested/"}},
				{name: "unprotected", prefix: "pub"},
				{name: "excluded", prefix: "ex"},
				{name: "ignored", prefix: "ig"},
				{name: "no match", prefix: "missing"},
				{name: "additional path", args: []string{"app.env"}, prefix: "sec", want: []string{"secrets/"}, noSpace: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					workingDirectory := test.directory
					if workingDirectory == "" {
						workingDirectory = directory
					}
					args := append([]string{"__completeNoDesc", "-C", workingDirectory, command}, test.args...)
					args = append(args, test.prefix)
					var output, stderr bytes.Buffer
					if code := Run(args, &output, &stderr); code != 0 {
						t.Fatalf("complete: exit %d, %s", code, &stderr)
					}
					want := test.want
					directive := cobra.ShellCompDirectiveNoFileComp
					if command == "edit" && len(test.args) != 0 {
						want = nil
					} else if test.noSpace {
						directive |= cobra.ShellCompDirectiveNoSpace
					}
					lines := strings.Split(strings.TrimSpace(output.String()), "\n")
					if !slices.Equal(lines[:len(lines)-1], want) || lines[len(lines)-1] != ":"+fmt.Sprint(int(directive)) {
						t.Fatalf("suggestions %q; want %q, directive %d", output.String(), want, directive)
					}
				})
			}
		})
	}
}

func TestProtectedPathCompletionWithoutRules(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, directory, "public.txt", "fixture")
	for _, rules := range []string{"", "[invalid]\n*.txt\n"} {
		if rules != "" {
			writeFile(t, directory, ".gitage", rules)
		}
		var output, stderr bytes.Buffer
		if code := Run([]string{"__completeNoDesc", "-C", directory, "lock", ""}, &output, &stderr); code != 0 || output.String() != ":4\n" {
			t.Fatalf("completion without valid rules: exit %d, output %q, stderr %q", code, &output, &stderr)
		}
	}
}

func TestCompletionScripts(t *testing.T) {
	directory := t.TempDir()
	name := "git-age"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	build := exec.Command("go", "build", "-o", filepath.Join(directory, name), "./cmd/git-age")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	key := filepath.Join(directory, "identity key")
	if err := os.WriteFile(key, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	initKeygenRepo(t, repo)
	writeFile(t, repo, ".gitage", "[files]\n*.env\n")
	writeFile(t, repo, "secret.env", "fixture")
	writeFile(t, repo, "secrets/a file.env", "fixture")
	writeFile(t, repo, "public.txt", "fixture")
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var script, stderr bytes.Buffer
			if code := Run([]string{"completion", shell}, &script, &stderr); code != 0 {
				t.Fatalf("generate: exit %d, %s", code, &stderr)
			}
			path := filepath.Join(directory, "completion."+shell)
			if err := os.WriteFile(path, script.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := exec.LookPath(shell); err != nil {
				t.Skipf("%s is not installed", shell)
			}
			if output, err := exec.Command(shell, "-n", path).CombinedOutput(); err != nil {
				t.Fatalf("script syntax: %v\n%s", err, output)
			}
			switch shell {
			case "bash":
				program := `source "$1"; shift
COMP_WORDS=("$@") COMP_CWORD=$(($#-1)) words=("$@") cword=$COMP_CWORD __git_cmd_idx=1
if [[ $1 == git ]]; then _git_age; else _git_age_main; fi
printf '%s\n' "${COMPREPLY[@]}"`
				for _, test := range []struct {
					words []string
					want  string
				}{
					{[]string{"git-age", "lo"}, "lock"},
					{[]string{"git", "age", "rek"}, "rekey"},
					{[]string{"git-age", "history", "au"}, "audit"},
					{[]string{"git-age", "history", "pu"}, "purge"},
					{[]string{"git-age", "history", "purge", "--a"}, "--all"},
					{[]string{"git", "age", "history", "rek"}, "rekey"},
					{[]string{"git-age", "history", "audit", "--ref"}, "--reflog"},
					{[]string{"git-age", "history", "rekey", "--keep"}, "--keep-undecryptable"},
					{[]string{"git-age", "check", "--sta"}, "--staged"},
					{[]string{"git-age", "trust", "--ha"}, "--hash"},
					{[]string{"git-age", "help", "history", "rek"}, "rekey"},
					{[]string{"git-age", "-C", "directory with spaces", "-n", "unl"}, "unlock"},
					{[]string{"git-age", "install", "--hook-mode", "=", "al"}, "always-lock"},
					{[]string{"git-age", "install", "--hook-mode=al"}, "always-lock"},
					{[]string{"git-age", "lock", "--no"}, "--no-reuse"},
					{[]string{"git-age", "unlock", "-i", filepath.ToSlash(filepath.Join(directory, "identity k"))}, filepath.ToSlash(key)},
					{[]string{"git-age", "help", "git-ho"}, "git-hooks"},
					{[]string{"git-age", "-C", repo, "lock", "secrets"}, "secrets/"},
					{[]string{"git", "age", "-C", repo, "edit", "secrets/"}, `secrets/a\ file.env`},
					{[]string{"git-age", "-C", repo, "status", "pub"}, ""},
				} {
					command := exec.Command(shell, append([]string{"-c", program, "bash", path}, test.words...)...)
					command.Dir = repo
					output, err := command.Output()
					if err != nil || strings.TrimSpace(string(output)) != test.want {
						t.Errorf("%v: output %q, error %v", test.words, output, err)
					}
				}
				for _, words := range [][]string{{"git-age", ""}, {"git", "age", ""}} {
					output, err := exec.Command(shell, append([]string{"-c", program, "bash", path}, words...)...).Output()
					if err != nil {
						t.Fatal(err)
					}
					assertDocumentedCommands(t, strings.Fields(string(output)))
				}
			case "zsh":
				program := `compdef() { :; }
source "$1"; shift
words=("$@") CURRENT=$#
if [[ $words[1] != age ]]; then
    git-age() { return 99; }
fi
_describe() { print -rl -- "${completions[@]}"; }
_git-age`
				for _, command := range []string{"age", filepath.ToSlash(filepath.Join(directory, name))} {
					output, err := exec.Command(shell, "-f", "-c", program, "zsh", path, command, "lo").CombinedOutput()
					if err != nil || !strings.Contains(string(output), "lock:") {
						t.Errorf("%s suggestions: %v\n%s", command, err, output)
					}
				}
				for _, test := range []struct {
					prefix string
					want   string
				}{
					{"secrets", "secrets/"},
					{"secrets/", "secrets/a file.env"},
					{"pub", ""},
				} {
					command := exec.Command(shell, "-f", "-c", program+` || true`, "zsh", path, "age", "-C", repo, "lock", test.prefix)
					command.Dir = repo
					output, err := command.CombinedOutput()
					got := strings.TrimSuffix(strings.TrimSpace(string(output)), ":")
					if err != nil || got != test.want {
						t.Errorf("path %q: output %q, error %v", test.prefix, output, err)
					}
				}
				if err := os.WriteFile(filepath.Join(directory, "_git-age"), script.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				lazy := `fpath=("$1" $fpath)
autoload -Uz compinit
compinit -D -i
words=(age lo) CURRENT=2
_describe() { print -rl -- "${completions[@]}"; }
_git-age`
				output, err := exec.Command(shell, "-f", "-c", lazy, "zsh", directory).CombinedOutput()
				if err != nil || !strings.Contains(string(output), "lock:") {
					t.Fatalf("autoloaded git age suggestions: %v\n%s", err, output)
				}
				bridge := `typeset -A _comps=(git _other_git)
compdef() { _comps[$2]=$1; }
_other_git() { print -r -- delegated; }
source "$1"
source "$1"
words=(git status) CURRENT=2
"${_comps[git]}"`
				output, err = exec.Command(shell, "-f", "-c", bridge, "zsh", path).CombinedOutput()
				if err != nil || strings.TrimSpace(string(output)) != "delegated" {
					t.Fatalf("existing Git completer after reloading: %v\n%s", err, output)
				}
			case "fish":
				output, err := exec.Command(shell, "--no-config", "-c", `source $argv[1]; complete -C 'git-age '`, path).CombinedOutput()
				if err != nil {
					t.Fatalf("fish commands: %v\n%s", err, output)
				}
				var commands []string
				for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
					command, _, _ := strings.Cut(line, "\t")
					commands = append(commands, command)
				}
				assertDocumentedCommands(t, commands)
				for _, request := range []string{
					"git-age install --hook-mode=al", "git age install --hook-mode=al",
					`git -C "directory with spaces" age install --hook-mode=al`,
					`git age -C "directory with spaces" install --hook-mode=al`,
				} {
					output, err := exec.Command(shell, "--no-config", "-c", `source $argv[1]; complete -C $argv[2]`, path, request).CombinedOutput()
					if err != nil || !strings.Contains(string(output), "--hook-mode=always-lock") {
						t.Errorf("%s: %v\n%s", request, err, output)
					}
				}
				for _, test := range []struct {
					words []string
					want  string
				}{
					{[]string{"git-age", "-C", repo, "lock", "secrets"}, "secrets/"},
					{[]string{"git", "age", "-C", repo, "edit", "secrets/"}, "secrets/a file.env"},
					{[]string{"git-age", "-C", repo, "status", "pub"}, ""},
				} {
					command := exec.Command(shell, "--no-config", "-c", `source $argv[1]; complete -C $argv[2]`, path, shellPaths(test.words))
					command.Dir = repo
					output, err := command.CombinedOutput()
					got, _, _ := strings.Cut(strings.TrimSpace(string(output)), "\t")
					if err != nil || got != test.want {
						t.Errorf("%v: output %q, error %v", test.words, output, err)
					}
				}
			}
		})
	}
}

func TestCompletionCommands(t *testing.T) {
	var output, stderr bytes.Buffer
	if code := Run([]string{"__completeNoDesc", ""}, &output, &stderr); code != 0 {
		t.Fatalf("complete: exit %d, %s", code, &stderr)
	}
	commands := strings.Fields(output.String())
	assertDocumentedCommands(t, commands)
	for _, args := range [][]string{{}, {"tcsh"}, {"bash", "extra"}} {
		output.Reset()
		stderr.Reset()
		if code := Run(append([]string{"completion"}, args...), &output, &stderr); code != 2 || output.Len() != 0 {
			t.Errorf("args %v: exit %d, output %q, stderr %q", args, code, &output, &stderr)
		}
		if len(args) == 1 && stderr.String() != "git-age: unknown shell \"tcsh\"; supported shells: bash, zsh, fish\n" {
			t.Errorf("unknown shell diagnostic: %q", &stderr)
		}
	}
}

func assertDocumentedCommands(t *testing.T, commands []string) {
	t.Helper()
	lock := false
	for _, command := range commands {
		lock = lock || command == "lock"
		if command == ":4" {
			continue
		}
		if !strings.Contains(manual, "    "+command+"\n") && !strings.Contains(manual, "    "+command+" ") {
			t.Errorf("undocumented completion: %s", command)
		}
	}
	if !lock {
		t.Errorf("completion did not offer lock: %v", commands)
	}
}
