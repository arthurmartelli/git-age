package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
					{[]string{"git-age", "-C", "directory with spaces", "-n", "unl"}, "unlock"},
					{[]string{"git-age", "install", "--mode", "=", "al"}, "always-lock"},
					{[]string{"git-age", "install", "--mode=al"}, "always-lock"},
					{[]string{"git-age", "lock", "--no"}, "--no-reuse"},
					{[]string{"git-age", "unlock", "-i", filepath.Join(directory, "identity k")}, key},
					{[]string{"git-age", "help", "git-ho"}, "git-hooks"},
				} {
					command := exec.Command(shell, append([]string{"-c", program, "bash", path}, test.words...)...)
					output, err := command.Output()
					if err != nil || strings.TrimSpace(string(output)) != test.want {
						t.Errorf("%v: output %q, error %v", test.words, output, err)
					}
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
				for _, request := range []string{"git-age install --mode=al", "git age install --mode=al"} {
					output, err := exec.Command(shell, "--no-config", "-c", `source $argv[1]; complete -C $argv[2]`, path, request).CombinedOutput()
					if err != nil || !strings.Contains(string(output), "--mode=always-lock") {
						t.Errorf("%s: %v\n%s", request, err, output)
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
	for _, command := range commands {
		if command == ":4" {
			continue
		}
		if !strings.Contains(manual, "    "+command+"\n") && !strings.Contains(manual, "    "+command+" ") {
			t.Errorf("undocumented completion: %s", command)
		}
	}
	for _, args := range [][]string{{}, {"tcsh"}, {"bash", "extra"}} {
		output.Reset()
		stderr.Reset()
		if code := Run(append([]string{"completion"}, args...), &output, &stderr); code != 2 || output.Len() != 0 {
			t.Errorf("args %v: exit %d, output %q, stderr %q", args, code, &output, &stderr)
		}
	}
}
