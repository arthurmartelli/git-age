package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func protectedPathCompletion(options *globalOptions) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		directive := cobra.ShellCompDirectiveNoFileComp
		if cmd.Name() == "edit" && len(args) != 0 {
			return nil, directive
		}
		files, err := repository.ProtectedFiles(options.directory, nil)
		if err != nil {
			return nil, directive
		}
		directory, err := filepath.Abs(options.directory)
		if err != nil {
			return nil, directive
		}
		base, partial := filepath.Split(toComplete)
		prefix := filepath.ToSlash(filepath.Clean(base))
		if prefix == "." {
			prefix = ""
		} else if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		var candidates []string
		for _, file := range files {
			path := file.Path
			if filepath.IsAbs(base) {
				path = filepath.ToSlash(filepath.Join(directory, path))
			}
			if !strings.HasPrefix(path, prefix) || strings.ContainsAny(path, "\t\r\n") {
				continue
			}
			name, _, isDirectory := strings.Cut(strings.TrimPrefix(path, prefix), "/")
			if !strings.HasPrefix(name, partial) {
				continue
			}
			candidate := filepath.ToSlash(base) + name
			if isDirectory {
				candidate += "/"
			}
			candidates = append(candidates, candidate)
		}
		slices.Sort(candidates)
		candidates = slices.Compact(candidates)
		if len(candidates) == 1 && strings.HasSuffix(candidates[0], "/") {
			directive |= cobra.ShellCompDirectiveNoSpace
		}
		return candidates, directive
	}
}

func newCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:       "completion SHELL",
		ValidArgs: []string{"bash", "zsh", "fish"},
		Short:     "print the shell completion script for bash, zsh or fish",
		Args:      cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			out := cmd.OutOrStdout()
			var suffix string
			var err error
			switch args[0] {
			case "bash":
				err = root.GenBashCompletionV2(out, false)
				suffix = bashCompletion
			case "zsh":
				if _, err := io.WriteString(out, zshInit); err != nil {
					return err
				}
				err = root.GenZshCompletion(out)
				suffix = zshCompletion
			case "fish":
				err = root.GenFishCompletion(out, true)
				suffix = fishCompletion
			default:
				return fmt.Errorf("unknown shell %q; supported shells: bash, zsh, fish", args[0])
			}
			if err != nil {
				return err
			}
			_, err = io.WriteString(out, suffix)
			return err
		},
	}
}

// Preserve argument boundaries and dispatch git age without relying on Fish's
// version-specific completion support for custom Git commands.
const fishCompletion = `
function __git_age_perform_completion
    set -l args (commandline -opc)
    set -l lastArg (commandline -ct)
    set -l results (GIT_AGE_ACTIVE_HELP=0 $args[1] __complete $args[2..-1] "$lastArg" 2>/dev/null)
    set -l flagPrefix (string match -r -- '-.*=' "$lastArg")
    for comp in $results[1..-2]
	printf '%s%s\n' "$flagPrefix" "$comp"
    end
    printf '%s\n' "$results[-1]"
end
function __git_age_git_args
    set -l args (commandline -opc)
    set -e args[1]
    argparse -s C= c=+ p/paginate P/no-pager G/git-dir= W/work-tree= -- $args 2>/dev/null; or return
    test "$argv[1]" = age; or return 1
    printf '%s\n' $argv[2..-1]
end
function __git_age_git_completion
    set -l args (__git_age_git_args)
    set -l line (string join ' ' -- (string escape -- git-age $args (commandline -ct)))
    complete -C "$line"
end
complete -c git -n '__git_age_git_args >/dev/null' -f -a '(__git_age_git_completion)'
`

// Cobra invokes the completer during autoload, before the wrapper below exists.
const zshInit = `#compdef git-age
[[ ${words[1]-} != age ]] || words[1]=git-age
`

// Carapace and other Git completers may not dispatch to _git-age.
const zshCompletion = `
functions[_git_age_main]=$functions[_git-age]
_git-age() {
    local -a words=("${words[@]}")
    [[ ${words[1]} != age ]] || words[1]=git-age
    _git_age_main "$@"
}
if [[ ${_comps[git]-} != _git_age_git ]]; then
    typeset -g _git_age_previous_git_completion=${_comps[git]:-_git}
fi
autoload -Uz _git
_git_age_git() {
    if [[ ${words[2]} == age ]]; then
	_git "$@"
    else
	"$_git_age_previous_git_completion" "$@"
    fi
}
compdef _git_age_git git
`

// Git calls _git_age for its subcommand; standalone Bash needs no bash-completion package.
const bashCompletion = `
_git_age_main() {
    local words=("${COMP_WORDS[@]:0:COMP_CWORD+1}") cur out directive i
    words[COMP_CWORD]=${words[COMP_CWORD]-}
    COMPREPLY=()
    for ((i=1; i<${#words[@]}; i++)); do
	if [[ ${words[i]} == = && ${words[i-1]} == -* ]]; then
	    words[i-1]+="=${words[i+1]-}"
	    words=("${words[@]:0:i}" "${words[@]:i+2}")
	fi
    done
    cur=${words[${#words[@]}-1]}
    out=$("${words[0]}" __completeNoDesc "${words[@]:1}" 2>/dev/null) || return
    directive=${out##*:}
    out=${out%:*}
    out=${out%$'\n'}
    [[ $cur != -*=* ]] || cur=${cur#*=}
    __git-age_process_completion_results
    if ((directive == 0 && ${#COMPREPLY[@]} == 0)); then
	while IFS= read -r i; do COMPREPLY+=("$i"); done < <(compgen -f -- "$cur")
    fi
}
_git_age() {
    local COMP_WORDS=(git-age "${words[@]:${__git_cmd_idx:-1}+1}")
    local COMP_CWORD=$((cword-${__git_cmd_idx:-1}))
    _git_age_main
}
complete -o default -F _git_age_main git-age
`
