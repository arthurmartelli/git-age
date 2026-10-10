package cli

import (
	"io"

	"github.com/spf13/cobra"
)

func newCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:       "completion SHELL",
		ValidArgs: []string{"bash", "zsh", "fish"},
		Short:     "print the shell completion script for bash, zsh or fish",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			return choice(args[0], "bash", "zsh", "fish")
		},
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
				return root.GenFishCompletion(out, true)
			}
			if err != nil {
				return err
			}
			_, err = io.WriteString(out, suffix)
			return err
		},
	}
}

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
