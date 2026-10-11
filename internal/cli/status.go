package cli

import (
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newStatusCommand(options *globalOptions) *cobra.Command {
	var porcelain, nullTerminated bool

	status := &cobra.Command{
		Use:   "status [PATH ...]",
		Short: "show working-tree state of protected files",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := repository.ProtectedFiles(options.directory, args)
			if err != nil {
				return err
			}
			statuses, target, err := repository.Statuses(options.directory, files)
			if err != nil {
				return err
			}

			porcelain = porcelain || nullTerminated
			var output strings.Builder
			var stale []string
			for i, file := range files {
				status := statuses[i]
				if status.Stale {
					stale = append(stale, file.Path)
				}
				if porcelain {
					path, terminator := file.Path, "\n"
					if nullTerminated {
						terminator = "\x00"
					} else {
						path = quoteStatusPath(path)
					}
					state, flag := string(file.State[:1]), "."
					if file.State == repository.Unknown {
						state = "?"
					}
					if status.Stale {
						flag = "S"
					} else if status.NoAccess {
						flag = "N"
					}
					fmt.Fprintf(&output, "%s%s %s%s", state, flag, path, terminator)
					continue
				}
				note := ""
				if status.NoAccess {
					note = " (no access)"
				}
				fmt.Fprintf(&output, "%-10s %s%s\n", file.State, file.Path, note)
				if options.verbose {
					fmt.Fprintf(&output, "           matched %s:%d: %s\n", file.RuleFile, file.RuleLine, file.Pattern)
					fmt.Fprintf(&output, "           encrypted to %s\n", status.Target)
				}
			}
			if !porcelain && options.verbose {
				fmt.Fprintf(&output, "encrypting to: %s\n", target)
			}
			if _, err := fmt.Fprint(cmd.OutOrStdout(), output.String()); err != nil || porcelain || len(stale) == 0 {
				return err
			}
			var warning strings.Builder
			warning.WriteString("\ngit-age: these files are still encrypted to a previous [recipients] list (run `git-age rekey`):\n")
			for _, path := range stale {
				fmt.Fprintf(&warning, "  %s\n", quoteStatusPath(path))
			}
			_, err = fmt.Fprint(cmd.ErrOrStderr(), warning.String())
			return err
		},
	}
	status.Flags().BoolVar(&porcelain, "porcelain", false, "stable machine-readable output")
	status.Flags().BoolVarP(&nullTerminated, "z", "z", false, "NUL-terminate porcelain records; implies --porcelain")
	return status
}

func quoteStatusPath(path string) string {
	var quoted strings.Builder
	for _, char := range path {
		switch char {
		case '"', '\\':
			quoted.WriteByte('\\')
			quoted.WriteRune(char)
		case '\t':
			quoted.WriteString("\\t")
		case '\n':
			quoted.WriteString("\\n")
		default:
			if char < 0x20 || char == 0x7f {
				fmt.Fprintf(&quoted, "\\%03o", char)
			} else {
				quoted.WriteRune(char)
			}
		}
	}
	if quoted.String() == path {
		return path
	}
	return "\"" + quoted.String() + "\""
}
