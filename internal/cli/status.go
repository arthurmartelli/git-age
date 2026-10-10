package cli

import (
	"fmt"
	"strings"

	"github.com/arthurmartelli/git-age/internal/repository"
	"github.com/spf13/cobra"
)

func newStatusCommand() *cobra.Command {
	var porcelain, nullTerminated bool

	status := &cobra.Command{
		Use:   "status [PATH ...]",
		Short: "show working-tree state of protected files",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			directory, err := cmd.Flags().GetString("directory")
			if err != nil {
				return err
			}
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}
			files, err := repository.ProtectedFiles(directory, args)
			if err != nil {
				return err
			}

			for _, file := range files {
				var line string
				if porcelain || nullTerminated {
					path, terminator := file.Path, "\n"
					if nullTerminated {
						terminator = "\x00"
					} else {
						path = quoteStatusPath(path)
					}
					line = fmt.Sprintf("%s. %s%s", file.State[:1], path, terminator)
					if file.State == "UNKNOWN" {
						line = "?" + line[1:]
					}
				} else {
					line = fmt.Sprintf("%-10s %s\n", file.State, file.Path)
					if verbose {
						line += fmt.Sprintf("           matched %s:%d: %s\n", file.RuleFile, file.RuleLine, file.Pattern)
					}
				}
				if _, err := fmt.Fprint(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			return nil
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
