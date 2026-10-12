package cli

import (
	"bytes"
	_ "embed"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed manual.txt
var manual string

func newHelpCommand() *cobra.Command {
	sections := map[string]string{}
	headings := regexp.MustCompile(`(?m)^[A-Z.][A-Z .-]*\n-{3,}\n`).FindAllStringIndex(manual, -1)
	for i, heading := range headings {
		end := len(manual)
		if i+1 < len(headings) {
			end = headings[i+1][0]
		}
		name := strings.SplitN(manual[heading[0]:heading[1]], "\n", 2)[0]
		name = strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(name, ".")), " ", "-")
		sections[name] = strings.TrimSpace(manual[heading[0]:end]) + "\n"
	}
	return &cobra.Command{
		Use:   "help [TOPIC|COMMAND ...]",
		Short: "show the manual or a command's options",
		Args:  cobra.ArbitraryArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			var names []string
			if len(args) == 0 {
				for name := range sections {
					names = append(names, name)
				}
				for _, command := range cmd.Root().Commands() {
					if !command.Hidden {
						names = append(names, command.Name())
					}
				}
			} else if parent, rest, err := cmd.Root().Find(args); err == nil && len(rest) == 0 {
				for _, command := range parent.Commands() {
					if !command.Hidden {
						names = append(names, command.Name())
					}
				}
			}
			slices.Sort(names)
			return names, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return writeHelp(cmd, manual)
			}
			if section, ok := sections[args[0]]; len(args) == 1 && ok {
				return writeHelp(cmd, section)
			}

			root := cmd.Root()
			topic, rest, err := root.Find(args)
			if err != nil || topic == root || len(rest) != 0 {
				return fmt.Errorf("unknown help command %q (see git-age --help)", strings.Join(args, " "))
			}

			topic.InitDefaultHelpFlag()
			var output bytes.Buffer
			previous := topic.OutOrStdout()
			topic.SetOut(&output)
			err = topic.Help()
			topic.SetOut(previous)
			if err != nil {
				return err
			}
			return writeHelp(cmd, output.String())
		},
	}
}
