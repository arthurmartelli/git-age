package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

func recipientFlags(flags *pflag.FlagSet, recipients *[]string) {
	flags.StringArrayVarP(recipients, "recipient", "r", nil, "age recipient used for encryption; may be repeated")
}

func identityFlags(flags *pflag.FlagSet, identities *[]string) {
	flags.StringArrayVarP(identities, "identity", "i", nil, "age identity file; may be repeated")
}

func booleanFlags(flags *pflag.FlagSet, name string, target *bool, help string) {
	flags.BoolVar(target, name, true, help)

	flags.BoolFunc("no-"+name, "disable: "+help, func(value string) error {
		b, err := strconv.ParseBool(value)
		*target = !b

		return err
	})
}

func choice(value string, choices ...string) error {
	for _, allowed := range choices {
		if value == allowed {
			return nil
		}
	}

	return fmt.Errorf("invalid choice: '%s' (choose from %s)", value, strings.Join(choices, ", "))
}
