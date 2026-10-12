package cli

import (
	"strconv"

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
	boolFlag(flags, "no-"+name, "disable: "+help, func(enabled bool) { *target = enabled }, true)
}

// boolFlag calls set with the flag's value, inverted if negated.
func boolFlag(flags *pflag.FlagSet, name, help string, set func(bool), negated bool) {
	flags.BoolFunc(name, help, func(value string) error {
		b, err := strconv.ParseBool(value)
		set(b != negated)
		return err
	})
}
