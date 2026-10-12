package cli

import "runtime/debug"

// version is set at build time for release builds:
//
//	-ldflags "-X github.com/arthurmartelli/git-age/internal/cli.version=v1.2.3"
var version string

// buildVersion returns the release version, the module version for
// go install builds, or "devel".
func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "devel"
}
