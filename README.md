# git-age

[![test](https://github.com/arthurmartelli/git-age/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/arthurmartelli/git-age/actions/workflows/test.yml)

Keep secrets in Git, encrypted with [age](https://github.com/FiloSottile/age).

A `.gitage` file defines which files are protected and who can decrypt them. Private keys stay outside the repository. git-age is a single Go executable with age built in. Git is its only runtime dependency.

## Install

Requires Git.

Download a prebuilt executable for Linux, macOS or Windows from the [releases page](https://github.com/arthurmartelli/git-age/releases), check it against `checksums.txt`, rename it to `git-age` (`git-age.exe` on Windows), make it executable and put it on your `PATH`.

Release files are named `git-age_<tag>_<os>_<arch>`, with `.exe` on Windows. macOS files use `darwin` for `<os>`, such as `git-age_v1.0.0_darwin_arm64`.

Or install with Go 1.26+:

```sh
CGO_ENABLED=0 go install github.com/arthurmartelli/git-age/cmd/git-age@latest
```

Go installs the executable in `GOBIN`, or `$(go env GOPATH)/bin` by default. Add that directory to your `PATH`.

With `git-age` on your `PATH`, Git also runs it as `git age`.

## Quick start

Create a `.gitage` file:

```sh
printf '[files]\nsecret.env\n' > .gitage
```

Generate a key and install the Git integration:

```sh
git-age keygen
git-age install
```

Encrypt protected files and commit them:

```sh
git-age lock
git add -A
git commit
```

Decrypt them when you need to work on them:

```sh
git-age unlock
```

Move your private key outside the repository:

```sh
mkdir -p ~/.config/git-age
mv .gitage.key ~/.config/git-age/myrepo.key
git config age.keyFile ~/.config/git-age/myrepo.key
```

## Teams

git-age supports sharing secrets with a team. Each member keeps their own private key outside the repository, and their public recipient is committed to `[recipients]` in `.gitage`. Nested `.gitage` files can grant a member access to only part of the repository.

Adding and removing members, and limiting access, are covered in the manual:

```sh
git-age help teamwork
```

## Documentation

The full manual is built in:

```sh
git-age help            # the whole manual
git-age help TOPIC      # one section, e.g. `git-age help teamwork`
git-age help COMMAND    # a command's options
git-age help history rekey  # a history subcommand's options
```

Inspect history with `git-age history audit`. To encrypt plaintext and
re-encrypt protected history for the current recipients, preview with
`git-age history rekey --dry-run`, then run `git-age history rekey`.
This rewrites local branches, tags and the stash, and keeps the original
refs for recovery. See `git-age help history-rekey` for the full workflow.

Shell completion for bash, zsh and fish: `git-age completion SHELL`.

## Tests

```sh
go vet ./...
go test ./...
```

Go tests cover command handlers and integration workflows with real Git hooks, filters, diffs, merges, pushes, interactive commits and history rewrites in temporary repositories. They also check file metadata, compatibility with the age CLI, and static linking on Linux. The tests isolate their Git configuration and keys.

Tests require Go 1.26+, Git, Bash, `age` and `age-keygen`. Unix interactive tests require `script` and fail if it is missing. Linux metadata tests use `acl` and `attr`; macOS and Windows use their built-in metadata tools. Metadata checks skip when the filesystem lacks support. Install zsh and fish to run their completion tests too. CI runs the suite on Linux, macOS and Windows.

## License

[MIT](LICENSE)
