# git-age

[![test](https://github.com/arthurmartelli/git-age/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/arthurmartelli/git-age/actions/workflows/test.yml)

Keep secrets in Git, encrypted with [age](https://github.com/FiloSottile/age).

A `.gitage` file defines which files are protected and who can decrypt them. Private keys stay outside the repository. git-age is a single Go executable with age built in. Git is its only runtime dependency.

## Install

Requires Git. Install with Go 1.25+:

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
```

Shell completion for bash, zsh and fish: `git-age completion SHELL`.

## Tests

```sh
go test ./...
./test.sh
```

Go tests cover migrated command handlers directly and verify that the Linux binary is static. The shell script builds the Go binary and runs the end-to-end tests in throwaway repositories. It never touches your keys, config or hooks.

Tests require Go 1.25+, Bash, Git, `age`, `age-keygen` and Perl. Set `GIT_AGE=/absolute/path/to/git-age` to test an existing executable without rebuilding.

## License

[MIT](LICENSE)
