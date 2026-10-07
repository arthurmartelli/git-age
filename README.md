# git-age

[![test](https://github.com/arthurmartelli/git-age/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/arthurmartelli/git-age/actions/workflows/test.yml)

Keep secrets in Git, encrypted with [age](https://github.com/FiloSottile/age).

A `.gitage` file defines which files are protected and who can decrypt them.
Private keys stay outside the repository. git-age is a single Python script
with no dependencies beyond Python, Git and age.

## Install

Requires Python 3.10+, Git, `age` and `age-keygen`.

```sh
curl -fsSLo ~/.local/bin/git-age https://raw.githubusercontent.com/arthurmartelli/git-age/main/git-age
chmod +x ~/.local/bin/git-age
```

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

git-age supports sharing secrets with a team. Each member keeps their own
private key outside the repository, and their public recipient is committed to
`[recipients]` in `.gitage`. Nested `.gitage` files can grant a member access
to only part of the repository.

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
./git-age-test.sh
```

The end-to-end test builds throwaway repositories in a temporary directory and
never touches your keys, config or hooks.

## License

[MIT](LICENSE)
