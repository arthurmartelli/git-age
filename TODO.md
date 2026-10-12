# TODO

Pending work on the Go port before merging `go-port` into `main`.

## Correctness

- [x] `check --staged` doesn't report stale recipients; only the pre-commit hook
  computes them (`repository/check.go:166`).
- [x] Stale-recipient detection only compares against HEAD (`commit.go:108-158`),
  so files left stale by earlier commits aren't flagged. Add rekey/`git add`
  advice to the warning.
- [x] `lock` doesn't warn about stale recipients afterwards (`cli/lock.go:89-108`).
- [x] `unlock`, `rekey` and `edit` don't refresh the `.git/info/attributes` block;
  only `lock` and the hooks do.
- [x] Reject invalid `GIT_AGE_ALLOW_*` values (e.g. `maybe`) instead of silently
  treating them as false (`cli/check.go:107-110`).
- [x] Expand `~` in `-i`, `GIT_AGE_KEY_FILE` and `age.keyFile` paths
  (`identities.go:59,76`, `git.go:79`).
- [x] Skip empty `GIT_AGE_KEY_FILE` entries (`a::b`) and de-duplicate identity
  paths.
- [x] Decide whether an empty value should clear earlier values for every config
  key or only `age.keyFile` (`identities.go:17-35`); treat whitespace-only as
  empty.
- [x] Handle lone `\r` line endings in `.gitage` (`files.go:224`); they currently
  error.
- [ ] The ciphertext fingerprint cache in `.git/git-age/recipients`
  (`repository/recipients_cache.go`) gains one file per encryption and is never
  pruned. `uninstall` doesn't remove it either. When pruning, keep entries for
  ciphertext in the index (all stages), HEAD, and locked protected files in the
  working tree, since `lock` records the fingerprint before the file is staged.
  Also keep entries newer than a grace period (e.g. 30 days), so ciphertext on
  other branches or in the stash survives a branch switch. Remove the directory
  on uninstall.
- [x] Tolerate a BEGIN marker without END in `.git/info/attributes`
  (`attributes.go:324`), or give a clear repair message.

## UX

- [ ] Help topic lookup: match by section word, unique prefix and any case
  (`help hooks`, `help team`, `help INTEG`), and list topics on an unknown or
  ambiguous name (`cli/help.go:55-71`). Decide whether sections or commands win
  for `help trust`.
- [ ] `install`: warn when `git-age` isn't on `PATH` (hooks run `git age`).
- [ ] `uninstall`: the "Kept user Git config" message reads every config scope
  (`git config --get-regexp` without `--local`, `repository/uninstall.go:92`),
  so a global `age.keyFile` is reported as kept in the repo. Query `--local` only.

## Tests

- [ ] `help`: topic matching (blocked on the UX item above; `TestHelpTopic` only
  checks exact names). `--help` still doesn't mention `git-age help`: Cobra's
  footer says `Use "git-age [command] --help"`. Change the footer, then test it.
- [ ] Plaintext push refusal message includes `GIT_AGE_ALLOW_PLAINTEXT_PUSH=1`.
- [ ] `lock -i` outside Git with no `[recipients]` encrypts to your own identity.
- [ ] `./path` arguments from a subdirectory.
- [ ] Unknown shell message for `completion`.
