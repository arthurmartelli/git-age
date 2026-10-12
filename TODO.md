# TODO

Pending work on the Go port before merging `go-port` into `main`.

## Before merge

- [x] **Support every age recipient and identity type.** Recipient parsing only
  accepts X25519 and `ssh-` keys (`internal/repository/lock.go:348`), and
  identities go through `age.ParseIdentities` (`identities.go:104`). Plugin
  recipients and identities (`age1yubikey1…`, `age1se1…`, `age1tpm1…`,
  `AGE-PLUGIN-…`) and post-quantum `age1pq1…` recipients are rejected. Use
  `filippo.io/age/plugin` and `age.ParseRecipients`. Also make "your own public
  key" detection (`identities.go:109-113`) work for these types.
- [x] **Reuse ciphertext when recipients come from `-r`, `GIT_AGE_RECIPIENT` or
  `age.recipient`.** `external` disables reuse (`lock.go:154-169`, `lock.go:289`,
  `clean.go:59`), so every `lock` rewrites files, unchanged unlocked files show
  as modified, and unrelated commits re-encrypt secrets.
- [x] **Only disable reuse when the effective `[recipients]` change.** Any byte
  change to a parent `.gitage` (even a comment or a new `[files]` line) currently
  re-encrypts every file under it (`lock.go:368,410,427-440`).
- [x] **Keep `edit`'s plaintext copy out of the shared temp directory.** It uses
  `os.MkdirTemp("")` (`edit.go:26`). Put it in a 0700 directory under `.git` and
  clean it up on SIGHUP/SIGTERM. Then fix the "private temporary file" wording
  (`manual.txt:89`).
- [x] **Don't kill the editor on Ctrl-C.** `CommandContext` cancels the editor
  when the command is interrupted. Let the editor handle SIGINT and report
  its exit status.
- [x] **Fix the release concurrency deadlock.** `release.yml` calls `test.yml`, and
  both use `${{ github.workflow }}-${{ github.ref }}`, which resolves to the same
  group in a called workflow. Add a `-test` suffix to block from `test.yml`
  and verify with a throwaway tag.
- [x] **Update the manual.** DEPENDENCIES still lists Python 3.9+, age and
  age-keygen (`manual.txt:1039-1047`). `--version` is missing from global options
  (`manual.txt:162-166`). Align the indentation of new lines (tabs vs spaces).

## Correctness

- [ ] `check --staged` doesn't report stale recipients; only the pre-commit hook
  computes them (`repository/check.go:166`).
- [ ] Stale-recipient detection only compares against HEAD (`commit.go:108-158`),
  so files left stale by earlier commits aren't flagged. Add rekey/`git add`
  advice to the warning.
- [ ] `lock` doesn't warn about stale recipients afterwards (`cli/lock.go:89-108`).
- [ ] `unlock`, `rekey` and `edit` don't refresh the `.git/info/attributes` block;
  only `lock` and the hooks do.
- [ ] Reject invalid `GIT_AGE_ALLOW_*` values (e.g. `maybe`) instead of silently
  treating them as false (`cli/check.go:107-110`).
- [ ] Expand `~` in `-i`, `GIT_AGE_KEY_FILE` and `age.keyFile` paths
  (`identities.go:59,76`, `git.go:79`).
- [ ] Skip empty `GIT_AGE_KEY_FILE` entries (`a::b`) and de-duplicate identity
  paths.
- [ ] Decide whether an empty value should clear earlier values for every config
  key or only `age.keyFile` (`identities.go:17-35`); treat whitespace-only as
  empty.
- [ ] Handle lone `\r` line endings in `.gitage` (`files.go:224`); they currently
  error.
- [ ] Tolerate a BEGIN marker without END in `.git/info/attributes`
  (`attributes.go:324`), or give a clear repair message.

## UX

- [ ] Help topic lookup: match by section word, unique prefix and any case
  (`help hooks`, `help team`, `help INTEG`), and list topics on an unknown or
  ambiguous name (`cli/help.go:55-71`). Decide whether sections or commands win
  for `help trust`.
- [x] Page `help` output through `GIT_PAGER`/`PAGER`/`less -FRX` on a terminal.
- [x] Handle Ctrl-C globally with a clean message.
- [ ] `install`: warn when `git-age` isn't on `PATH` (hooks run `git age`).
- [x] `uninstall`: mention which user config keys were kept (`age.keyFile`,
  `age.recipient`, `age.trustedRecipients`).

## CI and release

- [x] Add a `toolchain go1.25.N` line to `go.mod` (or use `go-version: 1.25.x`) so
  releases get Go patch releases.
- [x] Add `gomod` to `.github/dependabot.yml`.
- [x] Publish pre-release tags (`v1.0.0-rc1`) with binaries and checksums, marked
  as prereleases and never latest (`release.yml`).
- [x] `SECURITY.md`: say "latest release" instead of "latest version on `main`".
- [x] README: mention `darwin` in release file names; mention `go vet` alongside
  `go test`; `script` is required (not optional) for Unix interactive tests
  (`terminal_unix_test.go:22-24`).

## Tests

- [x] `help`: topic matching, `--help` mentioning `git-age help`.
- [ ] Plaintext push refusal message includes `GIT_AGE_ALLOW_PLAINTEXT_PUSH=1`.
- [x] `edit` with a failing editor reports the exit status and that the file was
  not changed; also cover `EDITOR` (not just `GIT_EDITOR`).
- [ ] `lock -i` outside Git with no `[recipients]` encrypts to your own identity.
- [ ] `./path` arguments from a subdirectory.
- [ ] Unknown shell message for `completion`.
- [x] Ciphertext reuse with external recipients and after a comment-only
  `.gitage` change (regression tests for the items above).
