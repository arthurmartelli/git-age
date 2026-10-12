# TODO

Pending work on the Go port before merging `go-port` into `main`.

## Correctness

- [x] Cache pruning reads every blob in HEAD's tree, not just protected files
  (`liveCiphertextHashes`, `repository/recipients_cache.go`). Expired records
  that are still live are kept but never touched, so once any record is older
  than 30 days, every encrypting command scans the whole tree again. Limit the
  scan to protected paths, and refresh the mtime of live records you keep.

## UX

- [x] Help topic lookup: match by section word, unique prefix and any case
  (`help hooks`, `help team`, `help INTEG`), and list topics on an unknown or
  ambiguous name (`cli/help.go:55-71`). Decide whether sections or commands win
  for `help trust`.
- [x] `install`: warn when `git-age` isn't on `PATH` (hooks run `git age`).
- [x] `uninstall`: the "Kept user Git config" message reads every config scope
  (`git config --get-regexp` without `--local`, `repository/uninstall.go:92`),
  so a global `age.keyFile` is reported as kept in the repo. Query `--local` only.

## Tests

- [x] `help`: topic matching (blocked on the UX item above; `TestHelpTopic` only
  checks exact names). `--help` still doesn't mention `git-age help`: Cobra's
  footer says `Use "git-age [command] --help"`. Change the footer, then test it.
- [ ] Plaintext push refusal message includes `GIT_AGE_ALLOW_PLAINTEXT_PUSH=1`.
- [ ] `lock -i` outside Git with no `[recipients]` encrypts to your own identity.
- [ ] `./path` arguments from a subdirectory.
- [ ] Unknown shell message for `completion`.
- [ ] Flaky: `TestTrustPinsAndLockRefusesChanges` failed once with
  `lstat .git/objects/maintenance.lock: no such file or directory` and passed
  in 10 reruns. Git's background auto-maintenance races `installSnapshot` walking
  `.git`. Set `maintenance.auto=false` and `gc.auto=0` in the tests' isolated Git
  config.
