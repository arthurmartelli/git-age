# TODO

## Large

- [ ] Replace `audit --rekey` (`HistoryRewrite`, `run_history_rekey`,
  `_rewritable_refs`, `_update_refs`, `_without_signature`) with a documented
  `git filter-repo --blob-callback` recipe.

  It is a mini git-filter-repo and the largest maintenance surface. Keep
  `audit` itself, which pre-push uses. At least drop `--plaintext-only` and
  `--keep-undecryptable`.

## Medium

- [ ] Test on macOS and Windows.

  Add `macos-latest` and `windows-latest` to CI; no test runs the macOS and
  Windows branches of the safe replacement today.

- [ ] Keep only the pinned recipients hash from `git-age trust`.

  Remove the "last changed by someone else" warning, which relies on
  `user.email` and protects against the same threat less reliably.

- [ ] Improve gitignore pattern matching to follow Git semantics more exactly.

## Small

- [ ] Remove the chown branch from metadata preservation.

  A non-root user normally cannot change file ownership. Keep chmod, xattrs
  and ACL preservation.
