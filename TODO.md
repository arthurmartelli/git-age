# TODO

## Large

- [ ] Replace `audit --rekey` (`HistoryRewrite`, `run_history_rekey`,
  `_rewritable_refs`, `_update_refs`, `_without_signature`) with a documented
  `git filter-repo --blob-callback` recipe.

  It is a mini git-filter-repo and the largest maintenance surface. Keep
  `audit` itself, which pre-push uses. At least drop `--plaintext-only` and
  `--keep-undecryptable`.

## Medium

- [ ] Improve gitignore pattern matching to follow Git semantics more exactly.
