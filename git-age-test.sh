#!/usr/bin/env bash
#
# git-age-test.sh: end-to-end test for git-age.
#
# Builds a throwaway repository with two protected files, walks through a
# normal team workflow, then checks that the main failure cases are refused.
#
# Usage:
#   git-age-test.sh            # test the git-age next to this script
#   GIT_AGE=/path/to/git-age git-age-test.sh
#   KEEP=1 git-age-test.sh     # keep the temporary directory for inspection
#
# Requires: git, age, age-keygen, python3. Runs on Linux, macOS and Windows
# (Git Bash).

set -euo pipefail

case $(uname -s) in
  Darwin) platform=macos ;;
  MINGW* | MSYS* | CYGWIN*) platform=windows ;;
  *) platform=linux ;;
esac

GIT_AGE=${GIT_AGE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/git-age}
for tool in git age age-keygen; do
  command -v "$tool" >/dev/null || { echo "missing dependency: $tool" >&2; exit 2; }
done
[[ -x $GIT_AGE ]] || { echo "git-age not found or not executable: $GIT_AGE" >&2; exit 2; }

# --- isolated environment ----------------------------------------------------

tmp=$(mktemp -d "${TMPDIR:-/tmp}/git-age-test.XXXXXX")
if [[ ${KEEP:-0} == 1 ]]; then trap 'echo "kept: $tmp"' EXIT; else trap 'rm -rf "$tmp"' EXIT; fi
# git-age's temporary files land here too, where the test can look for them.
export TMPDIR=$tmp

# Never touch the user's keys, config or hooks.
unset GIT_AGE_KEY_FILE GIT_AGE_RECIPIENT GIT_AGE_HOOK_MODE GIT_AGE_UNLOCK_AFTER_COMMIT \
  GIT_AGE_ALLOW_PRIVATE_KEYS GIT_AGE_ALLOW_STALE_RECIPIENTS GIT_AGE_ALLOW_EMPTY \
  GIT_AGE_ALLOW_REMOVE GIT_AGE_ALLOW_PLAINTEXT_PUSH GIT_EDITOR VISUAL
export GIT_CONFIG_GLOBAL=$tmp/gitconfig GIT_CONFIG_NOSYSTEM=1
printf '[user]\nname = git-age test\nemail = test@example.invalid\n[init]\ndefaultBranch = main\n' \
  >"$GIT_CONFIG_GLOBAL"

# The test runs `git-age`, and hooks `git age`: put the one under test first.
mkdir -p "$tmp/bin" "$tmp/keys"
ln -s "$GIT_AGE" "$tmp/bin/git-age"
export PATH=$tmp/bin:$PATH
# Python for Windows calls python3 python.
if ! command -v python3 >/dev/null && command -v python >/dev/null; then
  printf '#!/bin/sh\nexec python "$@"\n' >"$tmp/bin/python3" && chmod +x "$tmp/bin/python3"
fi
command -v python3 >/dev/null || { echo "missing dependency: python3" >&2; exit 2; }

for name in alice bob carol dave; do
  age-keygen -o "$tmp/keys/$name" 2>/dev/null
  printf -v "$name" '%s' "$(age-keygen -y "$tmp/keys/$name")"
done

# --- helpers -------------------------------------------------------------------

passed=0 failed=0
section() { printf '\n== %s\n' "$*"; }
skip() { printf '  skip  %s\n' "$*"; }

# check DESCRIPTION COMMAND... | check DESCRIPTION 'CONDITION': it must succeed.
# refuse DESCRIPTION TEXT COMMAND...: it must fail and print TEXT.
# warns DESCRIPTION TEXT COMMAND...: it must succeed and print TEXT.
# A single argument is evaluated as shell code, without pipefail so that
# `cmd | grep -q` cannot fail on SIGPIPE.
check() { _expect 0 "$1" "" "${@:2}"; }
refuse() { _expect 1 "$@"; }
warns() { _expect 0 "$@"; }
_expect() {
  local want=$1 description=$2 text=$3 output status=0; shift 3
  output=$(set +o pipefail; if (($# == 1)); then eval "$1"; else "$@"; fi 2>&1 </dev/null) || status=$?
  if (((status != 0) == want)) && grep -qF -- "$text" <<<"$output"; then
    passed=$((passed + 1)); printf '  ok    %s\n' "$description"
  else
    failed=$((failed + 1)); printf '  FAIL  %s (exit %d)\n' "$description" "$status"
    printf '%s\n' "${text:+expected: $text}" "$*" "$output" | sed '/^$/d; s/^/        | /'
  fi
}

not() { ! "$@"; }
commit() { git commit -q -m "$1" </dev/null; }
# commit_unchecked MESSAGE: commit what is staged, skipping the hooks.
commit_unchecked() { git commit -q --no-verify -m "$1" </dev/null; }
clean_tree() { [[ -z $(git status --porcelain) ]]; }
lock() { git-age lock "$@" >/dev/null; }
unlock() { git-age unlock "$@" >/dev/null; }
as() { local who=$1; shift; GIT_AGE_KEY_FILE=$tmp/keys/$who git-age "$@"; }
mode_is() { [[ $(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777)[2:])' "$1") == "$2" ]]; }
# drop_carol: remove carol's entry from .gitage.
drop_carol() { grep -v -e '^# Carol$' -e "^$carol\$" .gitage >.gitage.new && mv .gitage.new .gitage; }

# gitage [RECIPIENT...]: a .gitage protecting *.env for RECIPIENTs.
gitage() {
  printf '[files]\n*.env\n'
  if (($#)); then printf '\n[recipients]\n'; printf '%s\n' "$@"; fi
}
# new_repo NAME [RECIPIENT...]: enter a new repository that uses alice's key
# and protects *.env for RECIPIENTs.
new_repo() {
  mkdir -p "$tmp/$1" && cd "$tmp/$1" && git init -q && git config age.keyFile "$tmp/keys/alice"
  shift
  gitage "$@" >.gitage
}

# is_locked FILE...: every FILE is age ciphertext; staged_is_locked: as staged.
is_locked() { local f; for f; do head -c 21 "$f" | grep -q '^age-encryption.org/v1' || return 1; done; }
staged_is_locked() { git show ":$1" | head -c 21 | grep -q '^age-encryption.org/v1'; }
# decrypts_as WHO FILE CONTENT, head_decrypts_as WHO PATH CONTENT: WHO's key
# decrypts FILE, or PATH as committed, to CONTENT.
decrypts_as() { [[ $(age -d -i "$tmp/keys/$1" "$2" 2>/dev/null) == "$3" ]]; }
head_decrypts_as() { [[ $(git show "HEAD:$2" | age -d -i "$tmp/keys/$1" 2>/dev/null) == "$3" ]]; }
# status_is [ARGS...] -- RECORD...: `git-age ARGS... status --porcelain` prints these.
status_is() {
  local args=()
  while [[ $1 != -- ]]; do args+=("$1"); shift; done
  shift
  [[ $(git-age "${args[@]}" status --porcelain 2>/dev/null) == "$(printf '%s\n' "$@")" ]]
}
# stage_plaintext FILE...: stage FILE's bytes as they are, bypassing Git's filters.
stage_plaintext() {
  local f
  for f; do git update-index --add --cacheinfo "100644,$(git hash-object -w --no-filters "$f"),$f"; done
}
# forget_stat FILE...: make Git compare FILE by content, as once it changes.
forget_stat() { git ls-files -s "$@" | git update-index --index-info; }
# file_list: every path in the working tree, to compare.
file_list() { find . -path ./.git -prune -o -print | LC_ALL=C sort; }

# on_terminal COMMAND: run COMMAND on a pseudo-terminal, typing stdin into it.
# Read all its output: if the reader stops early, COMMAND hangs.
on_terminal() {
  python3 -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(["sh", "-c", sys.argv[1]])))' "$1"
}
# without_terminal COMMAND...: run COMMAND without a controlling terminal,
# which native Windows programs never have.
without_terminal() {
  if [[ $platform == windows ]]; then "$@"
  elif command -v setsid >/dev/null; then setsid -w "$@"
  else python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@"
  fi
}
# answer REPLIES MESSAGE: commit on a terminal, answering the hook's prompt.
answer() { printf '%b' "$1" | on_terminal "git commit -q -m '$2'"; }

# --- a team workflow -----------------------------------------------------------

section "lock, unlock and status"

new_repo repo
mkdir config
echo 'API_TOKEN=s3cr3t' >secret.env
echo 'password: hunter2' >config/credentials.yaml
printf '[files]\nsecret.env\nconfig/*.yaml\n\n[recipients]\n# Alice\n%s\n# Bob\n%s\n' "$alice" "$bob" >.gitage

check "status lists both files as unlocked" \
  'git-age status | grep -q "^UNLOCKED *config/credentials.yaml" &&
   status_is -- "U. config/credentials.yaml" "U. secret.env" &&
   git-age status -z | tr "\0" "\n" | grep -qx "U. secret.env"'
check "lock encrypts them to the recipients only" \
  'git-age lock && is_locked secret.env config/credentials.yaml &&
   decrypts_as bob secret.env API_TOKEN=s3cr3t && not decrypts_as carol secret.env API_TOKEN=s3cr3t'
check "unlock restores the plaintext" 'git-age unlock && grep -qx API_TOKEN=s3cr3t secret.env'

files=$(file_list)
# root and Windows read files whatever their mode.
if [[ $platform != windows && $(id -u) -ne 0 ]]; then
  chmod 000 secret.env
  refuse "lock fails on an unreadable file" secret.env git-age lock
  chmod 644 secret.env
  check "locking neither file, leaving no stray files" \
    'not is_locked config/credentials.yaml && [[ $(file_list) == "$files" ]]'
else
  skip "unreadable files"
fi
lock
age -r "$carol" -o secret.env <<<'API_TOKEN=s3cr3t'
refuse "unlock fails on a file it cannot decrypt" secret.env git-age unlock
check "unlocking neither file, leaving no stray files" \
  'is_locked config/credentials.yaml && [[ $(file_list) == "$files" ]]'
echo 'API_TOKEN=s3cr3t' >secret.env
unlock

section "lock and unlock keep file metadata"

# set_metadata gives secret.env a mode, an ACL and an extended attribute, or
# their Windows equivalents, credentials.yaml a mode, and config/ an ACL that
# new files inherit; metadata_kept checks that all of it survived, and no more.
case $platform in
  linux)
    has_acl() { getfacl -cn "$2" 2>/dev/null | grep -q "^$1"; }
    set_metadata() {
      command -v setfacl >/dev/null && setfacl -m u:65534:r secret.env 2>/dev/null &&
        python3 -c 'import os; os.setxattr("secret.env", "user.test", b"kept")' 2>/dev/null &&
        chmod 640 secret.env && chmod 600 config/credentials.yaml && setfacl -d -m u:65534:rw config
    }
    metadata_kept() {
      mode_is secret.env 640 && mode_is config/credentials.yaml 600 && has_acl user:65534:r-- secret.env &&
        [[ $(python3 -c 'import os; print(os.getxattr("secret.env", "user.test").decode())') == kept ]] &&
        not has_acl user:65534: config/credentials.yaml
    }
    ;;
  macos)
    has_acl() { ls -le "$2" | grep -qF "$1"; }
    set_metadata() {
      chmod 640 secret.env && chmod 600 config/credentials.yaml && chmod +a "everyone allow read" secret.env &&
        xattr -w user.test kept secret.env && chmod +a "everyone allow write,file_inherit,directory_inherit" config
    }
    metadata_kept() {
      mode_is secret.env 640 && mode_is config/credentials.yaml 600 &&
        has_acl "group:everyone allow read" secret.env && [[ $(xattr -p user.test secret.env) == kept ]] &&
        not has_acl group:everyone config/credentials.yaml
    }
    ;;
  windows)
    # Keep MSYS from turning icacls's /switches into paths.
    icacls() { MSYS2_ARG_CONV_EXCL='*' command icacls "$@"; }
    set_metadata() {
      icacls secret.env /grant '*S-1-1-0:(R)' >/dev/null &&
        python3 -c 'open("secret.env:test", "w").write("kept")' && attrib +R +H secret.env
    }
    metadata_kept() {
      python3 -c 'import os, stat, sys; a = os.stat("secret.env").st_file_attributes
sys.exit(not (a & stat.FILE_ATTRIBUTE_READONLY and a & stat.FILE_ATTRIBUTE_HIDDEN))' &&
        icacls secret.env | grep -qF "Everyone:(R)" &&
        [[ $(python3 -c 'print(open("secret.env:test").read())') == kept ]]
    }
    ;;
esac
cp secret.env config/credentials.yaml "$tmp/"
if set_metadata; then
  check "lock keeps it, adding none a file lacked" 'git-age lock && metadata_kept'
  check "so does unlock, leaving no stray files" 'git-age unlock && metadata_kept && [[ $(file_list) == "$files" ]]'
else
  skip "no ACL or extended attribute support here"
fi
# Fresh copies drop the metadata.
[[ $platform != windows ]] || attrib -R -H secret.env
rm -rf secret.env config && mkdir config && cp "$tmp/secret.env" . && cp "$tmp/credentials.yaml" config/

section "hooks and the clean filter"

check "install --mode=always-lock" git-age install --mode=always-lock
check "a commit of staged plaintext stores it encrypted" \
  'git add -A && commit "initial secrets" && head_decrypts_as alice secret.env API_TOKEN=s3cr3t &&
   head_decrypts_as bob config/credentials.yaml "password: hunter2"'
check "unchanged files lock to identical ciphertext" 'git-age unlock && git-age lock && clean_tree'
check "unlocked, they show no changes, and git add stages them encrypted" \
  'git-age unlock && clean_tree && git diff --quiet && git add -A && staged_is_locked secret.env'
check "an edit shows as modified until reverted" \
  'echo API_TOKEN=edited >secret.env && git status --porcelain | grep -qx " M secret.env" &&
   echo API_TOKEN=s3cr3t >secret.env && clean_tree'
check "without an identity, or after install --no-filter, they show as modified" \
  'forget_stat secret.env && git -c age.keyFile= status --porcelain | grep -qx " M secret.env" &&
   git-age install --mode=always-lock --no-filter >/dev/null && forget_stat secret.env &&
   git status --porcelain | grep -qx " M secret.env"'
check "installing and locking again leaves a clean tree" \
  'git-age install --mode=always-lock >/dev/null && lock && clean_tree'
unlock
echo 'API_TOKEN=rotated' >secret.env
check "a commit stores an edit encrypted, and git show diffs the plaintext" \
  'git add secret.env && commit "rotate token" && head_decrypts_as alice secret.env API_TOKEN=rotated &&
   git show HEAD -- secret.env | grep -qx "+API_TOKEN=rotated"'
check "git show without a key shows a placeholder" \
  'git -c age.keyFile= show --textconv HEAD:secret.env | grep -q "git-age: encrypted, no identity configured"'

section "adding a recipient"

lock
printf '# Carol\n%s\n' "$carol" >>.gitage
warns "status flags files encrypted to the previous list" "previous [recipients] list" git-age status
check "as LS in porcelain" 'git-age status --porcelain 2>&1 | grep -qx "LS secret.env"'
check "after rekey and commit, carol reads HEAD and nothing is stale" \
  'git-age rekey && git add -A && commit "add carol" &&
   head_decrypts_as carol secret.env API_TOKEN=rotated && ! git-age status 2>&1 | grep -q previous'
drop_carol
git add .gitage
refuse "the hook refuses a [recipients] change before rekey" "still encrypted to the previous list" \
  git commit -q -m "remove carol"
git reset -q --hard

section "refusals"

unlock
echo 'API_TOKEN=leak' >secret.env
git add secret.env
refuse "abort mode refuses staged plaintext" "commit aborted" env GIT_AGE_HOOK_MODE=abort git commit -q -m leak
git reset -q --hard
git-age keygen >/dev/null 2>&1
check "keygen keeps .gitage.key out of git add -A" 'git add -A && ! git diff --cached --name-only | grep -qx .gitage.key'
git add -f .gitage.key
refuse "the hook refuses a staged .gitage.key" "refusing to commit private age keys" git commit -q -m oops
git reset -q
cp "$tmp/keys/bob" leaked-key.txt
git add -f leaked-key.txt
refuse "and an unprotected file containing a key" leaked-key.txt git commit -q -m oops
git reset -q && rm .gitage.key leaked-key.txt

cp .gitage "$tmp/gitage.good"
while IFS='|' read -r content error; do
  printf "$content" >.gitage
  refuse "an invalid .gitage: $error" "$error" git-age status
done <<'EOF'
secret.env\n|outside a section
[files]\nsecret.env\n[nope]\n|unknown section [nope]
[files]\nsecret.env\n[recipients]\nnot-a-key\n|is not an age recipient
EOF
cp "$tmp/gitage.good" .gitage

refuse "unlock without any identity" "no identity configured" git -c age.keyFile= age unlock
age -r "$alice" -o "$tmp/keys/protected.age" "$tmp/keys/alice"
refuse "a passphrase-protected identity" "encrypted (passphrase-protected) age identity" \
  git-age unlock -i "$tmp/keys/protected.age"
unlock
drop_carol
warns "lock warns when your identity is not a recipient" "is not among the recipients" \
  git-age lock -i "$tmp/keys/carol"
git checkout -q -- .gitage

# --- where rules and keys come from --------------------------------------------

section "subdirectories, nested .gitage and other key sources"

new_repo repo-nested "$alice"
mkdir -p sub/deep
echo top >top.env && echo x >sub/x.env && echo y >sub/deep/y.env && echo keep >sub/keep.env
printf '[files]\n!keep.env\n' >sub/.gitage

check "a nested negation unprotects a file; -C sub lists paths below sub" \
  'status_is -- "U. sub/deep/y.env" "U. sub/x.env" "U. top.env" && status_is -C sub -- "U. deep/y.env" "U. x.env"'
check "lock -C sub locks only below sub, to the top-level [recipients]" \
  'git-age -C sub lock && status_is -- "L. sub/deep/y.env" "L. sub/x.env" "U. top.env" && decrypts_as alice sub/x.env x'
unlock
git config --unset age.keyFile
check "keygen in a subdirectory writes the key at the root, ignored by Git" \
  '(cd sub && git-age keygen >/dev/null 2>&1) && [[ -f .gitage.key && ! -e sub/.gitage.key ]] && git check-ignore -q .gitage.key'
cp "$tmp/keys/alice" .gitage.key
check "a subdirectory uses the root .gitage.key" \
  '(cd sub && git-age lock && [[ $(git-age status --porcelain) == $'"'"'L. deep/y.env\nL. x.env'"'"' ]]) &&
   decrypts_as alice sub/x.env x && git-age -C sub unlock && grep -qx x sub/x.env'
rm .gitage.key
git config age.keyFile "$tmp/keys/alice"

check "dry runs report what they would do, changing nothing" \
  'git-age -n lock | grep -qx "would lock: top.env" && git-age -n rekey | grep -qx "would rekey: top.env" &&
   git-age -n install --mode=abort | grep -q "would install git-age pre-commit hook" &&
   status_is -- "U. sub/deep/y.env" "U. sub/x.env" "U. top.env" &&
   not test -e .git/hooks/pre-commit && not git config age.hookMode'
check "lock -r overrides [recipients]" 'git-age lock -r "$bob" && decrypts_as bob top.env top && not decrypts_as alice top.env top'
unlock -i "$tmp/keys/bob"
check "so does GIT_AGE_RECIPIENT" 'GIT_AGE_RECIPIENT="$carol" git-age lock && decrypts_as carol top.env top'
unlock -i "$tmp/keys/carol"

mkdir "$tmp/plain" && echo s >"$tmp/plain/a.env" && gitage >"$tmp/plain/.gitage"
check "outside Git and without recipients, lock encrypts to your identity, and unlock works" \
  'git-age -C "$tmp/plain" lock -i "$tmp/keys/alice" && decrypts_as alice "$tmp/plain/a.env" s &&
   git-age -C "$tmp/plain" unlock -i "$tmp/keys/alice" && grep -qx s "$tmp/plain/a.env"'

new_repo repo-symlink
gitage "$alice" >"$tmp/gitage.linked"
rm .gitage && ln -s "$tmp/gitage.linked" .gitage
mkdir sub && printf '[files]\nx.env\n' >sub/.gitage && echo x >sub/x.env
# Git Bash copies instead of linking unless symbolic links are enabled.
if [[ -L .gitage ]]; then
  refuse "a symlinked .gitage is ignored" "no encryption key configured" git -c age.keyFile= age lock
else
  skip "symbolic links are unavailable here"
fi
cd "$tmp/repo-nested"

section "hooks: unlock after commit, empty commits, no .gitage"

git-age install --mode=always-lock --unlock-after-commit >/dev/null
check "a commit stores the files encrypted and leaves them unlocked" \
  'git add -A && commit secrets && head_decrypts_as alice top.env top &&
   status_is -- "U. sub/deep/y.env" "U. sub/x.env" "U. top.env"'
stage_plaintext top.env sub/x.env sub/deep/y.env
refuse "a commit that encryption makes empty is refused" "encrypt to the ciphertext already in HEAD" \
  git commit -q -m empty
unlock
stage_plaintext top.env sub/x.env sub/deep/y.env
check "unless GIT_AGE_ALLOW_EMPTY=1" env GIT_AGE_ALLOW_EMPTY=1 git commit -q --amend --no-edit
lock

git switch -q --orphan no-gitage
echo "AGE-SECRET-KEY-1 is the marker" >notes.txt
git add notes.txt
check "commits without a .gitage succeed silently, even mentioning the key marker" \
  '[[ -z $(git commit -q -m "no rules" 2>&1) && -z $(git commit -q --allow-empty -m again 2>&1) ]]'
git-age keygen >/dev/null 2>&1
git add -f .gitage.key
refuse "but a staged .gitage.key is still refused" "refusing to commit private age keys" git commit -q -m oops
git reset -q && rm .gitage.key
refuse "explicit commands still need a .gitage" "no .gitage files staged" git-age check --cached
git switch -q main && git branch -q -D no-gitage
git config age.unlockAfterCommit false

section "hooks: removing a .gitage"

git switch -q -c drop-rules
git rm -q .gitage
refuse "a commit removing .gitage is refused" "refusing to commit the removal of .gitage" git commit -q -m drop
refuse "check --cached suggests the restore" "git restore --staged --worktree -- .gitage" git-age check --cached
git restore --staged --worktree -- .gitage
git mv sub/.gitage sub/deep/.gitage
refuse "moving a nested .gitage counts as removing it" "  sub/.gitage" git commit -q -m move
git mv sub/deep/.gitage sub/.gitage
git rm -q .gitage sub/.gitage
warns "GIT_AGE_ALLOW_REMOVE=1 allows it" "by explicit choice (GIT_AGE_ALLOW_REMOVE)" \
  env GIT_AGE_ALLOW_REMOVE=1 git commit -q -m drop
check "and later commits are not refused" git commit -q --allow-empty -m after
git switch -q main && git branch -q -D drop-rules

section "hooks: interactive"

git-age install --mode=interactive >/dev/null
unlock
echo changed >top.env
git add -A
refuse "without a terminal the commit is aborted" "interactive confirmation is unavailable" \
  without_terminal git commit -q -m "no terminal"
if [[ $platform != windows ]]; then
  refuse "answering a aborts the commit" "commit aborted" answer 'a\n' aborted
  check "e encrypts and commits" 'answer "e\n" encrypted && head_decrypts_as alice top.env changed'
  echo plain >top.env && git add top.env
  refuse "c without typing commit aborts" "not confirmed" answer 'c\nno\n' plaintext
  check "c, then commit, commits plaintext" 'answer "c\ncommit\n" plaintext && [[ $(git show HEAD:top.env) == plain ]]'
else
  skip "interactive prompts (no terminal on Windows)"
fi

# --- per-directory recipients and trust ---------------------------------------

section "per-directory recipients"

# alice reads everything; carol, and later dave, only prod/.
new_repo repo-scoped "$alice"
mkdir prod && echo app >app.env && echo db >prod/db.env
printf '[recipients]\n# Carol\n%s\n' "$carol" >prod/.gitage

check "a nested [recipients] adds carol below prod/ only, as status -v says" \
  'git-age lock && decrypts_as carol prod/db.env db && decrypts_as alice prod/db.env db &&
   not decrypts_as carol app.env app && git-age -v status | grep -q "encrypted to .* + prod/.gitage \[recipients\]"'
git add -A && commit "scoped secrets"
check "status marks what carol cannot read" \
  'as carol status | grep -q "^LOCKED *app.env (no access)" &&
   [[ $(as carol status --porcelain) == $'"'"'LN app.env\nL. prod/db.env'"'"' ]]'
warns "unlock as carol skips what is not hers" "1 file(s) locked that are not encrypted to you" as carol unlock
check "unlocking prod/db.env only; relocking reuses the ciphertext" \
  'grep -qx db prod/db.env && is_locked app.env && as carol lock && clean_tree'
printf '# Dave\n%s\n' "$dave" >>prod/.gitage
check "a nested change makes only its files stale" '[[ $(git-age status --porcelain) == $'"'"'L. app.env\nLS prod/db.env'"'"' ]]'
warns "dave is told prod/db.env is not re-encrypted to him yet" "not re-encrypted to you yet" as dave unlock
git-age install --mode=always-lock >/dev/null
git add prod/.gitage
refuse "the hook refuses the change before rekey" prod/db.env git commit -q -m "add dave"
warns "carol rekeys what she can and names the rest" app.env as carol rekey
check "re-encrypting only prod/db.env, which dave reads" \
  'decrypts_as dave prod/db.env db && git add -A && commit "add dave" &&
   [[ $(git diff --name-only HEAD^ HEAD -- "*.env") == prod/db.env ]]'
age -r "$alice" -o prod/db.env <<<tampered
refuse "a file meant for dave that fails to decrypt still stops unlock" "cannot decrypt" as dave unlock
git checkout -q -- prod/db.env

new_repo repo-nobase
mkdir prod && echo app >app.env && echo db >prod/db.env
printf '[recipients]\n%s\n' "$carol" >prod/.gitage
check "without a base list, lock encrypts to your identity, plus carol under prod/" \
  'as alice lock && decrypts_as carol prod/db.env db && decrypts_as alice app.env app'
warns "carol's unlock leaves app.env alone" "not encrypted to you" as carol unlock
check "and status marks it for her" '[[ $(as carol status --porcelain) == $'"'"'LN app.env\nU. prod/db.env'"'"' ]]'
refuse "someone listed nowhere gets an error" "cannot decrypt" as dave unlock

section "recipient trust"

# Mallory, who can push, adds keys behind everyone's back; bob's key stands in for hers.
mallory() { git -c user.name=Mallory -c user.email=mallory@example.invalid "$@"; }

cd "$tmp/repo-scoped"
unlock
printf '# Mallory\n%s\n' "$bob" >>prod/.gitage
git add prod/.gitage && mallory commit -q --no-verify -m "add a key"
warns "without a pin, lock warns about someone else's change" "Mallory <mallory@example.invalid>" git-age lock
unlock
check "trust pins the lists in age.trustedRecipients, and lock stops warning" \
  'git-age trust && [[ $(git-age trust --show) == $(git config age.trustedRecipients) ]] &&
   ! git-age lock 2>&1 | grep -q "someone else"'
unlock
echo "$dave" >>.gitage
git add .gitage && mallory commit -q --no-verify -m "widen access"
refuse "lock refuses lists that differ from the pin" "untrusted [recipients]" git-age lock
check "naming the new key and who added it, and locking nothing" \
  'out=$(git-age lock 2>&1); grep -q "+ $dave" <<<"$out" && grep -q Mallory <<<"$out" && not is_locked prod/db.env'
warns "status says the lists differ" "differ from the ones you trusted" git-age status
check "trust shows the change it accepts, and lock then works" 'git-age trust | grep -q "+ $dave" && git-age lock'
unlock
sed '$d' .gitage >.gitage.new && mv .gitage.new .gitage
refuse "uncommitted edits need trust too" "(uncommitted changes)" git-age lock
echo db2 >prod/db.env && git add -A
refuse "and the pre-commit hook refuses them" untrusted git commit -q -m edit
git reset -q --hard
git checkout -q -b mallory
echo "$carol" >>.gitage
git add .gitage && mallory commit -q --no-verify -m "sneak a key in"
git checkout -q main
warns "post-merge warns when a merge changes [recipients]" "this merge changes [recipients]" git merge -q mallory

new_repo repo-merge-trust "$alice"
echo app >app.env && lock
git add -A && commit_unchecked init
git checkout -q -b theirs && echo "$bob" >>.gitage && git commit -q --no-verify -am "theirs: add bob"
git checkout -q main && echo "$carol" >>.gitage && git commit -q --no-verify -am "main: add carol"
git merge -q --no-edit theirs >/dev/null 2>&1 || true
gitage "$alice" "$bob" "$carol" "$dave" >.gitage
git add .gitage && mallory commit -q --no-verify -m "merge theirs"
unlock
warns "a [recipients] change made in a merge counts" "merge theirs" git-age lock
git reset -q --hard HEAD~1
mallory merge -q --no-edit -X theirs theirs >/dev/null 2>&1
unlock
check "a merge that takes one side's lists does not" '! git-age lock 2>&1 | grep -q "someone else"'

# --- merges -----------------------------------------------------------------------

section "merge driver"

new_repo repo-merge "$alice" "$bob"
printf 'A=1\nB=1\nC=1\n' >app.env
git-age install --mode=always-lock >/dev/null
git add -A && commit base && lock
# edit BRANCH CONTENT: commit an encrypted edit of app.env on BRANCH.
edit() { git checkout -q "$1" && printf "$2" >app.env && git add app.env && commit "$1" 2>/dev/null && lock; }
# diverge BRANCH OURS THEIRS: branch off main, and edit both sides.
diverge() { git branch "$1" main && edit "$1" "$3" && edit main "$2"; }

diverge side 'A=1\nB=1\nC=2\n' 'A=2\nB=1\nC=1\n'
check "changes to different lines merge cleanly, encrypted" \
  'git merge -q --no-edit side && head_decrypts_as bob app.env $'"'"'A=2\nB=1\nC=2'"'"' && clean_tree'
diverge side2 'A=3\nB=1\nC=2\n' 'A=3\nB=1\nC=2\n'
check "the same change on both sides merges to one side's ciphertext" \
  'git merge -q --no-edit side2 && { [[ $(git rev-parse HEAD:app.env) == $(git rev-parse HEAD^1:app.env) ]] ||
   [[ $(git rev-parse HEAD:app.env) == $(git rev-parse HEAD^2:app.env) ]]; }'
diverge side3 'A=3\nB=main\nC=2\n' 'A=3\nB=side\nC=2\n'
refuse "a conflicting change conflicts" "is now UNLOCKED" git merge -q --no-edit side3
check "with plaintext conflict markers" 'grep -qx "<<<<<<< ours" app.env && grep -qx B=side app.env'
printf 'A=3\nB=both\nC=2\n' >app.env
check "git add encrypts the resolution, which commits" \
  'git add app.env && staged_is_locked app.env && commit "merge side3" && head_decrypts_as bob app.env $'"'"'A=3\nB=both\nC=2'"'"''

diverge side4 'A=3\nB=main4\nC=2\n' 'A=3\nB=side4\nC=2\n'
git checkout -q side4
refuse "a rebase conflicts the same way" "is now UNLOCKED" git rebase -q main
printf 'A=3\nB=untrusted\nC=2\n' >app.env
git config age.trustedRecipients deadbeef
refuse "git add refuses a resolution it cannot encrypt" "Refusing to stage it as plaintext" git add app.env
check "leaving the path unmerged" '[[ -n $(git ls-files -u app.env) ]] && git status --porcelain'
refuse "so rebase --continue cannot commit the plaintext" app.env env GIT_EDITOR=true git rebase --continue
git config --unset age.trustedRecipients
check "once fixed, rebase --continue, which skips pre-commit, commits it encrypted" \
  'git add app.env && GIT_EDITOR=true git rebase --continue && head_decrypts_as alice app.env $'"'"'A=3\nB=untrusted\nC=2'"'"''

git checkout -q main
diverge side5 'A=3\nB=main4\nC=5\n' 'A=5\nB=main4\nC=2\n'
ours=$(git rev-parse HEAD:app.env)
refuse "without a key the merge conflicts" "keeping our version" git -c age.keyFile= merge -q --no-edit side5
check "keeping our ciphertext" '[[ $(git hash-object app.env) == "$ours" ]]'
git merge --abort
git-age install --mode=always-lock --no-merge >/dev/null
refuse "after install --no-merge, even separate changes conflict" CONFLICT git merge -q --no-edit side5
git merge --abort

section "Git attributes"

git-age install --mode=always-lock >/dev/null
printf '[files]\n*.env\n*.secret\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
echo hidden >new.secret
git_files() { find .git -type f ! -name index ! -name '*.lock' -exec cksum {} + | LC_ALL=C sort; }
before=$(git_files)
check "status writes nothing to the repository" 'git-age status >/dev/null && [[ $(git_files) == "$before" ]]'
check "lock applies a new pattern, so Git shows the file readably" \
  'git-age lock && git add new.secret && staged_is_locked new.secret && [[ $(git cat-file --textconv :new.secret) == hidden ]]'
git rm -q --cached new.secret && rm new.secret
git checkout -q -- .gitage && lock

hooks=$(git rev-parse --git-path hooks)
check "install --no-diff --no-merge --no-filter turns off readable diffs, with their hooks" \
  'git-age -n install --no-diff --no-merge --no-filter | grep -q "would remove git-age post-checkout hook" &&
   git-age install --mode=always-lock --no-diff --no-merge --no-filter && ! git cat-file --textconv HEAD:app.env | grep -q A=3 &&
   [[ ! -e $hooks/post-checkout && ! -e $hooks/post-rewrite && -x $hooks/post-merge ]]'
printf '#!/bin/sh\n' >"$hooks/post-checkout"
check "it leaves a hook it does not own alone" \
  'git-age install --mode=always-lock --no-diff --no-merge --no-filter && [[ -e $hooks/post-checkout ]]'

# --- history -----------------------------------------------------------------------

section "audit"

new_repo history && rm .gitage
echo TOKEN=early >early.env && echo hello >readme
git add . && commit "before .gitage"
gitage "$alice" "$bob" >.gitage && echo TOKEN=locked >locked.env && lock
git add -A && commit "add .gitage"
git checkout -q -b side
echo TOKEN=side >side.env && git add side.env && commit "side: plaintext"
lock && git add side.env && commit "side: locked"
git checkout -q main
printf '[files]\n*.env\nold.txt\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
echo 'was protected' >old.txt && git add -A && commit "old.txt protected, as plaintext"
gitage "$alice" "$bob" >.gitage && git add -A && commit "old.txt no longer protected"
git merge -q --no-edit side
git tag -a v1 -m release
git -c advice.nestedTag=false tag -a v1-nested -m "a tag of a tag" v1
git branch side-head side

audit_status=0
audit_out=$(git-age audit 2>&1) || audit_status=$?
check "audit fails on plaintext committed before .gitage, on a branch, or protected then" \
  '((audit_status == 1)) && grep -qx "  early.env" <<<"$audit_out" && grep -qx "  side.env" <<<"$audit_out" &&
   grep -qx "  old.txt" <<<"$audit_out" && ! grep -qE "locked.env|readme" <<<"$audit_out"'
mkdir sub
check "audit REV searches only that history; -C subdir all of it" \
  '! git-age audit main~1 2>&1 | grep -q side.env && git-age -C sub audit 2>&1 | grep -qx "  early.env"'

gitage "$alice" >.gitage && git commit -q -am "drop bob" </dev/null
before=$(git rev-parse HEAD)
refuse "audit --rekey without a terminal asks for --yes" "pass --yes" git-age audit --rekey
echo dirty >>readme
refuse "and refuses a dirty working tree" "uncommitted changes" git-age audit --rekey --yes
git checkout -q readme
refuse "and revisions" "takes no revisions" git-age audit --rekey --yes main
refuse "what it cannot decrypt stops it" "cannot decrypt" \
  env GIT_AGE_KEY_FILE="$tmp/keys/carol" GIT_AGE_RECIPIENT="$carol" git-age audit --rekey --yes
check "-n, and the refusals, rewrite nothing" \
  'git-age -n audit --rekey | grep -q "would rewrite" && [[ $(git rev-parse HEAD) == "$before" ]]'
warns "audit --rekey --yes rewrites" "git-age audit -- --branches --tags" git-age audit --rekey --yes
check "keeping the old branch in refs/git-age/original, so audit passes" \
  '[[ $(git rev-parse refs/git-age/original/refs/heads/main) == "$before" && $(git rev-parse HEAD) != "$before" ]] &&
   git-age audit'
git update-ref refs/remotes/origin/main "$before"
refuse "remote-tracking refs keep the old history" early.env git-age audit
check "which audit -- --branches --tags leaves out" git-age audit -- --branches --tags
git update-ref -d refs/remotes/origin/main
# every_version WHO can|cannot: WHO can (or cannot) decrypt every .env in history.
every_version() {
  local commit path
  for commit in $(git rev-list --exclude='refs/git-age/*' --all); do
    for path in $(git ls-tree -r --name-only "$commit" | grep '\.env$'); do
      if git show "$commit:$path" | age -d -i "$tmp/keys/$1" >/dev/null 2>&1; then
        [[ $2 == can ]] || return 1
      else
        [[ $2 == cannot ]] || return 1
      fi
    done
  done
}
check "alice can read every version; bob, removed, none; old.txt stays plaintext" \
  'every_version alice can && every_version bob cannot && git show HEAD~2:old.txt | grep -qx "was protected"'
check "tags, tags of tags and branches point into the new history" \
  'git merge-base --is-ancestor "v1^{commit}" HEAD && git merge-base --is-ancestor "v1-nested^{commit}" HEAD &&
   [[ $(git cat-file -p v1-nested | sed -n "1s/^object //p") == $(git rev-parse v1) ]] &&
   git merge-base --is-ancestor side-head HEAD && clean_tree'
refuse "a second rewrite wants the backup gone" "previous rewrite" git-age audit --rekey --yes

new_repo keyleak "$alice"
echo hello >readme && git add . && commit init
check "audit passes without leaks" git-age audit
cp "$tmp/keys/alice" k.txt && git add k.txt && commit_unchecked "key as k.txt"
key_status=0
key_out=$(git-age audit 2>&1) || key_status=$?
check "a committed key fails audit, with its path and commit, as compromised" \
  '((key_status == 1)) && grep -qx "Private age keys committed to Git history:" <<<"$key_out" &&
   grep -qx "  k.txt" <<<"$key_out" && grep -q "in [0-9a-f]\{12\}  key as k.txt$" <<<"$key_out" &&
   grep -q compromised <<<"$key_out" && grep -q "git filter-repo" <<<"$key_out"'
git rm -q k.txt && commit "remove k.txt"
echo 'not a key' >.gitage.key && git add -f .gitage.key && commit_unchecked "a .gitage.key"
echo TOKEN=plain >app.env && git add app.env && commit_unchecked "plaintext app.env"
key_status=0
key_out=$(git-age audit 2>&1) || key_status=$?
check "so do a .gitage.key, whatever its content, and a removed key" \
  '((key_status == 1)) && grep -qx "  .gitage.key" <<<"$key_out" && grep -qx "  k.txt" <<<"$key_out"'
check "plaintext is listed in its own group, not as a key" \
  'grep -qx "Protected files committed as plaintext:" <<<"$key_out" &&
   ! sed -n "/^Private/,/^Protected/p" <<<"$key_out" | grep -q app.env'
echo 'not a key either' >.gitage.key && git add -f .gitage.key && commit_unchecked "change .gitage.key"
check "audit lists one version by default, -v every one" \
  'git-age audit 2>&1 | grep -q "and 1 more version(s); -v lists them" &&
   [[ $(git-age -v audit 2>&1 | grep -c "in [0-9a-f]\{12\}  .*gitage.key") -eq 2 ]]'
git rm -q --cached .gitage.key && rm .gitage.key && commit "remove .gitage.key"
warns "audit --rekey warns about committed keys" "private key file(s) are in Git history" git-age -n audit --rekey

section "pre-push"

git init -q --bare "$tmp/remote.git"
new_repo repo-push "$alice"
echo TOKEN=one >app.env
git-age install --mode=always-lock >/dev/null
git add -A && commit init
git remote add origin "$tmp/remote.git"
check "a clean push succeeds" git push -q origin main
remote_main() { git --git-dir="$tmp/remote.git" rev-parse main; }
pushed=$(git rev-parse HEAD)

unlock
echo TOKEN=two >app.env && git add app.env && commit_unchecked "plaintext app.env"
refuse "pushing a plaintext commit made with --no-verify is refused" "push aborted" git push -q origin main
check "naming the file and how to push anyway, and the remote did not get it" \
  'out=$(git push -q origin main 2>&1); grep -q "  app.env" <<<"$out" &&
   grep -qF "GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push" <<<"$out" && [[ $(remote_main) == "$pushed" ]]'
warns "GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 allows it" "by explicit choice (GIT_AGE_ALLOW_PLAINTEXT_PUSH)" \
  env GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push -q origin main
lock && git add app.env && commit "encrypt app.env"
check "what the remote has is not audited again" git push -q origin main

git switch -q -c leak
unlock
echo TOKEN=three >app.env && git add app.env && commit_unchecked "plaintext again"
refuse "a new branch is audited too" "push aborted" git push -q origin leak
check "unless with --no-verify; deleting a branch is not audited" 'git push -q --no-verify origin leak && git push -q origin :leak'
git switch -q -c side main
echo TOKEN=side >app.env && git commit -q --no-verify -am "plaintext on side"
git switch -q -c rebased main && git cherry-pick side >/dev/null
refuse "a cherry-picked plaintext commit is refused" "push aborted" git push -q origin rebased
git switch -q -c keys main
cp "$tmp/keys/bob" k.txt && git add k.txt && commit_unchecked "a key"
refuse "a committed private key is refused" "Private age keys in the commits being pushed" git push -q origin keys
git switch -q --orphan no-rules
echo "AGE-SECRET-KEY-1 is the marker" >notes.txt && git add notes.txt && commit_unchecked "no rules"
check "a branch without a .gitage pushes silently" '[[ -z $(git push -q origin no-rules 2>&1) ]]'
check "while pushed commits with their own .gitage are still audited" \
  '! git push -q origin leak 2>/dev/null && [[ -z $(git ls-remote origin refs/heads/leak) ]]'
git switch -q -f main
lock

section "uninstall"

git rm -q .gitage
refuse "the .gitage removal refusal suggests uninstall" "git-age uninstall" git commit -q -m drop
git restore --staged --worktree -- .gitage
hooks=$(git rev-parse --git-path hooks)
printf '#!/bin/sh\n' >"$hooks/post-rewrite" && chmod +x "$hooks/post-rewrite"
# installed: the hooks are in place, and Git decrypts diffs.
installed() {
  [[ -x $hooks/pre-commit && -x $hooks/pre-push ]] && git config age.hookMode >/dev/null &&
    git cat-file --textconv HEAD:app.env | grep -q TOKEN=
}
check "uninstall -n says what it would do, and does nothing" \
  'git-age -n uninstall | grep -q "would remove git-age pre-push hook" && installed'
warns "uninstall keeps a hook it did not install" "Kept post-rewrite hook" git-age uninstall
check "removing its own hooks, config and readable diffs, keeping age.keyFile and the file locked" \
  'for hook in pre-commit post-commit pre-push post-checkout post-merge; do [[ ! -e $hooks/$hook ]] || exit 1; done
   [[ -x $hooks/post-rewrite ]] && not git config age.hookMode && ! git cat-file --textconv HEAD:app.env | grep -q TOKEN= &&
   git config age.keyFile && is_locked app.env'
check "a second uninstall has nothing to do" 'git-age uninstall | grep -qx "git-age: nothing to uninstall"'
rm "$hooks/post-rewrite"
check "install puts it all back" 'git-age install --mode=always-lock && installed'

# --- commands --------------------------------------------------------------------

section "path arguments"

new_repo repo-paths "$alice"
mkdir sub docs
echo a-plaintext >a.env && echo b >sub/b.env && echo c >sub/c.env && echo notes >notes.txt && echo doc >docs/readme.txt

check "lock FILE and lock DIR lock only those" \
  'git-age lock a.env && status_is -- "L. a.env" "U. sub/b.env" "U. sub/c.env" &&
   git-age lock sub && status_is -- "L. a.env" "L. sub/b.env" "L. sub/c.env"'
check "unlock FILE unlocks only that file; status takes PATHs" \
  'git-age unlock sub/b.env && status_is -- "L. a.env" "U. sub/b.env" "L. sub/c.env" &&
   [[ $(git-age status --porcelain sub) == $'"'"'U. sub/b.env\nL. sub/c.env'"'"' &&
      $(git-age status --porcelain sub/c.env a.env) == $'"'"'L. a.env\nL. sub/c.env'"'"' ]]'
check "PATHs are relative to -C, or the current directory" \
  'git-age -C sub unlock c.env && status_is -- "L. a.env" "U. sub/b.env" "U. sub/c.env" &&
   (cd sub && git-age lock ./b.env) && status_is -- "L. a.env" "L. sub/b.env" "U. sub/c.env" &&
   [[ $(git-age -n rekey sub/c.env) == "would rekey: sub/c.env" ]]'
refuse "a PATH that .gitage does not protect is an error" "notes.txt: not protected by .gitage" \
  git-age lock sub/c.env notes.txt
refuse "so is a missing PATH" "nope.env: no such file or directory" git-age unlock nope.env
refuse "a directory without protected files" "docs: no file in it is protected" git-age status docs
refuse "a PATH outside -C" "../a.env: outside" git-age -C sub lock ../a.env
refuse "and a PATH outside the repository" outside git-age lock "$tmp/keys/alice"
check "the refusals changed nothing" status_is -- 'L. a.env' 'L. sub/b.env' 'U. sub/c.env'

section "edit"

lock && git add -A && commit secrets
# The editor records whether anyone else could read the file it got, and
# what Git saw in the working tree meanwhile, then appends a line.
cat >"$tmp/append-editor" <<'EOF'
#!/bin/sh
python3 -c 'import os, sys
print(any(os.stat(p).st_mode & 0o077 == 0 for p in (sys.argv[1], os.path.dirname(sys.argv[1]))))' "$1" >"${0%/*}/edit-private"
git status --porcelain --untracked-files=all >"${0%/*}/edit-status"
printf 'NEW=1\n' >>"$1"
EOF
printf '#!/bin/sh\nprintf "NEW=1\\n" >>"$1"\nexit 1\n' >"$tmp/failing-editor"
chmod +x "$tmp/append-editor" "$tmp/failing-editor"
# no_plaintext_left: no decrypted copy of a.env is anywhere in the test's files.
no_plaintext_left() { ! grep -rqF a-plaintext "$tmp"; }
cp a.env "$tmp/a.env.before"

check "an editor that changes nothing leaves the file byte for byte" 'EDITOR=true git-age edit a.env && cmp -s a.env "$tmp/a.env.before"'
check "edit re-encrypts the change" \
  'EDITOR="$tmp/append-editor" git-age edit a.env && decrypts_as alice a.env $'"'"'a-plaintext\nNEW=1'"'"''
check "the editor got a copy outside the working tree, gone afterwards" '[[ ! -s $tmp/edit-status ]] && no_plaintext_left'
[[ $platform == windows ]] || check "which no one else could read" '[[ $(cat "$tmp/edit-private") == True ]]'
check "edit -C sub FILE is relative to -C; editing back reuses the committed ciphertext" \
  'EDITOR="perl -pi -e s/b/B/" git-age -C sub edit b.env && decrypts_as alice sub/b.env B &&
   EDITOR="perl -pi -e s/B/b/" git-age edit sub/b.env && git diff --quiet -- sub/b.env'
cp a.env "$tmp/a.env.before"
refuse "a failing editor is an error" "exit status 1; a.env was not changed" env EDITOR="$tmp/failing-editor" git-age edit a.env
check "that leaves the file as it was, with no decrypted copy" 'cmp -s a.env "$tmp/a.env.before" && no_plaintext_left'
check "edit -n changes nothing" \
  '[[ $(EDITOR="$tmp/append-editor" git-age -n edit a.env) == "would edit: a.env" ]] && cmp -s a.env "$tmp/a.env.before"'
refuse "edit refuses a file .gitage does not protect" "notes.txt: not protected by .gitage" \
  env EDITOR=true git-age edit notes.txt
refuse "and a directory" "is a directory" env EDITOR=true git-age edit sub
unlock sub/c.env
warns "edit opens an unlocked file in place" "sub/c.env is unlocked" env EDITOR="$tmp/append-editor" git-age edit sub/c.env
check "where it stays plaintext, edited" '[[ $(cat sub/c.env) == $'"'"'c\nNEW=1'"'"' ]]'

section "help and completion"

check "help prints the manual, anywhere, without a key; --help points to it" \
  'out=$(git-age -C "$tmp" help) && grep -qx "QUICK START" <<<"$out" && grep -qx "SHELL COMPLETION" <<<"$out" &&
   git-age --help | grep -qF "git-age help"'
check "help TOPIC prints one section, found by a word or a prefix, in any case; help COMMAND its options" \
  'out=$(git-age help hooks) && [[ $(head -1 <<<"$out") == "GIT HOOKS" ]] && ! grep -qx KEYS <<<"$out" &&
   [[ $(git-age help trust | head -1) == "RECIPIENT TRUST" && $(git-age help INTEG | head -1) == "GIT INTEGRATION" &&
      $(git-age help .gitage | head -1) == .GITAGE ]] && git-age help lock | grep -q "^usage: git-age lock"'
refuse "an unknown topic lists the topics" "topics are: quick-start, everyday-use, commands" git-age help nonsense
[[ $platform == windows ]] || check "on a terminal, the manual goes through Git's pager" \
  'GIT_PAGER="sed s/^/paged:/" on_terminal "git-age help" | tr -d "\r" | grep -x "paged:QUICK START" >/dev/null'
check "otherwise it is printed plainly" 'GIT_PAGER="sed s/^/paged:/" git-age help | grep -qx "QUICK START"'

check "the bash completion script parses" 'bash -n <(git-age completion bash)'
! command -v zsh >/dev/null || check "so does zsh's" 'git-age completion zsh | zsh -n'
! command -v fish >/dev/null || check "so does fish's" 'git-age completion fish | fish --no-config -n'
refuse "an unknown shell is refused" "invalid choice: 'tcsh'" git-age completion tcsh
# bash_complete WORD...: what bash completes for the last WORD, as `git-age` or `git age`.
bash_complete() {
  bash -c 'source <(git-age completion bash)
    COMP_WORDS=("$@") COMP_CWORD=$(($# - 1)) words=("$@") cword=$(($# - 1)) __git_cmd_idx=1
    if [[ $1 == git ]]; then _git_age; else _git_age_main; fi
    printf "%s\n" "${COMPREPLY[@]}"' bash "$@"
}
completes() { [[ $(bash_complete "${@:2}") == "$1" ]]; }
# offers_documented COMPLETIONS: they include lock, and only commands the manual lists.
manual=$(git-age help commands)
offers_documented() {
  local command
  grep -qx lock <<<"$1" || return 1
  for command in $1; do grep -q "^    $command\b" <<<"$manual" || return 1; done
}
check "bash completes commands, options, choices and files" \
  'completes lock git-age lo && completes unlock git-age -C . -n unl && completes --no-reuse git-age lock --no &&
   completes always-lock git-age install --mode al && completes always-lock git-age install --mode = al &&
   completes "$tmp/keys/alice" git-age unlock -i "$tmp/keys/al" && completes git-hooks git-age help git-ho'
check "offering only documented commands, also as git age" \
  'offers_documented "$(bash_complete git-age "")" && offers_documented "$(bash_complete git age "")" &&
   completes rekey git age rek'
fish_complete() { fish --no-config -c "source (git-age completion fish | psub); complete -C \"$1\"" | cut -f1; }
! command -v fish >/dev/null || check "fish completes documented commands and choices" \
  'offers_documented "$(fish_complete "git-age ")" && [[ $(fish_complete "git-age install --mode=al") == --mode=always-lock ]]'

printf '\n%d passed, %d failed\n' "$passed" "$failed"
((failed == 0))
