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

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GIT_AGE=${GIT_AGE:-$script_dir/git-age}

for tool in git age age-keygen; do
  command -v "$tool" >/dev/null || { echo "missing dependency: $tool" >&2; exit 2; }
done
[[ -x $GIT_AGE ]] || { echo "git-age not found or not executable: $GIT_AGE" >&2; exit 2; }

# --- isolated environment ----------------------------------------------------

tmp=$(mktemp -d "${TMPDIR:-/tmp}/git-age-test.XXXXXX")
if [[ ${KEEP:-0} == 1 ]]; then
  trap 'echo; echo "kept: $tmp"' EXIT
else
  trap 'rm -rf "$tmp"' EXIT
fi
# Temporary files git-age makes land here too, where the test can look for them.
export TMPDIR=$tmp

# Never touch the user's keys, config or hooks.
unset GIT_AGE_KEY_FILE GIT_AGE_RECIPIENT GIT_AGE_HOOK_MODE \
      GIT_AGE_UNLOCK_AFTER_COMMIT GIT_AGE_ALLOW_PRIVATE_KEYS \
      GIT_AGE_ALLOW_STALE_RECIPIENTS GIT_AGE_ALLOW_EMPTY GIT_AGE_ALLOW_REMOVE \
      GIT_AGE_ALLOW_PLAINTEXT_PUSH
# `git-age edit` tests choose the editor with EDITOR.
unset GIT_EDITOR VISUAL
export GIT_CONFIG_GLOBAL=$tmp/gitconfig
export GIT_CONFIG_NOSYSTEM=1
cat >"$GIT_CONFIG_GLOBAL" <<'EOF'
[user]
  name = git-age test
  email = test@example.invalid
[init]
  defaultBranch = main
[commit]
  gpgsign = false
EOF

# The test runs `git-age` and hooks run `git age`, so put the git-age under
# test first on PATH.
mkdir -p "$tmp/bin" "$tmp/keys"
ln -s "$GIT_AGE" "$tmp/bin/git-age"
export PATH=$tmp/bin:$PATH
# git-age runs with python3, which Python for Windows calls python.
if ! command -v python3 >/dev/null && command -v python >/dev/null; then
  printf '#!/bin/sh\nexec python "$@"\n' >"$tmp/bin/python3"
  chmod +x "$tmp/bin/python3"
fi
command -v python3 >/dev/null || { echo "missing dependency: python3" >&2; exit 2; }

for name in alice bob carol dave; do
  age-keygen -o "$tmp/keys/$name" 2>/dev/null
done
alice=$(age-keygen -y "$tmp/keys/alice")
bob=$(age-keygen -y "$tmp/keys/bob")
carol=$(age-keygen -y "$tmp/keys/carol")
dave=$(age-keygen -y "$tmp/keys/dave")

# --- helpers -------------------------------------------------------------------

passed=0
failed=0

section() { printf '\n== %s\n' "$*"; }
pass() { passed=$((passed + 1)); printf '  ok    %s\n' "$*"; }
fail() { failed=$((failed + 1)); printf '  FAIL  %s\n' "$*"; }
skip() { printf '  skip  %s\n' "$*"; }

# run_ COMMAND... | run_ 'CONDITION': run a command, or evaluate a shell
# condition such as 'a && b', in a subshell without pipefail so that
# `cmd | grep -q` cannot fail on SIGPIPE.
run_() {
  set +o pipefail
  if (($# == 1)); then eval "$1"; else "$@"; fi
}

# check DESCRIPTION COMMAND... | check DESCRIPTION 'CONDITION': it must succeed.
check() {
  local description=$1; shift
  local output
  if output=$(run_ "$@" 2>&1 </dev/null); then
    pass "$description"
  else
    fail "$description"
    printf '%s\n' "$*" "$output" | sed 's/^/        | /'
  fi
}

# refuse DESCRIPTION PATTERN COMMAND...: it must fail and print PATTERN.
refuse() { _expect_output fail "$@"; }
# warns DESCRIPTION PATTERN COMMAND...: it must succeed and print PATTERN.
warns() { _expect_output succeed "$@"; }

_expect_output() {
  local want=$1 description=$2 pattern=$3; shift 3
  local output status=0
  output=$(run_ "$@" 2>&1 </dev/null) || status=$?
  local exit_ok=$((status == 0))
  [[ $want == succeed ]] || exit_ok=$((!exit_ok))
  if ((exit_ok)) && grep -qF -- "$pattern" <<<"$output"; then
    pass "$description"
  else
    fail "$description (exit $status, expected: $pattern)"
    printf '%s\n' "$output" | sed 's/^/        | /'
  fi
}

not() { ! "$@"; }
commit() { git commit -q -m "$1" </dev/null; }
clean_tree() { [[ -z $(git status --porcelain) ]]; }
# sed_i SCRIPT FILE: edit FILE in place; BSD and GNU sed disagree on -i.
sed_i() { sed "$1" "$2" >"$2.sed" && mv "$2.sed" "$2"; }
mode_is() {
  [[ $(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777)[2:])' "$1") == "$2" ]]
}

# is_locked FILE...: every FILE is age ciphertext.
is_locked() {
  local file
  for file; do head -c 21 "$file" | grep -q '^age-encryption.org/v1' || return 1; done
}
# decrypts_as WHO FILE CONTENT: WHO's key decrypts FILE to CONTENT.
decrypts_as() { [[ $(age -d -i "$tmp/keys/$1" "$2" 2>/dev/null) == "$3" ]]; }
# head_decrypts_as WHO PATH CONTENT: the same, for PATH as committed in HEAD.
head_decrypts_as() { [[ $(git show "HEAD:$2" | age -d -i "$tmp/keys/$1" 2>/dev/null) == "$3" ]]; }
staged_is_locked() { git show ":$1" | head -c 21 | grep -q '^age-encryption.org/v1'; }
# stage_plaintext FILE...: stage FILE's bytes exactly, bypassing Git's filters.
stage_plaintext() {
  local file
  for file; do
    git update-index --add --cacheinfo "100644,$(git hash-object -w --no-filters "$file"),$file"
  done
}
# forget_stat FILE...: make Git compare FILE by content, as once it changes.
forget_stat() { git ls-files -s "$@" | git update-index --index-info; }
# as WHO ARGS...: run git-age with WHO's key.
as() { local who=$1; shift; GIT_AGE_KEY_FILE=$tmp/keys/$who git-age "$@"; }

# status_is [ARGS...] -- RECORD...: `git-age ARGS... status --porcelain`
# prints exactly these records.
status_is() {
  local args=()
  while [[ $1 != -- ]]; do args+=("$1"); shift; done
  shift
  [[ $(git-age "${args[@]}" status --porcelain 2>/dev/null) == "$(printf '%s\n' "$@")" ]]
}

# file_list: every file and directory in the working tree, to compare.
file_list() { find . -path ./.git -prune -o -print | LC_ALL=C sort; }

# on_terminal COMMAND: run the shell COMMAND on a pseudo-terminal, typing
# what is on stdin. Unlike script(1), this works alike on Linux and macOS.
# Read all its output: if the reader stops early, COMMAND hangs.
on_terminal() {
  python3 -c 'import os, pty, sys
sys.exit(os.waitstatus_to_exitcode(pty.spawn(["sh", "-c", sys.argv[1]])))' "$1"
}
has_terminal() { [[ $platform != windows ]]; }

# without_terminal COMMAND...: run COMMAND without a controlling terminal,
# which native Windows programs never have.
without_terminal() {
  if [[ $platform == windows ]]; then
    "$@"
  elif command -v setsid >/dev/null; then
    setsid -w "$@"
  else
    python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@"
  fi
}

# answer REPLIES MESSAGE: commit on a terminal, answering the hook's prompt.
answer() {
  printf '%b' "$1" | on_terminal "git commit -q -m '$2'"
}

# --- end to end: a working team setup ---------------------------------------

section "setup: repository with two protected files, recipients alice + bob"

repo=$tmp/repo
mkdir -p "$repo/config"
cd "$repo"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo 'API_TOKEN=s3cr3t' >secret.env
echo 'password: hunter2' >config/credentials.yaml
cat >.gitage <<EOF
[files]
secret.env
config/*.yaml

[recipients]
# Alice
$alice
# Bob
$bob
EOF

check "status lists both files as unlocked" \
  'git-age status | grep -q "^UNLOCKED *secret.env" &&
   git-age status | grep -q "^UNLOCKED *config/credentials.yaml" &&
   status_is -- "U. config/credentials.yaml" "U. secret.env"'
check "status -z NUL-terminates records" 'git-age status -z | tr "\0" "\n" | grep -qx "U. secret.env"'

section "lock / unlock"

check "lock encrypts both files to the recipients only" \
  'git-age lock && is_locked secret.env config/credentials.yaml &&
   decrypts_as bob secret.env API_TOKEN=s3cr3t && not decrypts_as carol secret.env API_TOKEN=s3cr3t'
check "unlock restores the plaintext" 'git-age unlock && grep -qx API_TOKEN=s3cr3t secret.env'

section "lock / unlock are all-or-nothing"

files=$(file_list)
# root reads files whatever their mode, so it cannot test this; nor can
# Windows, where chmod does not take away read access.
if [[ $platform == windows ]]; then
  skip "unreadable files (Windows)"
elif [[ $(id -u) -eq 0 ]]; then
  skip "unreadable files (running as root)"
else
  chmod 000 secret.env
  refuse "lock fails on an unreadable file" "secret.env" git-age lock
  chmod 644 secret.env
  check "it locks neither file and leaves no stray files" \
    'not is_locked config/credentials.yaml && [[ $(file_list) == "$files" ]]'
fi

git-age lock >/dev/null
age -r "$carol" -o secret.env.carol <<<'API_TOKEN=s3cr3t'
mv secret.env.carol secret.env
refuse "unlock fails on a file it cannot decrypt" "secret.env" git-age unlock
check "it unlocks neither file and leaves no stray files" \
  'is_locked config/credentials.yaml && [[ $(file_list) == "$files" ]]'
echo 'API_TOKEN=s3cr3t' >secret.env
git-age unlock >/dev/null

section "lock / unlock keep file metadata"

# Each platform defines: set_metadata, which gives secret.env a mode, an ACL
# and an extended attribute (or the Windows equivalents), credentials.yaml
# just a mode, and config/ an ACL that new files there inherit;
# metadata_kept; and clear_metadata.
metadata=yes
case $platform in
  linux)
    if command -v setfacl >/dev/null && setfacl -m u:65534:r secret.env 2>/dev/null &&
      python3 -c 'import os; os.setxattr("secret.env", "user.git-age-test", b"kept")' 2>/dev/null; then
      has_acl() { getfacl -cn "$2" 2>/dev/null | grep -q "^$1"; }
      xattr_is() {
        [[ $(python3 -c 'import os, sys; print(os.getxattr(sys.argv[1], sys.argv[2]).decode())' \
          "$2" "$1" 2>/dev/null) == "$3" ]]
      }
      set_metadata() {
        chmod 640 secret.env && chmod 600 config/credentials.yaml && setfacl -d -m u:65534:rw config
      }
      metadata_kept() {
        mode_is secret.env 640 && mode_is config/credentials.yaml 600 && has_acl user:65534:r-- secret.env &&
          xattr_is user.git-age-test secret.env kept && not has_acl user:65534: config/credentials.yaml
      }
      clear_metadata() {
        setfacl -b secret.env && setfacl -k config && chmod 644 secret.env config/credentials.yaml &&
          python3 -c 'import os; os.removexattr("secret.env", "user.git-age-test")'
      }
    else
      metadata=
    fi
    ;;
  macos)
    has_acl() { ls -le "$2" | grep -qF "$1"; }
    set_metadata() {
      chmod 640 secret.env && chmod 600 config/credentials.yaml && chmod +a "everyone allow read" secret.env &&
        xattr -w user.git-age-test kept secret.env &&
        chmod +a "everyone allow write,file_inherit,directory_inherit" config
    }
    metadata_kept() {
      mode_is secret.env 640 && mode_is config/credentials.yaml 600 &&
        has_acl "group:everyone allow read" secret.env &&
        [[ $(xattr -p user.git-age-test secret.env) == kept ]] &&
        not has_acl "group:everyone" config/credentials.yaml
    }
    clear_metadata() {
      chmod -N secret.env config && chmod 644 secret.env config/credentials.yaml &&
        xattr -d user.git-age-test secret.env
    }
    ;;
  windows)
    # Keep MSYS from turning icacls's /switches into paths.
    icacls() { MSYS2_ARG_CONV_EXCL='*' command icacls "$@"; }
    set_metadata() {
      icacls secret.env /grant '*S-1-1-0:(R)' >/dev/null &&
        python3 -c 'open("secret.env:git-age-test", "w").write("kept")' &&
        attrib +R +H secret.env
    }
    metadata_kept() {
      python3 -c 'import os, stat, sys
wanted = stat.FILE_ATTRIBUTE_READONLY | stat.FILE_ATTRIBUTE_HIDDEN
sys.exit(os.stat("secret.env").st_file_attributes & wanted != wanted)' &&
        icacls secret.env | grep -qF "Everyone:(R)" &&
        [[ $(python3 -c 'print(open("secret.env:git-age-test").read())') == kept ]]
    }
    clear_metadata() {
      attrib -R -H secret.env && icacls secret.env /remove '*S-1-1-0' >/dev/null &&
        python3 -c 'import os; os.remove("secret.env:git-age-test")'
    }
    ;;
esac
if [[ -n $metadata ]]; then
  set_metadata
  check "lock keeps it, and adds none a file lacked" 'git-age lock && metadata_kept'
  check "so does unlock, leaving no stray files" \
    'git-age unlock && metadata_kept && [[ $(file_list) == "$files" ]]'
  clear_metadata
else
  skip "no ACL or extended attribute support here"
fi

section "hooks (always-lock)"

check "install --mode=always-lock" git-age install --mode=always-lock
check "a commit of staged plaintext stores it encrypted" \
  'git add -A && commit "initial secrets" &&
   head_decrypts_as alice secret.env API_TOKEN=s3cr3t &&
   head_decrypts_as bob config/credentials.yaml "password: hunter2"'

section "idempotent encryption and the clean filter"

check "unchanged files lock to identical ciphertext" 'git-age unlock && git-age lock && clean_tree'
check "unlocked, unchanged files show no changes" 'git-age unlock && clean_tree && git diff --quiet'
check "git add stages them encrypted" 'git add -A && staged_is_locked secret.env'
check "an edit shows as modified until it is reverted" \
  'echo API_TOKEN=edited >secret.env && git status --porcelain | grep -qx " M secret.env" &&
   echo API_TOKEN=s3cr3t >secret.env && clean_tree'
check "without an identity they show as modified" \
  'forget_stat secret.env && git -c age.keyFile= status --porcelain | grep -qx " M secret.env"'
check "so they do after install --no-filter" \
  'git-age install --mode=always-lock --no-filter >/dev/null && forget_stat secret.env &&
   git status --porcelain | grep -qx " M secret.env"'
check "installing and locking again leaves a clean tree" \
  'git-age install --mode=always-lock >/dev/null && git-age lock >/dev/null && clean_tree'

section "editing a secret"

git-age unlock
echo 'API_TOKEN=rotated' >secret.env
check "a commit stores the edit encrypted, and git show diffs the plaintext" \
  'git add secret.env && commit "rotate token" &&
   head_decrypts_as alice secret.env API_TOKEN=rotated &&
   git show HEAD -- secret.env | grep -qx "+API_TOKEN=rotated"'

section "adding a recipient (carol) with rekey"

git-age lock >/dev/null
printf '# Carol\n%s\n' "$carol" >>.gitage
warns "status flags files encrypted to the previous list" "previous [recipients] list" git-age status
check "status --porcelain flags them as LS" 'git-age status --porcelain 2>&1 | grep -qx "LS secret.env"'
check "after rekey and commit, carol reads HEAD and nothing is stale" \
  'git-age rekey && git add -A && commit "add carol" &&
   head_decrypts_as carol secret.env API_TOKEN=rotated && ! git-age status 2>&1 | grep -q previous'

# --- error cases -----------------------------------------------------------------

section "errors: hook policies"

git-age unlock
echo 'API_TOKEN=leak' >secret.env
git add secret.env
refuse "abort mode refuses staged plaintext" "commit aborted" \
  env GIT_AGE_HOOK_MODE=abort git commit -q -m "plaintext"
git restore --staged secret.env
git checkout -q -- secret.env 2>/dev/null || true
git-age lock >/dev/null

sed_i '/# Carol/{N;d;}' .gitage
git add .gitage
refuse "the hook refuses a [recipients] change with stale ciphertext" \
  "still encrypted to the previous list" git commit -q -m "remove carol"
git restore --staged .gitage
git checkout -q -- .gitage

section "errors: private keys"

git-age keygen >/dev/null 2>&1
check "keygen excludes .gitage.key from git add -A" \
  'git add -A && ! git diff --cached --name-only | grep -qx .gitage.key'
git add -f .gitage.key
refuse "the hook refuses a staged .gitage.key" "refusing to commit private age keys" \
  git commit -q -m "oops"
cp "$tmp/keys/bob" leaked-key.txt
git add -f leaked-key.txt
refuse "the hook refuses an unprotected file containing a key" "leaked-key.txt" \
  git commit -q -m "oops"
git restore --staged .gitage.key leaked-key.txt
rm -f .gitage.key leaked-key.txt

section "errors: invalid .gitage"

cp .gitage "$tmp/gitage.good"
printf 'secret.env\n' >.gitage
refuse "an entry outside a section" "outside a section" git-age status
printf '[files]\nsecret.env\n[nope]\n' >.gitage
refuse "an unknown section" "unknown section [nope]" git-age status
printf '[files]\nsecret.env\n[recipients]\nnot-a-key\n' >.gitage
refuse "an invalid recipient" "is not an age recipient" git-age status
cp "$tmp/gitage.good" .gitage

section "errors: identities"

refuse "unlock without any identity" "no identity configured" git -c age.keyFile= age unlock
age -r "$alice" -o "$tmp/keys/protected.age" "$tmp/keys/alice"
refuse "a passphrase-protected identity" "encrypted (passphrase-protected) age identity" \
  git-age unlock -i "$tmp/keys/protected.age"
git-age unlock >/dev/null
sed_i '/# Carol/{N;d;}' .gitage
warns "lock warns when your identity is not a recipient" "is not among the recipients" \
  git-age lock -i "$tmp/keys/carol"
git checkout -q -- .gitage

# --- more workflows ------------------------------------------------------------

section "subdirectories and nested .gitage"

repo3=$tmp/repo-nested
mkdir -p "$repo3/sub/deep"
cd "$repo3"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo top >top.env
echo x >sub/x.env
echo y >sub/deep/y.env
echo keep >sub/keep.env
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
printf '[files]\n!keep.env\n' >sub/.gitage

check "a nested negation unprotects a file" \
  status_is -- 'U. sub/deep/y.env' 'U. sub/x.env' 'U. top.env'
check "status -C sub lists paths relative to sub" status_is -C sub -- 'U. deep/y.env' 'U. x.env'
check "lock -C sub locks only below sub, to the top-level [recipients]" \
  'git-age -C sub lock && status_is -- "L. sub/deep/y.env" "L. sub/x.env" "U. top.env" &&
   decrypts_as alice sub/x.env x'
git-age unlock >/dev/null

git config --unset age.keyFile
check "keygen in a subdirectory writes the key at the root, ignored by Git" \
  '(cd sub && git-age keygen >/dev/null 2>&1) && [[ -f .gitage.key && ! -e sub/.gitage.key ]] &&
   git check-ignore -q .gitage.key'
cp "$tmp/keys/alice" .gitage.key
check "a subdirectory uses the root .gitage.key" \
  '(cd sub && git-age lock && [[ $(git-age status --porcelain) == $'"'"'L. deep/y.env\nL. x.env'"'"' ]]) &&
   decrypts_as alice sub/x.env x &&
   git-age -C sub unlock && grep -qx x sub/x.env'
rm .gitage.key
git config age.keyFile "$tmp/keys/alice"

section "outside a Git repository"

plain=$tmp/plain
mkdir -p "$plain"
echo s >"$plain/a.env"
printf '[files]\n*.env\n' >"$plain/.gitage"
check "lock without Git or recipients encrypts to your identity" \
  'git-age -C "$plain" lock -i "$tmp/keys/alice" && decrypts_as alice "$plain/a.env" s'
check "unlock without Git" 'git-age -C "$plain" unlock -i "$tmp/keys/alice" && grep -qx s "$plain/a.env"'

section "a symlinked .gitage is ignored"

linked=$tmp/repo-symlink
mkdir -p "$linked/sub"
cd "$linked"
git init -q
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >"$tmp/gitage.linked"
ln -s "$tmp/gitage.linked" .gitage
printf '[files]\nx.env\n' >sub/.gitage
echo x >sub/x.env
# Git Bash copies instead of linking unless symbolic links are enabled.
if [[ -L .gitage ]]; then
  refuse "neither its rules nor its recipients apply" "no encryption key configured" \
    git -c age.keyFile= age lock
else
  skip "symbolic links are unavailable here"
fi
cd "$repo3"

section "dry runs"

check "lock, rekey and install -n report what they would do" \
  'git-age -n lock | grep -qx "would lock: top.env" &&
   git-age -n rekey | grep -qx "would rekey: top.env" &&
   git-age -n install --mode=abort | grep -q "would install git-age pre-commit hook"'
check "and change no files, hooks or config" \
  'status_is -- "U. sub/deep/y.env" "U. sub/x.env" "U. top.env" &&
   not test -e .git/hooks/pre-commit && not git config age.hookMode'

section "recipient sources"

check "lock -r overrides [recipients]" \
  'git-age lock -r "$bob" && decrypts_as bob top.env top && not decrypts_as alice top.env top'
git-age unlock -i "$tmp/keys/bob" >/dev/null
check "so does GIT_AGE_RECIPIENT" \
  'GIT_AGE_RECIPIENT="$carol" git-age lock && decrypts_as carol top.env top'
git-age unlock -i "$tmp/keys/carol" >/dev/null

section "hooks: unlock after commit, empty commits"

git-age install --mode=always-lock --unlock-after-commit >/dev/null
check "a commit stores the files encrypted and leaves them unlocked" \
  'git add -A && commit "secrets" && head_decrypts_as alice top.env top &&
   status_is -- "U. sub/deep/y.env" "U. sub/x.env" "U. top.env"'
stage_plaintext top.env sub/x.env sub/deep/y.env
refuse "a commit that encryption makes empty is refused" \
  "encrypt to the ciphertext already in HEAD" git commit -q -m "empty"
git-age unlock >/dev/null
stage_plaintext top.env sub/x.env sub/deep/y.env
check "GIT_AGE_ALLOW_EMPTY=1 allows it" env GIT_AGE_ALLOW_EMPTY=1 git commit -q --amend --no-edit
git config age.unlockAfterCommit false
git-age lock >/dev/null

section "hooks without a .gitage"

git config age.unlockAfterCommit true
git switch -q --orphan no-gitage
echo plain >plain.txt
git add plain.txt
check "commits without a staged .gitage succeed, silently" \
  '[[ -z $(git commit -q -m "no rules" 2>&1) && -z $(git commit -q --allow-empty -m "again" 2>&1) ]]'
echo "AGE-SECRET-KEY-1 is the marker" >notes.txt
git add notes.txt
check "without rules, mentioning the key marker is allowed" commit "notes"
git-age keygen >/dev/null 2>&1
git add -f .gitage.key
refuse "a staged .gitage.key is still refused" "refusing to commit private age keys" \
  git commit -q -m "oops"
git restore --staged .gitage.key
rm -f .gitage.key
refuse "explicit commands still need a .gitage" "no .gitage files staged" git-age check --cached
git switch -q main
git branch -q -D no-gitage
git config age.unlockAfterCommit false

section "hooks: removing a .gitage"

git switch -q -c drop-rules
git rm -q .gitage
refuse "a commit removing .gitage is refused" "refusing to commit the removal of .gitage" \
  git commit -q -m "drop rules"
refuse "check --cached refuses it too, suggesting a restore" \
  "git restore --staged --worktree -- .gitage" git-age check --cached
check "the suggested restore brings it back" 'git restore --staged --worktree -- .gitage && clean_tree'
rm .gitage
refuse "so is git commit -a after deleting it" "GIT_AGE_ALLOW_REMOVE=1" git commit -q -a -m "drop rules"
git restore --staged --worktree -- .gitage
git rm -q sub/.gitage
refuse "removing a nested .gitage is refused" "  sub/.gitage" git commit -q -m "drop sub rules"
git restore --staged --worktree -- sub/.gitage
git mv sub/.gitage sub/deep/.gitage
refuse "moving a .gitage counts as removing it" "  sub/.gitage" git commit -q -m "move rules"
git mv sub/deep/.gitage sub/.gitage
git rm -q .gitage sub/.gitage
warns "GIT_AGE_ALLOW_REMOVE=1 allows it" "by explicit choice (GIT_AGE_ALLOW_REMOVE)" \
  env GIT_AGE_ALLOW_REMOVE=1 git commit -q -m "drop rules"
check "and later commits are not refused" git commit -q --allow-empty -m "after"
git switch -q main
git branch -q -D drop-rules

section "readable diffs without a key"

check "git show without a key shows a placeholder" \
  'git -c age.keyFile= show --textconv HEAD:top.env | grep -q "git-age: encrypted, no identity configured"'

section "hooks: interactive"

git-age install --mode=interactive >/dev/null
git-age unlock >/dev/null
echo changed >top.env
git add -A
refuse "without a terminal the commit is aborted" "interactive confirmation is unavailable" \
  without_terminal git commit -q -m "no terminal"
if has_terminal; then
  refuse "answering a aborts the commit" "commit aborted" answer 'a\n' "aborted"
  check "answering e encrypts and commits" \
    'answer "e\n" encrypted && head_decrypts_as alice top.env changed'
  echo plain >top.env
  git add top.env
  refuse "c without typing commit aborts" "not confirmed" answer 'c\nno\n' "plaintext"
  check "c, then commit, commits plaintext" \
    'answer "c\ncommit\n" plaintext && [[ $(git show HEAD:top.env) == plain ]]'
else
  skip "interactive prompts (no terminal on Windows)"
fi

section "per-directory recipients"

# alice reads everything; carol, and later dave, only prod/.
repo4=$tmp/repo-scoped
mkdir -p "$repo4/prod"
cd "$repo4"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo app >app.env
echo db >prod/db.env
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
printf '[recipients]\n# Carol\n%s\n' "$carol" >prod/.gitage

check "a nested [recipients] adds carol below prod/ only" \
  'git-age lock && decrypts_as carol prod/db.env db && decrypts_as alice prod/db.env db &&
   not decrypts_as carol app.env app'
check "status -v names the nested list" \
  'git-age -v status | grep -q "encrypted to .* + prod/.gitage \[recipients\]"'
git add -A
commit "scoped secrets"

check "status marks what carol cannot read" \
  'as carol status | grep -q "^LOCKED *app.env (no access)" &&
   [[ $(as carol status --porcelain) == $'"'"'LN app.env\nL. prod/db.env'"'"' ]]'
warns "unlock as carol skips what is not hers" "1 file(s) locked that are not encrypted to you" \
  as carol unlock
check "unlocking prod/db.env only" 'grep -qx db prod/db.env && is_locked app.env'
check "carol relocks to the same ciphertext" 'as carol lock && clean_tree'

printf '# Dave\n%s\n' "$dave" >>prod/.gitage
check "a nested change makes only its files stale" \
  '[[ $(git-age status --porcelain) == $'"'"'L. app.env\nLS prod/db.env'"'"' ]]'
warns "dave is told prod/db.env is not re-encrypted to him yet" "not re-encrypted to you yet" \
  as dave unlock
check "and it stays locked" is_locked prod/db.env
git-age install --mode=always-lock >/dev/null
git add prod/.gitage
refuse "the hook refuses the nested change before rekey" "prod/db.env" git commit -q -m "add dave"
warns "carol rekeys what she can and names the rest" "app.env" as carol rekey
check "dave can decrypt prod/db.env now, and app.env was left alone" \
  'decrypts_as dave prod/db.env db && [[ -z $(git status --porcelain app.env) ]]'
check "the commit goes through, re-encrypting only prod/db.env" \
  'git add -A && commit "add dave" && [[ $(git diff --name-only HEAD^ HEAD -- "*.env") == prod/db.env ]]'
age -r "$alice" -o prod/db.env <<<'tampered'
refuse "a file meant for dave that fails to decrypt still stops unlock" "cannot decrypt" as dave unlock
git checkout -q -- prod/db.env

section "recipient trust"

# Mallory, who can push, adds keys behind everyone's back; bob's key stands in for hers.
mallory_commit() {
  git -c user.name=Mallory -c user.email=mallory@example.invalid commit -q --no-verify -m "$1"
}

git-age unlock >/dev/null
printf '# Mallory\n%s\n' "$bob" >>prod/.gitage
git add prod/.gitage
mallory_commit "add a key"
warns "without a pin, lock warns about someone else's change" \
  "Mallory <mallory@example.invalid>" git-age lock

git-age unlock >/dev/null
check "trust pins the current lists in age.trustedRecipients" \
  'git-age trust && [[ $(git-age trust --show) == $(git config age.trustedRecipients) ]]'
check "with the lists pinned, lock does not warn" '! git-age lock 2>&1 | grep -q "someone else"'

git-age unlock >/dev/null
printf '%s\n' "$dave" >>.gitage
git add .gitage
mallory_commit "widen access"
refuse "lock refuses lists that differ from the pin" "untrusted [recipients]" git-age lock
check "naming the new key and who added it, and locking nothing" \
  'out=$(git-age lock 2>&1); grep -q "+ $dave" <<<"$out" && grep -q Mallory <<<"$out" &&
   not is_locked prod/db.env'
warns "status says the lists differ" "differ from the ones you trusted" git-age status
check "trust shows the change it accepts, and lock then works" \
  'git-age trust | grep -q "+ $dave" && git-age lock'

git-age unlock >/dev/null
sed_i '$d' .gitage
refuse "your own uncommitted edits need trust too" "(uncommitted changes)" git-age lock
echo db2 >prod/db.env
git add -A
refuse "the pre-commit hook refuses to encrypt to untrusted lists" "untrusted" git commit -q -m "edit"
git reset -q
git checkout -q -- .gitage prod/db.env
git-age lock >/dev/null 2>&1

git checkout -q -b mallory
printf '%s\n' "$carol" >>.gitage
git add .gitage
mallory_commit "sneak a key in"
git checkout -q main
warns "post-merge warns when a merge changes [recipients]" "this merge changes [recipients]" \
  git merge -q mallory

section "recipient trust: changes made in a merge"

trust_merge=$tmp/repo-merge-trust
mkdir -p "$trust_merge"
cd "$trust_merge"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo app >app.env
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
git-age lock >/dev/null
git add -A && git commit -q --no-verify -m "init" </dev/null
git checkout -q -b theirs
printf '%s\n' "$bob" >>.gitage
git commit -q --no-verify -am "theirs: add bob" </dev/null
git checkout -q main
printf '%s\n' "$carol" >>.gitage
git commit -q --no-verify -am "main: add carol" </dev/null
git merge -q --no-edit theirs >/dev/null 2>&1 || true
printf '[files]\n*.env\n\n[recipients]\n%s\n%s\n%s\n%s\n' "$alice" "$bob" "$carol" "$dave" >.gitage
git add .gitage
mallory_commit "merge theirs"
git-age unlock >/dev/null
warns "a [recipients] change made in a merge counts" "merge theirs" git-age lock
git reset -q --hard HEAD~1
git -c user.name=Mallory -c user.email=mallory@example.invalid merge -q --no-edit -X theirs theirs \
  >/dev/null 2>&1
git-age unlock >/dev/null
check "a merge that takes one side's lists does not" '! git-age lock 2>&1 | grep -q "someone else"'

section "partial access without a base list"

repo5=$tmp/repo-nobase
mkdir -p "$repo5/prod"
cd "$repo5"
git init -q
echo app >app.env
echo db >prod/db.env
printf '[files]\n*.env\n' >.gitage
printf '[recipients]\n%s\n' "$carol" >prod/.gitage

check "alice locks to her identity, plus carol under prod/" \
  'as alice lock && decrypts_as carol prod/db.env db && decrypts_as alice app.env app'
warns "carol's unlock leaves app.env alone" "not encrypted to you" as carol unlock
check "and status marks it for her" \
  'is_locked app.env && [[ $(as carol status --porcelain) == $'"'"'LN app.env\nU. prod/db.env'"'"' ]]'
refuse "someone listed nowhere still gets an error" "cannot decrypt" as dave unlock

section "merge driver"

repo6=$tmp/repo-merge
mkdir -p "$repo6"
cd "$repo6"
git init -q
git config age.keyFile "$tmp/keys/alice"
printf '[files]\n*.env\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
printf 'A=1\nB=1\nC=1\n' >app.env
git-age install --mode=always-lock >/dev/null
git add -A
commit "base"
git-age lock >/dev/null
# edit BRANCH CONTENT MESSAGE: commit an encrypted edit of app.env on BRANCH.
edit() {
  git checkout -q "$1"
  printf "$2" >app.env
  git add app.env
  commit "$3" 2>/dev/null
  git-age lock >/dev/null
}

git branch side
edit side 'A=2\nB=1\nC=1\n' "side: A"
edit main 'A=1\nB=1\nC=2\n' "main: C"
check "changes to different lines merge cleanly, encrypted" \
  'git merge -q --no-edit side && head_decrypts_as bob app.env $'"'"'A=2\nB=1\nC=2'"'"' && clean_tree'

git branch side2
edit side2 'A=3\nB=1\nC=2\n' "side2: A"
edit main 'A=3\nB=1\nC=2\n' "main: A too"
check "the same change on both sides merges to one side's ciphertext" \
  'git merge -q --no-edit side2 &&
   { [[ $(git rev-parse HEAD:app.env) == $(git rev-parse HEAD^1:app.env) ]] ||
     [[ $(git rev-parse HEAD:app.env) == $(git rev-parse HEAD^2:app.env) ]]; }'

git branch side3
edit side3 'A=3\nB=side\nC=2\n' "side3: B"
edit main 'A=3\nB=main\nC=2\n' "main: B"
refuse "a conflicting change conflicts" "is now UNLOCKED" git merge -q --no-edit side3
check "leaving plaintext conflict markers" 'grep -qx "<<<<<<< ours" app.env && grep -qx B=side app.env'
printf 'A=3\nB=both\nC=2\n' >app.env
check "git add encrypts the resolution, which commits" \
  'git add app.env && staged_is_locked app.env && commit "merge side3" &&
   head_decrypts_as bob app.env $'"'"'A=3\nB=both\nC=2'"'"''

git branch side4
edit side4 'A=3\nB=side4\nC=2\n' "side4: B"
edit main 'A=3\nB=main4\nC=2\n' "main: B again"
git checkout -q side4
refuse "a rebase conflicts the same way" "is now UNLOCKED" git rebase -q main
printf 'A=3\nB=rebased\nC=2\n' >app.env
check "rebase --continue, which skips pre-commit, commits it encrypted" \
  'git add app.env && GIT_EDITOR=true git rebase --continue &&
   head_decrypts_as alice app.env $'"'"'A=3\nB=rebased\nC=2'"'"''

git checkout -q main
git branch side6
edit side6 'A=3\nB=side6\nC=2\n' "side6: B"
edit main 'A=3\nB=main6\nC=2\n' "main: B once more"
git checkout -q side6
refuse "another rebase conflicts" "is now UNLOCKED" git rebase -q main
printf 'A=3\nB=untrusted\nC=2\n' >app.env
git config age.trustedRecipients deadbeef
refuse "git add refuses a resolution it cannot encrypt" "Refusing to stage it as plaintext" \
  git add app.env
check "the path stays unmerged, and git status still works" \
  '[[ -n $(git ls-files -u app.env) ]] && git status --porcelain'
refuse "rebase --continue cannot commit the plaintext" "app.env" \
  env GIT_EDITOR=true git rebase --continue
git config --unset age.trustedRecipients
check "once fixed, rebase --continue commits it encrypted" \
  'git add app.env && GIT_EDITOR=true git rebase --continue &&
   head_decrypts_as alice app.env $'"'"'A=3\nB=untrusted\nC=2'"'"''

git checkout -q main
git branch side5
edit side5 'A=5\nB=main4\nC=2\n' "side5: A"
edit main 'A=3\nB=main4\nC=5\n' "main: C again"
ours=$(git rev-parse HEAD:app.env)
refuse "without a key the merge conflicts" "keeping our version" \
  git -c age.keyFile= merge -q --no-edit side5
check "and keeps our ciphertext" '[[ $(git hash-object app.env) == "$ours" ]]'
git merge --abort

git-age install --mode=always-lock --no-merge >/dev/null
refuse "after install --no-merge, even separate changes conflict" "CONFLICT" \
  git merge -q --no-edit side5
git merge --abort
git-age install --mode=always-lock >/dev/null

section "status is read-only; lock applies .gitage changes"

cp .gitage "$tmp/gitage.saved"
sed_i '/^\[files\]$/a\
*.secret
' .gitage
echo hidden >new.secret
git_files() { find .git -type f ! -name index ! -name '*.lock' -exec cksum {} + | LC_ALL=C sort; }
before=$(git_files)
check "status writes nothing to the repository" 'git-age status >/dev/null && [[ $(git_files) == "$before" ]]'
check "after lock, Git shows the new protected file readably" \
  'git-age lock && git add new.secret && staged_is_locked new.secret &&
   [[ $(git cat-file --textconv :new.secret) == hidden ]]'
git rm -q --cached new.secret
rm new.secret
cp "$tmp/gitage.saved" .gitage
check "and again once .gitage is back" git-age lock

section "install without Git attributes"

hooks=$(git rev-parse --git-path hooks)
check "-n says it would remove the hooks that sync them" \
  'git-age -n install --no-diff --no-merge --no-filter | grep -q "would remove git-age post-checkout hook"'
check "install --no-diff --no-merge --no-filter turns off readable diffs" \
  'git-age install --mode=always-lock --no-diff --no-merge --no-filter &&
   ! git cat-file --textconv HEAD:app.env | grep -q "A=3"'
check "keeping only post-merge, which warns about [recipients] changes" \
  '[[ ! -e $hooks/post-checkout && ! -e $hooks/post-rewrite && -x $hooks/post-merge ]]'
printf '#!/bin/sh\nexit 0\n' >"$hooks/post-checkout"
check "it leaves a hook it does not own alone" \
  'git-age install --mode=always-lock --no-diff --no-merge --no-filter && [[ -e $hooks/post-checkout ]]'
rm "$hooks/post-checkout"

# --- history: audit and audit --rekey ------------------------------------------

section "audit finds protected files committed as plaintext"

history=$tmp/history
mkdir -p "$history"
cd "$history"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo 'TOKEN=early' >early.env
echo 'hello' >readme
git add . && commit "before .gitage"
printf '[files]\n*.env\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
echo 'TOKEN=locked' >locked.env
git-age lock >/dev/null
git add -A && commit "add .gitage"
git checkout -q -b side
echo 'TOKEN=side' >side.env
git add side.env && commit "side: plaintext"
git-age lock >/dev/null
git add side.env && commit "side: locked"
git checkout -q main
printf '[files]\n*.env\nold.txt\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
echo 'was protected' >old.txt
git add -A && commit "old.txt protected, as plaintext"
printf '[files]\n*.env\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
git add -A && commit "old.txt no longer protected"
git merge -q --no-edit side
git tag -a v1 -m "release"
git -c advice.nestedTag=false tag -a v1-nested -m "a tag of a tag" v1
git branch side-head side

audit_status=0
audit_out=$(git-age audit 2>&1) || audit_status=$?
check "audit fails, listing plaintext committed before .gitage, on a branch, or protected then" \
  '((audit_status == 1)) && grep -qx "  early.env" <<<"$audit_out" &&
   grep -qx "  side.env" <<<"$audit_out" && grep -qx "  old.txt" <<<"$audit_out"'
check "but not ciphertext or unprotected files" \
  '! grep -qE "locked.env|readme" <<<"$audit_out"'
check "audit REV searches only that history" '! git-age audit main~1 2>&1 | grep -q side.env'
mkdir -p sub
check "-C subdir audits the whole repository" 'git-age -C sub audit 2>&1 | grep -qx "  early.env"'

section "audit --rekey re-encrypts history"

printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
git commit -q -am "drop bob" </dev/null
before=$(git rev-parse HEAD)
refuse "without a terminal it asks for --yes" "pass --yes" git-age audit --rekey
echo dirty >>readme
refuse "a dirty working tree is refused" "uncommitted changes" git-age audit --rekey --yes
git checkout -q readme
refuse "it takes no revisions" "takes no revisions" git-age audit --rekey --yes main
check "--dry-run rewrites nothing" \
  'git-age -n audit --rekey | grep -q "would rewrite" && [[ $(git rev-parse HEAD) == "$before" ]]'
refuse "what it cannot decrypt stops it" "cannot decrypt" \
  env GIT_AGE_KEY_FILE="$tmp/keys/carol" GIT_AGE_RECIPIENT="$carol" git-age audit --rekey --yes
check "and nothing moved" '[[ $(git rev-parse HEAD) == "$before" ]]'

warns "audit --rekey --yes rewrites" "git-age audit -- --branches --tags" git-age audit --rekey --yes
check "moving the branch, keeping the old one in refs/git-age/original, so audit passes" \
  '[[ $(git rev-parse refs/git-age/original/refs/heads/main) == "$before" &&
      $(git rev-parse HEAD) != "$before" ]] && git-age audit'
git update-ref refs/remotes/origin/main "$before"
refuse "remote-tracking refs keep the old history" "early.env" git-age audit
check "audit -- --branches --tags leaves them out" git-age audit -- --branches --tags
git update-ref -d refs/remotes/origin/main

# every_version WHO can|cannot: WHO can (or cannot) decrypt every .env in history.
every_version() {
  local who=$1 want=$2 commit path
  for commit in $(git rev-list --exclude='refs/git-age/*' --all); do
    for path in $(git ls-tree -r --name-only "$commit" | grep '\.env$'); do
      if git show "$commit:$path" | age -d -i "$tmp/keys/$who" >/dev/null 2>&1; then
        [[ $want == can ]] || return 1
      else
        [[ $want == cannot ]] || return 1
      fi
    done
  done
}
check "alice can read every version; bob, removed, none" \
  'every_version alice can && every_version bob cannot'
check "a file no longer protected stays as it was" 'git show HEAD~2:old.txt | grep -qx "was protected"'
check "tags, tags of tags and every branch point into the new history" \
  'git merge-base --is-ancestor "v1^{commit}" HEAD &&
   [[ $(git cat-file -p v1-nested | sed -n "1s/^object //p") == $(git rev-parse v1) ]] &&
   git merge-base --is-ancestor "v1-nested^{commit}" HEAD &&
   git merge-base --is-ancestor side-head HEAD && clean_tree'
refuse "a second rewrite wants the backup gone" "previous rewrite" git-age audit --rekey --yes

section "audit finds committed private keys"

keyleak=$tmp/keyleak
mkdir -p "$keyleak"
cd "$keyleak"
git init -q
git config age.keyFile "$tmp/keys/alice"
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
echo 'hello' >readme
git add . && commit "init"
check "audit passes without leaks" git-age audit
cp "$tmp/keys/alice" k.txt
git add k.txt && git commit -q --no-verify -m "key as k.txt" </dev/null
key_status=0
key_out=$(git-age audit 2>&1) || key_status=$?
check "a key committed as k.txt fails audit, listed with the commit that added it" \
  '((key_status == 1)) && grep -qx "Private age keys committed to Git history:" <<<"$key_out" &&
   grep -qx "  k.txt" <<<"$key_out" && grep -q "in [0-9a-f]\{12\}  key as k.txt$" <<<"$key_out"'
check "saying it is compromised and that --rekey does not purge it" \
  'grep -q compromised <<<"$key_out" && grep -q "git filter-repo" <<<"$key_out" &&
   ! grep -q "committed as plaintext:" <<<"$key_out"'
git rm -q k.txt && commit "remove k.txt"
echo 'not a key' >.gitage.key
git add -f .gitage.key && git commit -q --no-verify -m "a .gitage.key" </dev/null
echo 'TOKEN=plain' >app.env
git add app.env && git commit -q --no-verify -m "plaintext app.env" </dev/null
key_status=0
key_out=$(git-age audit 2>&1) || key_status=$?
check "a .gitage.key fails audit whatever its content; a removed key still counts" \
  '((key_status == 1)) && grep -qx "  .gitage.key" <<<"$key_out" && grep -qx "  k.txt" <<<"$key_out"'
check "plaintext is listed in its own group, not as a key" \
  'grep -qx "Protected files committed as plaintext:" <<<"$key_out" &&
   ! sed -n "/^Private/,/^Protected/p" <<<"$key_out" | grep -q app.env &&
   ! grep -q readme <<<"$key_out"'
echo 'not a key either' >.gitage.key
git add -f .gitage.key && git commit -q --no-verify -m "change .gitage.key" </dev/null
check "audit lists one version by default, -v every one" \
  'git-age audit 2>&1 | grep -q "and 1 more version(s); -v lists them" &&
   [[ $(git-age -v audit 2>&1 | grep -c "in [0-9a-f]\{12\}  .*gitage.key") -eq 2 ]]'
git rm -q --cached .gitage.key && rm .gitage.key && commit "remove .gitage.key"
warns "audit --rekey warns about committed keys" "private key file(s) are in Git history" \
  git-age -n audit --rekey

section "pre-push refuses to publish plaintext"

push_repo=$tmp/repo-push
push_remote=$tmp/remote.git
git init -q --bare "$push_remote"
mkdir -p "$push_repo"
cd "$push_repo"
git init -q
git config age.keyFile "$tmp/keys/alice"
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
echo 'TOKEN=one' >app.env
git-age install --mode=always-lock >/dev/null
git add -A && commit "init"
git remote add origin "$push_remote"
check "a clean push succeeds" git push -q origin main
remote_main() { git --git-dir="$push_remote" rev-parse main; }
pushed=$(git rev-parse HEAD)

git-age unlock >/dev/null
echo 'TOKEN=two' >app.env
git add app.env && git commit -q --no-verify -m "plaintext app.env" </dev/null
refuse "a plaintext commit made with --no-verify is refused" "push aborted" git push -q origin main
check "the remote did not get it" '[[ $(remote_main) == "$pushed" ]]'
refuse "the refusal names the file" "  app.env" git push -q origin main
refuse "and how to push anyway" "GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push" git push -q origin main
warns "GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 allows it" "by explicit choice (GIT_AGE_ALLOW_PLAINTEXT_PUSH)" \
  env GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push -q origin main
check "the remote got it" '[[ $(remote_main) == $(git rev-parse HEAD) ]]'
git-age lock >/dev/null
git add app.env && commit "encrypt app.env"
check "what the remote has is not audited again" git push -q origin main

git switch -q -c leak
git-age unlock >/dev/null
echo 'TOKEN=three' >app.env
git add app.env && git commit -q --no-verify -m "plaintext again" </dev/null
refuse "a new branch is audited too" "push aborted" git push -q origin leak
check "git push --no-verify skips the hook; deleting a branch is not audited" \
  'git push -q --no-verify origin leak && git push -q origin :leak'
git switch -q main
git-age lock >/dev/null

git switch -q -c rebased
git switch -q -c side main
echo 'TOKEN=side' >app.env
git commit -q --no-verify -am "plaintext on side" </dev/null
git switch -q rebased
git cherry-pick side >/dev/null
refuse "a cherry-picked plaintext commit is refused" "push aborted" git push -q origin rebased
git switch -q main
git branch -q -D rebased side
git-age lock >/dev/null

git switch -q -c keys
cp "$tmp/keys/bob" k.txt
git add k.txt && git commit -q --no-verify -m "a key" </dev/null
refuse "a committed private key is refused" "Private age keys in the commits being pushed" \
  git push -q origin keys
git switch -q main
git branch -q -D keys

section "pre-push without a .gitage"

git switch -q --orphan no-rules
echo "AGE-SECRET-KEY-1 is the marker" >notes.txt
git add notes.txt && git commit -q --no-verify -m "no rules" </dev/null
check "pushing a branch without a .gitage succeeds, silently" '[[ -z $(git push -q origin no-rules 2>&1) ]]'
check "pushed commits with their own .gitage are still audited" \
  '! git push -q origin leak 2>/dev/null && [[ -z $(git ls-remote origin refs/heads/leak) ]]'
git switch -q main
git-age lock >/dev/null
back=$PWD

section "path arguments"

repo7=$tmp/repo-paths
mkdir -p "$repo7/sub" "$repo7/docs"
cd "$repo7"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo a-plaintext >a.env
echo b >sub/b.env
echo c >sub/c.env
echo notes >notes.txt
echo doc >docs/readme.txt
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage

check "lock FILE locks only that file" \
  'git-age lock a.env && status_is -- "L. a.env" "U. sub/b.env" "U. sub/c.env"'
check "lock DIR locks the files below it" \
  'git-age lock sub && status_is -- "L. a.env" "L. sub/b.env" "L. sub/c.env"'
check "unlock FILE unlocks only that file" \
  'git-age unlock sub/b.env && status_is -- "L. a.env" "U. sub/b.env" "L. sub/c.env"'
check "status takes PATHs, files or directories" \
  '[[ $(git-age status --porcelain sub) == $'"'"'U. sub/b.env\nL. sub/c.env'"'"' &&
     $(git-age status --porcelain sub/c.env a.env) == $'"'"'L. a.env\nL. sub/c.env'"'"' ]]'
check "PATHs are relative to -C" \
  'git-age -C sub unlock c.env && status_is -- "L. a.env" "U. sub/b.env" "U. sub/c.env"'
check "PATHs are relative to the current directory" \
  '(cd sub && git-age lock ./b.env && [[ $(git-age status --porcelain) == $'"'"'L. b.env\nU. c.env'"'"' ]])'
check "rekey PATH rekeys only that file" '[[ $(git-age -n rekey sub/c.env) == "would rekey: sub/c.env" ]]'
refuse "a PATH that .gitage does not protect is an error" "notes.txt: not protected by .gitage" \
  git-age lock sub/c.env notes.txt
check "and nothing is locked, not even the matching PATH" \
  'not is_locked sub/c.env && grep -qx notes notes.txt'
refuse "a missing PATH is an error" "nope.env: no such file or directory" git-age unlock nope.env
refuse "a directory without protected files is an error" "docs: no file in it is protected" \
  git-age status docs
refuse "a PATH outside -C is an error" "../a.env: outside" git-age -C sub lock ../a.env
refuse "a PATH outside the repository is an error" "outside" git-age lock "$tmp/keys/alice"
check "the refusals changed nothing" status_is -- 'L. a.env' 'L. sub/b.env' 'U. sub/c.env'

section "edit"

git-age lock >/dev/null
git add -A && commit "secrets"
# The editor records whether anyone else could read the file it was given,
# and what Git saw in the working tree meanwhile, then appends a line.
cat >"$tmp/append-editor" <<'EOF'
#!/bin/sh
python3 -c 'import os, sys
path = sys.argv[1]
print(any(os.stat(p).st_mode & 0o077 == 0 for p in (path, os.path.dirname(path))))' "$1" \
  >"${0%/*}/edit-private"
git status --porcelain --untracked-files=all >"${0%/*}/edit-status"
printf 'NEW=1\n' >>"$1"
EOF
printf '#!/bin/sh\nprintf "NEW=1\\n" >>"$1"\nexit 1\n' >"$tmp/failing-editor"
chmod +x "$tmp/append-editor" "$tmp/failing-editor"
# no_plaintext_left: no decrypted copy of a.env is anywhere in the test's files.
no_plaintext_left() { ! grep -rqF a-plaintext "$tmp"; }

cp a.env "$tmp/a.env.before"
check "edit with an editor that changes nothing leaves the file byte for byte" \
  'EDITOR=true git-age edit a.env && cmp -s a.env "$tmp/a.env.before"'
check "edit re-encrypts the change" \
  'EDITOR="$tmp/append-editor" git-age edit a.env && decrypts_as alice a.env $'"'"'a-plaintext\nNEW=1'"'"''
check "the editor got a copy outside the working tree, gone afterwards" \
  '[[ ! -s $tmp/edit-status ]] && no_plaintext_left'
if [[ $platform != windows ]]; then
  check "which no one else could read" '[[ $(cat "$tmp/edit-private") == True ]]'
fi
check "edit -C sub FILE is relative to -C" \
  'EDITOR="perl -pi -e s/b/B/" git-age -C sub edit b.env && decrypts_as alice sub/b.env B'
check "editing it back reuses the committed ciphertext" \
  'EDITOR="perl -pi -e s/B/b/" git-age edit sub/b.env && git diff --quiet -- sub/b.env'
cp a.env "$tmp/a.env.before"
refuse "a failing editor is an error" "exit status 1; a.env was not changed" \
  env EDITOR="$tmp/failing-editor" git-age edit a.env
check "that leaves the file as it was, with no decrypted copy" \
  'cmp -s a.env "$tmp/a.env.before" && no_plaintext_left'
check "edit -n changes nothing" \
  '[[ $(EDITOR="$tmp/append-editor" git-age -n edit a.env) == "would edit: a.env" ]] &&
   cmp -s a.env "$tmp/a.env.before"'
refuse "edit refuses a file .gitage does not protect" "notes.txt: not protected by .gitage" \
  env EDITOR="$tmp/append-editor" git-age edit notes.txt
refuse "edit refuses a directory" "is a directory" env EDITOR=true git-age edit sub
git-age unlock sub/c.env >/dev/null
warns "edit opens an unlocked file in place" "sub/c.env is unlocked" \
  env EDITOR="$tmp/append-editor" git-age edit sub/c.env
check "it stays plaintext, edited" '[[ $(cat sub/c.env) == $'"'"'c\nNEW=1'"'"' ]]'
cd "$back"

section "uninstall"

git rm -q .gitage
refuse "the .gitage removal refusal suggests uninstall" "git-age uninstall" git commit -q -m "drop rules"
git restore --staged --worktree -- .gitage
hooks=$(git rev-parse --git-path hooks)
printf '#!/bin/sh\nexit 0\n' >"$hooks/post-rewrite"
chmod +x "$hooks/post-rewrite"
# installed: the hooks are in place, and Git decrypts diffs.
installed() {
  [[ -x $hooks/pre-commit && -x $hooks/pre-push ]] && git config age.hookMode >/dev/null &&
    git cat-file --textconv HEAD:app.env | grep -q TOKEN=
}
check "uninstall -n says what it would do, and changes nothing" \
  'git-age -n uninstall | grep -q "would remove git-age pre-push hook" && installed'
warns "uninstall keeps a hook it did not install" "Kept post-rewrite hook" git-age uninstall
check "it removes its hooks, its config and readable diffs" \
  'for hook in pre-commit post-commit pre-push post-checkout post-merge; do
     [[ ! -e $hooks/$hook ]] || exit 1
   done
   [[ -x $hooks/post-rewrite ]] && not git config age.hookMode &&
   ! git cat-file --textconv HEAD:app.env | grep -q TOKEN='
check "keeping age.keyFile and the file locked" 'git config age.keyFile && is_locked app.env'
check "a second uninstall has nothing to do" \
  'git-age uninstall | grep -qx "git-age: nothing to uninstall"'
rm "$hooks/post-rewrite"
check "install puts it all back" 'git-age install --mode=always-lock && installed'

section "help"

check "help prints the whole manual, anywhere, without a key" \
  'out=$(git-age -C "$tmp" help) && grep -qx "QUICK START" <<<"$out" && grep -qx "SHELL COMPLETION" <<<"$out" &&
   git-age --help | grep -qF "git-age help"'
check "help TOPIC prints one section, found by a word or a prefix, in any case" \
  'out=$(git-age help hooks) && [[ $(head -1 <<<"$out") == "GIT HOOKS" ]] && ! grep -qx KEYS <<<"$out" &&
   [[ $(git-age help trust | head -1) == "RECIPIENT TRUST" &&
      $(git-age help INTEG | head -1) == "GIT INTEGRATION" &&
      $(git-age help .gitage | head -1) == .GITAGE ]]'
check "help COMMAND prints the command's options" 'git-age help lock | grep -q "^usage: git-age lock"'
refuse "an unknown topic lists the topics" "topics are: quick-start, everyday-use, commands" \
  git-age help nonsense
if has_terminal; then
  check "on a terminal, the manual goes through Git's pager" \
    'GIT_PAGER="sed s/^/paged:/" on_terminal "git-age help" | tr -d "\r" | grep -x "paged:QUICK START" >/dev/null'
else
  skip "the pager (no terminal on Windows)"
fi
check "without a terminal, it is printed plainly" \
  'GIT_PAGER="sed s/^/paged:/" git-age help | grep -qx "QUICK START"'

section "shell completion"

check "the bash script parses" 'bash -n <(git-age completion bash)'
for shell in zsh fish; do
  if command -v "$shell" >/dev/null; then
    check "the $shell script parses" "git-age completion $shell | $shell $([[ $shell == fish ]] && echo --no-config) -n"
  else
    skip "$shell is not installed"
  fi
done
refuse "an unknown shell is refused" "invalid choice: 'tcsh'" git-age completion tcsh

# bash_complete WORD...: what bash completes for the last WORD.
bash_complete() {
  bash -c 'source <(git-age completion bash)
    COMP_WORDS=("$@") COMP_CWORD=$(($# - 1))
    if [[ $1 == git ]]; then
      # As Git'"'"'s completion sets them.
      words=("$@") cword=$COMP_CWORD __git_cmd_idx=1
      _git_age
    else
      _git_age_main
    fi
    printf "%s\n" "${COMPREPLY[@]}"' bash "$@"
}
# completes EXPECTED WORD...: bash completes the last WORD as exactly EXPECTED.
completes() { [[ $(bash_complete "${@:2}") == "$1" ]]; }
# offers_documented_commands COMPLETIONS: lock is offered, and only commands the manual lists.
manual=$(git-age help commands)
offers_documented_commands() {
  local command
  grep -qx lock <<<"$1" || return 1
  for command in $1; do grep -q "^    $command\b" <<<"$manual" || return 1; done
}
check "bash completes commands, options, choices and files" \
  'completes lock git-age lo && completes unlock git-age -C . -n unl &&
   completes --no-reuse git-age lock --no && completes always-lock git-age install --mode al &&
   completes always-lock git-age install --mode = al &&
   completes "$tmp/keys/alice" git-age unlock -i "$tmp/keys/al" && completes git-hooks git-age help git-ho'
check "it offers only documented commands, also as git age" \
  'offers_documented_commands "$(bash_complete git-age "")" &&
   offers_documented_commands "$(bash_complete git age "")" && completes rekey git age rek'
if command -v fish >/dev/null; then
  fish_complete() { fish --no-config -c "source (git-age completion fish | psub); complete -C \"$1\"" | cut -f1; }
  check "fish completes documented commands and choices" \
    'offers_documented_commands "$(fish_complete "git-age ")" &&
     [[ $(fish_complete "git-age install --mode=al") == --mode=always-lock ]]'
fi

# --- summary -------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[[ $failed -eq 0 ]]
