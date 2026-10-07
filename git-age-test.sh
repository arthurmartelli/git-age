#!/usr/bin/env bash
#
# git-age-test.sh: end-to-end smoke test for git-age.
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

# Hooks run `git age`, so put the git-age under test first on PATH.
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

repo=$tmp/repo
mkdir -p "$repo"
cd "$repo"

# --- helpers -------------------------------------------------------------------

passed=0
failed=0

section() { printf '\n== %s\n' "$*"; }
pass() { passed=$((passed + 1)); printf '  ok    %s\n' "$*"; }
fail() { failed=$((failed + 1)); printf '  FAIL  %s\n' "$*"; }

# check DESCRIPTION COMMAND...: the command must succeed.
check() {
  local description=$1; shift
  local output
  if output=$("$@" 2>&1); then
    pass "$description"
  else
    fail "$description"
    printf '%s\n' "$output" | sed 's/^/        | /'
  fi
}

# refuse DESCRIPTION PATTERN COMMAND...: the command must fail and print PATTERN.
refuse() {
  local description=$1 pattern=$2; shift 2
  local output status=0
  output=$("$@" 2>&1 </dev/null) || status=$?
  if [[ $status -ne 0 ]] && grep -qF -- "$pattern" <<<"$output"; then
    pass "$description"
  else
    fail "$description (exit $status, expected: $pattern)"
    printf '%s\n' "$output" | sed 's/^/        | /'
  fi
}

# warns DESCRIPTION PATTERN COMMAND...: the command must succeed and print PATTERN.
warns() {
  local description=$1 pattern=$2; shift 2
  local output status=0
  output=$("$@" 2>&1 </dev/null) || status=$?
  if [[ $status -eq 0 ]] && grep -qF -- "$pattern" <<<"$output"; then
    pass "$description"
  else
    fail "$description (exit $status, expected: $pattern)"
    printf '%s\n' "$output" | sed 's/^/        | /'
  fi
}

is_locked() { head -c 21 "$1" | grep -q '^age-encryption.org/v1'; }
head_is_locked() { git show "HEAD:$1" | head -c 21 | grep -q '^age-encryption.org/v1'; }
decrypts_as() { [[ $(age -d -i "$tmp/keys/$1" "$2" 2>/dev/null) == "$3" ]]; }
head_decrypts_as() { [[ $(git show "HEAD:$2" | age -d -i "$tmp/keys/$1" 2>/dev/null) == "$3" ]]; }
not() { ! "$@"; }
mode_is() {
  [[ $(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777)[2:])' "$1") == "$2" ]]
}
# sed_i SCRIPT FILE: edit FILE in place; BSD and GNU sed disagree on -i.
sed_i() { sed "$1" "$2" >"$2.sed" && mv "$2.sed" "$2"; }
clean_tree() { [[ -z $(git status --porcelain) ]]; }
commit() { git commit -q -m "$1" </dev/null; }

# status_is [ARGS...] -- RECORD...: `git-age ARGS... status --porcelain`
# prints exactly these records.
status_is() {
  local args=()
  while [[ $1 != -- ]]; do args+=("$1"); shift; done
  shift
  [[ $("$GIT_AGE" "${args[@]}" status --porcelain 2>/dev/null) == "$(printf '%s\n' "$@")" ]]
}

# on_terminal COMMAND: run the shell COMMAND on a pseudo-terminal, typing
# what is on stdin. Unlike script(1), this works alike on Linux and macOS.
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

git init -q
git config age.keyFile "$tmp/keys/alice"
mkdir config
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
  bash -c '"$0" status | grep -q "UNLOCKED *secret.env" && "$0" status | grep -q "UNLOCKED *config/credentials.yaml"' "$GIT_AGE"

check "status --porcelain lists both files as unlocked" \
  bash -c '[[ $("$0" status --porcelain) == $'"'"'U. config/credentials.yaml\nU. secret.env'"'"' ]]' "$GIT_AGE"
check "status -z NUL-terminates records" \
  bash -c '"$0" status -z | tr "\0" "\n" | grep -qx "U. secret.env"' "$GIT_AGE"

section "lock / unlock"

check "lock encrypts both files" "$GIT_AGE" lock
check "secret.env is ciphertext" is_locked secret.env
check "config/credentials.yaml is ciphertext" is_locked config/credentials.yaml
check "bob can decrypt (recipient)" decrypts_as bob secret.env 'API_TOKEN=s3cr3t'
check "carol cannot decrypt (not a recipient)" not decrypts_as carol secret.env 'API_TOKEN=s3cr3t'
check "unlock restores plaintext" "$GIT_AGE" unlock
check "secret.env is plaintext again" grep -qx 'API_TOKEN=s3cr3t' secret.env

section "lock / unlock are all-or-nothing"

no_leftovers() { [[ -z $(find . -name '.*.git-age-*' -print -quit) ]]; }

# root reads files whatever their mode, so it cannot test this; nor can
# Windows, where chmod does not take away read access.
if [[ $platform == windows ]]; then
  echo "  skip  unreadable files (Windows)"
elif [[ $(id -u) -ne 0 ]]; then
  chmod 000 secret.env
  refuse "lock fails on an unreadable file" "secret.env" "$GIT_AGE" lock
  chmod 644 secret.env
  check "the readable file was not locked either" not is_locked config/credentials.yaml
  check "no temporary files are left" no_leftovers
else
  echo "  skip  unreadable files (running as root)"
fi

"$GIT_AGE" lock >/dev/null
age -r "$carol" -o secret.env.carol <<<'API_TOKEN=s3cr3t'
mv secret.env.carol secret.env
refuse "unlock fails on a file it cannot decrypt" "secret.env" "$GIT_AGE" unlock
check "the decryptable file was not unlocked either" is_locked config/credentials.yaml
check "no temporary files are left" no_leftovers
echo 'API_TOKEN=s3cr3t' >secret.env
"$GIT_AGE" unlock >/dev/null

section "lock / unlock keep file metadata"

# Each platform keeps metadata its own way: Linux copies extended
# attributes, POSIX ACLs included; macOS calls copyfile(3); Windows lets
# ReplaceFileW carry the ACL and streams over and restores the attributes.
if [[ $platform == linux ]] && command -v setfacl >/dev/null &&
  setfacl -m u:65534:r secret.env 2>/dev/null &&
  python3 -c 'import os; os.setxattr("secret.env", "user.git-age-test", b"kept")' 2>/dev/null; then
  has_acl() { getfacl -cn "$2" 2>/dev/null | grep -q "^$1"; }
  xattr_is() {
    [[ $(python3 -c 'import os, sys; print(os.getxattr(sys.argv[1], sys.argv[2]).decode())' \
      "$2" "$1" 2>/dev/null) == "$3" ]]
  }
  keeps_metadata() {
    check "$1 keeps the mode" mode_is secret.env 640
    check "$1 keeps the ACL" has_acl user:65534:r-- secret.env
    check "$1 keeps the extended attribute" xattr_is user.git-age-test secret.env kept
    check "$1 adds no default ACL to a file without it" \
      not has_acl user:65534: config/credentials.yaml
  }
  chmod 640 secret.env
  # New files in config/ would get this ACL; credentials.yaml has none.
  setfacl -d -m u:65534:rw config
  check "lock" "$GIT_AGE" lock
  keeps_metadata "lock"
  check "unlock" "$GIT_AGE" unlock
  keeps_metadata "unlock"
  check "no temporary files are left" no_leftovers
  setfacl -b secret.env
  setfacl -k config
  chmod 644 secret.env
  python3 -c 'import os; os.removexattr("secret.env", "user.git-age-test")'
elif [[ $platform == macos ]]; then
  has_acl() { ls -le "$2" | grep -F "$1" >/dev/null; }
  xattr_is() { [[ $(xattr -p "$1" "$2" 2>/dev/null) == "$3" ]]; }
  keeps_metadata() {
    check "$1 keeps the mode" mode_is secret.env 640
    check "$1 keeps the ACL" has_acl "group:everyone allow read" secret.env
    check "$1 keeps the extended attribute" xattr_is user.git-age-test secret.env kept
    check "$1 adds no inherited ACL to a file without it" \
      not has_acl "group:everyone" config/credentials.yaml
  }
  chmod 640 secret.env
  chmod +a "everyone allow read" secret.env
  xattr -w user.git-age-test kept secret.env
  # New files and directories in config/ would get this ACL; credentials.yaml has none.
  chmod +a "everyone allow write,file_inherit,directory_inherit" config
  check "lock" "$GIT_AGE" lock
  keeps_metadata "lock"
  check "unlock" "$GIT_AGE" unlock
  keeps_metadata "unlock"
  check "no temporary files are left" no_leftovers
  chmod -N secret.env config
  chmod 644 secret.env
  xattr -d user.git-age-test secret.env
elif [[ $platform == windows ]]; then
  # Keep MSYS from turning icacls's /switches into paths.
  icacls() { MSYS2_ARG_CONV_EXCL='*' command icacls "$@"; }
  has_ace() { icacls "$2" | grep -F "$1" >/dev/null; }
  read_only_and_hidden() {
    python3 -c 'import os, stat, sys
wanted = stat.FILE_ATTRIBUTE_READONLY | stat.FILE_ATTRIBUTE_HIDDEN
sys.exit(os.stat(sys.argv[1]).st_file_attributes & wanted != wanted)' "$1"
  }
  stream_is() {
    [[ $(python3 -c 'import sys; print(open(sys.argv[1]).read())' "$1:$2" 2>/dev/null) == "$3" ]]
  }
  keeps_metadata() {
    check "$1 keeps the read-only and hidden attributes" read_only_and_hidden secret.env
    check "$1 keeps the ACL" has_ace "Everyone:(R)" secret.env
    check "$1 keeps the alternate data stream" stream_is secret.env git-age-test kept
  }
  icacls secret.env /grant '*S-1-1-0:(R)' >/dev/null
  python3 -c 'open("secret.env:git-age-test", "w").write("kept")'
  attrib +R +H secret.env
  check "lock" "$GIT_AGE" lock
  keeps_metadata "lock"
  check "unlock" "$GIT_AGE" unlock
  keeps_metadata "unlock"
  check "no temporary files are left" no_leftovers
  attrib -R -H secret.env
  icacls secret.env /remove '*S-1-1-0' >/dev/null
  python3 -c 'import os; os.remove("secret.env:git-age-test")'
else
  printf '  skip  no ACL or extended attribute support here\n'
fi

section "hooks (always-lock)"

check "install --mode=always-lock" "$GIT_AGE" install --mode=always-lock
git add -A
check "commit with staged plaintext succeeds" commit "initial secrets"
check "HEAD stores secret.env encrypted" head_is_locked secret.env
check "HEAD stores credentials encrypted" head_is_locked config/credentials.yaml
check "bob can decrypt HEAD" head_decrypts_as bob config/credentials.yaml 'password: hunter2'

section "idempotent encryption"

check "unlock" "$GIT_AGE" unlock
check "lock again" "$GIT_AGE" lock
check "unchanged files produce identical ciphertext (clean tree)" clean_tree

section "clean filter"

"$GIT_AGE" unlock >/dev/null
check "unlocked, unchanged files are not modified (clean filter)" clean_tree
check "git diff shows nothing for them" git diff --quiet
git add -A
check "git add keeps the ciphertext staged" \
  bash -c 'git show :secret.env | head -c 21 | grep -q "^age-encryption.org/v1"'
echo 'API_TOKEN=edited' >secret.env
check "an edited file is modified" bash -c 'git status --porcelain | grep -qx " M secret.env"'
echo 'API_TOKEN=s3cr3t' >secret.env
check "reverting the edit makes it unmodified again" clean_tree
# Make Git compare by content again, as it would once the file changes.
forget_stat() { git ls-files -s "$@" | git update-index --index-info; }
forget_stat secret.env
check "without an identity it shows as modified" \
  bash -c 'git -c age.keyFile= status --porcelain | grep -qx " M secret.env"'
"$GIT_AGE" install --mode=always-lock --no-filter >/dev/null
check "install --no-filter removes the filter" not git config filter.age.clean
check "and no longer requires it" \
  bash -c '! git config filter.age.required && ! git config filter.age.smudge'
forget_stat secret.env
check "without the filter it shows as modified" \
  bash -c 'git status --porcelain | grep -qx " M secret.env"'
"$GIT_AGE" install --mode=always-lock >/dev/null
"$GIT_AGE" lock >/dev/null
check "locking again leaves a clean tree" clean_tree

section "editing a secret"

"$GIT_AGE" unlock
echo 'API_TOKEN=rotated' >secret.env
git add secret.env
check "commit an edited secret" commit "rotate token"
check "HEAD has the new value, encrypted" head_decrypts_as alice secret.env 'API_TOKEN=rotated'
check "git show diffs the plaintext (diff driver)" \
  bash -c 'git show HEAD -- secret.env | grep -qx "+API_TOKEN=rotated"'

section "adding a recipient (carol) with rekey"

"$GIT_AGE" lock >/dev/null
printf '# Carol\n%s\n' "$carol" >>.gitage
warns "status flags files encrypted to the previous list" "previous [recipients] list" "$GIT_AGE" status
check "status --porcelain flags them as LS" \
  bash -c '"$0" status --porcelain 2>&1 | grep -qx "LS secret.env"' "$GIT_AGE"
check "rekey re-encrypts to the new list" "$GIT_AGE" rekey
git add -A
check "commit the recipient change" commit "add carol"
check "carol can decrypt HEAD" head_decrypts_as carol secret.env 'API_TOKEN=rotated'
check "nothing stale after rekey" bash -c '! "$0" status 2>&1 | grep -q "previous"' "$GIT_AGE"

# --- error cases -----------------------------------------------------------------

section "errors: hook policies"

"$GIT_AGE" unlock
echo 'API_TOKEN=leak' >secret.env
git add secret.env
refuse "abort mode refuses staged plaintext" "commit aborted" \
  env GIT_AGE_HOOK_MODE=abort git commit -q -m "plaintext"
git restore --staged secret.env
git checkout -q -- secret.env 2>/dev/null || true
"$GIT_AGE" lock >/dev/null

section "errors: recipient change without rekey"

sed_i '/# Carol/{N;d;}' .gitage
git add .gitage
refuse "hook refuses [recipients] change with stale ciphertext" \
  "still encrypted to the previous list" git commit -q -m "remove carol"
git restore --staged .gitage
git checkout -q -- .gitage

section "errors: private keys"

"$GIT_AGE" keygen >/dev/null 2>&1
check "keygen excludes .gitage.key from git add -A" \
  bash -c 'git add -A && ! git diff --cached --name-only | grep -qx .gitage.key'
git add -f .gitage.key
refuse "hook refuses a staged .gitage.key" "refusing to commit private age keys" \
  git commit -q -m "oops"
cp "$tmp/keys/bob" leaked-key.txt
git add -f leaked-key.txt
refuse "hook refuses an unprotected file containing a key" "leaked-key.txt" \
  git commit -q -m "oops"
git restore --staged .gitage.key leaked-key.txt
rm -f .gitage.key leaked-key.txt

section "errors: invalid .gitage"

cp .gitage "$tmp/gitage.good"
printf 'secret.env\n' >.gitage
refuse "entry outside a section" "outside a section" "$GIT_AGE" status
printf '[files]\nsecret.env\n[nope]\n' >.gitage
refuse "unknown section" "unknown section [nope]" "$GIT_AGE" status
printf '[files]\nsecret.env\n[recipients]\nnot-a-key\n' >.gitage
refuse "invalid recipient" "is not an age recipient" "$GIT_AGE" status
cp "$tmp/gitage.good" .gitage

section "errors: identities"

refuse "unlock without any identity" "no identity configured" \
  git -c age.keyFile= age unlock
age -r "$alice" -o "$tmp/keys/protected.age" "$tmp/keys/alice"
refuse "passphrase-protected (encrypted) identity" "encrypted (passphrase-protected) age identity" \
  "$GIT_AGE" unlock -i "$tmp/keys/protected.age"
"$GIT_AGE" unlock >/dev/null
sed_i '/# Carol/{N;d;}' .gitage
warns "lock warns when your identity is not a recipient" "is not among the recipients" \
  "$GIT_AGE" lock -i "$tmp/keys/carol"
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
check "lock -C sub locks only files below sub" "$GIT_AGE" -C sub lock
check "files outside sub stay unlocked" \
  status_is -- 'L. sub/deep/y.env' 'L. sub/x.env' 'U. top.env'
check "-C sub encrypts to the top-level [recipients]" decrypts_as alice sub/x.env x
"$GIT_AGE" unlock >/dev/null

git config --unset age.keyFile
check "keygen in a subdirectory writes the key at the root" \
  bash -c 'cd sub && "$0" keygen >/dev/null 2>&1 && [[ -f ../.gitage.key && ! -e .gitage.key ]]' "$GIT_AGE"
check "and excludes it from git add -A" git check-ignore -q .gitage.key
cp "$tmp/keys/alice" .gitage.key
check "lock in a subdirectory uses the root .gitage.key" bash -c 'cd sub && "$0" lock' "$GIT_AGE"
check "it encrypts the files below it" decrypts_as alice sub/x.env x
check "status in a subdirectory sees them locked" \
  bash -c 'cd sub && [[ $("$0" status --porcelain) == $'"'"'L. deep/y.env\nL. x.env'"'"' ]]' "$GIT_AGE"
check "unlock -C sub uses the root .gitage.key" "$GIT_AGE" -C sub unlock
check "they are plaintext again" grep -qx x sub/x.env
rm .gitage.key
git config age.keyFile "$tmp/keys/alice"

section "outside a Git repository"

plain=$tmp/plain
mkdir -p "$plain"
echo s >"$plain/a.env"
printf '[files]\n*.env\n' >"$plain/.gitage"
check "lock without Git or recipients encrypts to your identity" \
  "$GIT_AGE" -C "$plain" lock -i "$tmp/keys/alice"
check "alice can decrypt it" decrypts_as alice "$plain/a.env" s
check "unlock without Git" "$GIT_AGE" -C "$plain" unlock -i "$tmp/keys/alice"
check "it is plaintext again" grep -qx s "$plain/a.env"

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
  echo "  skip  symbolic links are unavailable here"
fi
cd "$repo3"

section "dry runs"

check "lock -n reports what it would do" \
  bash -c '"$0" -n lock | grep -qx "would lock: top.env"' "$GIT_AGE"
check "rekey -n reports what it would do" \
  bash -c '"$0" -n rekey | grep -qx "would rekey: top.env"' "$GIT_AGE"
check "install -n reports what it would do" \
  bash -c '"$0" -n install --mode=abort | grep -q "would install git-age pre-commit hook"' "$GIT_AGE"
check "dry runs change no files" status_is -- 'U. sub/deep/y.env' 'U. sub/x.env' 'U. top.env'
check "dry runs install no hooks" not test -e .git/hooks/pre-commit
check "dry runs set no git config" not git config age.hookMode

section "recipient sources"

check "lock -r overrides [recipients]" "$GIT_AGE" lock -r "$bob"
check "bob can decrypt" decrypts_as bob top.env top
check "alice cannot" not decrypts_as alice top.env top
"$GIT_AGE" unlock -i "$tmp/keys/bob" >/dev/null
check "GIT_AGE_RECIPIENT overrides [recipients]" env GIT_AGE_RECIPIENT="$carol" "$GIT_AGE" lock
check "carol can decrypt" decrypts_as carol top.env top
"$GIT_AGE" unlock -i "$tmp/keys/carol" >/dev/null

section "hooks: unlock after commit, empty commits"

"$GIT_AGE" install --mode=always-lock --unlock-after-commit >/dev/null
git add -A
check "commit with unlock after commit" commit "secrets"
check "HEAD stores the files encrypted" head_decrypts_as alice top.env top
check "the working tree is unlocked after the commit" \
  status_is -- 'U. sub/deep/y.env' 'U. sub/x.env' 'U. top.env'
# The clean filter would stage the reused ciphertext; stage the plaintext.
git -c filter.age.clean=cat add -A
refuse "a commit that encryption makes empty is refused" \
  "encrypt to the ciphertext already in HEAD" git commit -q -m "empty"
"$GIT_AGE" unlock >/dev/null
git -c filter.age.clean=cat add -A
check "GIT_AGE_ALLOW_EMPTY=1 allows it" \
  env GIT_AGE_ALLOW_EMPTY=1 git commit -q --amend --no-edit
git config age.unlockAfterCommit false
"$GIT_AGE" lock >/dev/null

section "hooks without a .gitage"

git config age.unlockAfterCommit true
git switch -q --orphan no-gitage
echo plain >plain.txt
git add plain.txt
check "a commit without a staged .gitage succeeds, silently" \
  bash -c '[[ -z $(git commit -q -m "no rules" </dev/null 2>&1) ]]'
check "the post-commit hook is silent without a .gitage" \
  bash -c '[[ -z $(git commit -q --allow-empty -m "again" </dev/null 2>&1) ]]'
echo "AGE-SECRET-KEY-1 is the marker" >notes.txt
git add notes.txt
check "without rules, mentioning the key marker is allowed" commit "notes"
"$GIT_AGE" keygen >/dev/null 2>&1
git add -f .gitage.key
refuse "a staged .gitage.key is still refused" "refusing to commit private age keys" \
  git commit -q -m "oops"
git restore --staged .gitage.key
rm -f .gitage.key
refuse "explicit commands still need a .gitage" "no .gitage files staged" \
  "$GIT_AGE" check --cached
git switch -q main
git branch -q -D no-gitage
git config age.unlockAfterCommit false

section "hooks: removing a .gitage"

git switch -q -c drop-rules
git rm -q .gitage
refuse "a commit removing .gitage is refused" "refusing to commit the removal of .gitage" \
  git commit -q -m "drop rules"
refuse "check --cached refuses it too" "git restore --staged --worktree -- .gitage" \
  "$GIT_AGE" check --cached
git restore --staged --worktree -- .gitage
check "the suggested restore brings it back" clean_tree
rm .gitage
refuse "so is git commit -a after deleting it" "GIT_AGE_ALLOW_REMOVE=1" \
  git commit -q -a -m "drop rules"
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
  bash -c 'git -c age.keyFile= show --textconv HEAD:top.env | grep -q "git-age: encrypted, no identity configured"'

section "hooks: interactive"

"$GIT_AGE" install --mode=interactive >/dev/null
"$GIT_AGE" unlock >/dev/null
echo changed >top.env
git add -A
refuse "without a terminal the commit is aborted" "interactive confirmation is unavailable" \
  without_terminal git commit -q -m "no terminal"
if has_terminal; then
  refuse "answering a aborts the commit" "commit aborted" answer 'a\n' "aborted"
  check "answering e encrypts and commits" answer 'e\n' "encrypted"
  check "HEAD stores the edit encrypted" head_decrypts_as alice top.env changed
  echo plain >top.env
  git add top.env
  refuse "c without typing commit aborts" "not confirmed" answer 'c\nno\n' "plaintext"
  check "c, then commit, commits plaintext" answer 'c\ncommit\n' "plaintext"
  check "HEAD stores it as plaintext" bash -c '[[ $(git show HEAD:top.env) == plain ]]'
else
  echo "  skip  interactive prompts (no terminal on Windows)"
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
as() { local who=$1; shift; GIT_AGE_KEY_FILE=$tmp/keys/$who "$GIT_AGE" "$@"; }

check "lock" "$GIT_AGE" lock
check "carol can decrypt prod/db.env" decrypts_as carol prod/db.env db
check "alice can decrypt prod/db.env" decrypts_as alice prod/db.env db
check "carol cannot decrypt app.env" not decrypts_as carol app.env app
check "status -v names the nested list" \
  bash -c '"$0" -v status | grep -q "encrypted to .* + prod/.gitage \[recipients\]"' "$GIT_AGE"
git add -A
commit "scoped secrets"

check "status marks what carol cannot read" \
  bash -c 'GIT_AGE_KEY_FILE=$0 "$1" status | grep -q "^LOCKED *app.env (no access)"' "$tmp/keys/carol" "$GIT_AGE"
check "porcelain status flags it N" \
  bash -c '[[ $(GIT_AGE_KEY_FILE=$0 "$1" status --porcelain) == $'"'"'LN app.env\nL. prod/db.env'"'"' ]]' \
  "$tmp/keys/carol" "$GIT_AGE"
warns "unlock as carol skips what is not hers" "1 file(s) locked that are not encrypted to you" \
  as carol unlock
check "prod/db.env is plaintext" grep -qx db prod/db.env
check "app.env is still locked" is_locked app.env
check "carol relocks to the same ciphertext (reuse)" bash -c 'GIT_AGE_KEY_FILE=$0 "$1" lock && [[ -z $(git status --porcelain) ]]' "$tmp/keys/carol" "$GIT_AGE"

printf '# Dave\n%s\n' "$dave" >>prod/.gitage
check "a nested change makes only its files stale" \
  bash -c '[[ $("$0" status --porcelain) == $'"'"'L. app.env\nLS prod/db.env'"'"' ]]' "$GIT_AGE"
warns "dave is told prod/db.env is not re-encrypted to him yet" "not re-encrypted to you yet" \
  as dave unlock
check "prod/db.env is still locked" is_locked prod/db.env
"$GIT_AGE" install --mode=always-lock >/dev/null
git add prod/.gitage
refuse "the hook refuses the nested change before rekey" "prod/db.env" git commit -q -m "add dave"
warns "carol rekeys what she can and names the rest" "app.env" as carol rekey
check "dave can decrypt prod/db.env now" decrypts_as dave prod/db.env db
check "app.env was left alone" bash -c '[[ -z $(git status --porcelain app.env) ]]'
git add -A
check "the commit goes through after rekey" commit "add dave"
check "only one file was re-encrypted" bash -c '[[ $(git diff --name-only HEAD^ HEAD -- "*.env") == prod/db.env ]]'
age -r "$alice" -o prod/db.env <<<'tampered'
refuse "a file meant for dave that fails to decrypt still stops unlock" "cannot decrypt" as dave unlock
git checkout -q -- prod/db.env

section "recipient trust"

# Mallory, who can push, adds keys behind everyone's back; bob's key stands in for hers.
mallory_commit() {
  git -c user.name=Mallory -c user.email=mallory@example.invalid commit -q --no-verify -m "$1"
}

"$GIT_AGE" unlock >/dev/null
printf '# Mallory\n%s\n' "$bob" >>prod/.gitage
git add prod/.gitage
mallory_commit "add a key"
warns "without a pin, lock warns about someone else's change" \
  "Mallory <mallory@example.invalid>" "$GIT_AGE" lock

"$GIT_AGE" unlock >/dev/null
check "trust pins the current lists" "$GIT_AGE" trust
check "trust --show prints the pinned hash" \
  bash -c '[[ $("$0" trust --show) == $(git config age.trustedRecipients) ]]' "$GIT_AGE"
check "with the lists pinned, lock does not warn" \
  bash -c '! "$0" lock 2>&1 | grep -q "someone else"' "$GIT_AGE"

"$GIT_AGE" unlock >/dev/null
printf '%s\n' "$dave" >>.gitage
git add .gitage
mallory_commit "widen access"
refuse "lock refuses lists that differ from the pin" "untrusted [recipients]" "$GIT_AGE" lock
check "the refusal shows the new key and who added it" \
  bash -c 'out=$("$0" lock 2>&1); grep -q "+ $1" <<<"$out" && grep -q "Mallory" <<<"$out"' \
  "$GIT_AGE" "$dave"
check "nothing was locked" not is_locked prod/db.env
warns "status says the lists differ" "differ from the ones you trusted" "$GIT_AGE" status
check "trust shows the change it accepts" \
  bash -c '"$0" trust | grep -q "+ $1"' "$GIT_AGE" "$dave"
check "lock works once the change is trusted" "$GIT_AGE" lock

"$GIT_AGE" unlock >/dev/null
sed_i '$d' .gitage
refuse "your own uncommitted edits need trust too" "(uncommitted changes)" "$GIT_AGE" lock
echo db2 >prod/db.env
git add -A
refuse "the pre-commit hook refuses to encrypt to untrusted lists" "untrusted" \
  git commit -q -m "edit"
git reset -q
git checkout -q -- .gitage prod/db.env
"$GIT_AGE" lock >/dev/null 2>&1

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
"$GIT_AGE" lock >/dev/null
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
"$GIT_AGE" unlock >/dev/null
warns "a [recipients] change made in a merge counts" "merge theirs" "$GIT_AGE" lock
git reset -q --hard HEAD~1
git -c user.name=Mallory -c user.email=mallory@example.invalid merge -q --no-edit -X theirs theirs \
  >/dev/null 2>&1
"$GIT_AGE" unlock >/dev/null
check "a merge that takes one side's lists does not" \
  bash -c '! "$0" lock 2>&1 | grep -q "someone else"' "$GIT_AGE"
cd "$repo"

section "partial access without a base list"

repo5=$tmp/repo-nobase
mkdir -p "$repo5/prod"
cd "$repo5"
git init -q
echo app >app.env
echo db >prod/db.env
printf '[files]\n*.env\n' >.gitage
printf '[recipients]\n%s\n' "$carol" >prod/.gitage

check "alice locks to her identity, plus carol under prod/" as alice lock
check "carol can decrypt prod/db.env" decrypts_as carol prod/db.env db
check "alice can decrypt app.env" decrypts_as alice app.env app
warns "carol's unlock leaves app.env alone" "not encrypted to you" as carol unlock
check "app.env stays locked" is_locked app.env
check "status marks it for carol" \
  bash -c '[[ $(GIT_AGE_KEY_FILE=$0 "$1" status --porcelain) == $'"'"'LN app.env\nU. prod/db.env'"'"' ]]' \
  "$tmp/keys/carol" "$GIT_AGE"
refuse "someone listed nowhere still gets an error" "cannot decrypt" as dave unlock

section "merge driver"

repo6=$tmp/repo-merge
mkdir -p "$repo6"
cd "$repo6"
git init -q
git config age.keyFile "$tmp/keys/alice"
printf '[files]\n*.env\n\n[recipients]\n%s\n%s\n' "$alice" "$bob" >.gitage
printf 'A=1\nB=1\nC=1\n' >app.env
"$GIT_AGE" install --mode=always-lock >/dev/null
check "install sets the merge driver" git config merge.age.driver
check "the attributes use it" bash -c 'git check-attr merge app.env | grep -q "merge: age"'
check "install requires the clean filter" bash -c '[[ $(git config filter.age.required) == true ]]'
git add -A
commit "base"
"$GIT_AGE" lock >/dev/null
staged_is_locked() { git show ":$1" | head -c 21 | grep -q '^age-encryption.org/v1'; }
# edit BRANCH CONTENT MESSAGE: commit an encrypted edit of app.env on BRANCH.
edit() {
  git checkout -q "$1"
  printf "$2" >app.env
  git add app.env
  commit "$3" 2>/dev/null
  "$GIT_AGE" lock >/dev/null
}

git branch side
edit side 'A=2\nB=1\nC=1\n' "side: A"
edit main 'A=1\nB=1\nC=2\n' "main: C"
check "changes to different lines merge cleanly" git merge -q --no-edit side
check "the merge result is encrypted" head_is_locked app.env
check "it holds both changes" head_decrypts_as bob app.env $'A=2\nB=1\nC=2'
check "the working tree is clean" clean_tree

git branch side2
edit side2 'A=3\nB=1\nC=2\n' "side2: A"
edit main 'A=3\nB=1\nC=2\n' "main: A too"
check "the same change on both sides merges cleanly" git merge -q --no-edit side2
check "it reuses one side's ciphertext" \
  bash -c '[[ $(git rev-parse HEAD:app.env) == $(git rev-parse HEAD^1:app.env) || $(git rev-parse HEAD:app.env) == $(git rev-parse HEAD^2:app.env) ]]'

git branch side3
edit side3 'A=3\nB=side\nC=2\n' "side3: B"
edit main 'A=3\nB=main\nC=2\n' "main: B"
refuse "a conflicting change conflicts" "is now UNLOCKED" git merge -q --no-edit side3
check "the file has plaintext conflict markers" \
  bash -c 'grep -qx "<<<<<<< ours" app.env && grep -qx "B=side" app.env'
printf 'A=3\nB=both\nC=2\n' >app.env
git add app.env
check "git add encrypts the resolution" staged_is_locked app.env
check "the merge commits" commit "merge side3"
check "HEAD holds the resolution" head_decrypts_as bob app.env $'A=3\nB=both\nC=2'

git branch side4
edit side4 'A=3\nB=side4\nC=2\n' "side4: B"
edit main 'A=3\nB=main4\nC=2\n' "main: B again"
git checkout -q side4
refuse "a rebase conflicts the same way" "is now UNLOCKED" git rebase -q main
printf 'A=3\nB=rebased\nC=2\n' >app.env
git add app.env
check "rebase --continue, which skips pre-commit, commits it" \
  env GIT_EDITOR=true git rebase --continue
check "the rebased commit is encrypted" head_decrypts_as alice app.env $'A=3\nB=rebased\nC=2'

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
check "the path stays unmerged" bash -c '[[ -n $(git ls-files -u app.env) ]]'
check "git status still works" git status --porcelain
refuse "rebase --continue cannot commit the plaintext" "app.env" \
  env GIT_EDITOR=true git rebase --continue
git config --unset age.trustedRecipients
git add app.env
check "once fixed, rebase --continue commits it" env GIT_EDITOR=true git rebase --continue
check "the rebased commit is encrypted" head_decrypts_as alice app.env $'A=3\nB=untrusted\nC=2'

git checkout -q main
git branch side5
edit side5 'A=5\nB=main4\nC=2\n' "side5: A"
edit main 'A=3\nB=main4\nC=5\n' "main: C again"
ours=$(git rev-parse HEAD:app.env)
refuse "without a key the merge conflicts" "keeping our version" \
  git -c age.keyFile= merge -q --no-edit side5
check "and keeps our ciphertext" bash -c '[[ $(git hash-object app.env) == "$0" ]]' "$ours"
git merge --abort

"$GIT_AGE" install --mode=always-lock --no-merge >/dev/null
check "install --no-merge removes the merge driver" not git config merge.age.driver

section "status is read-only"

attributes=$(git rev-parse --git-path info/attributes)
cp .gitage "$tmp/gitage.saved"
sed_i '/^\[files\]$/a\
*.secret
' .gitage
before_attributes=$(cat "$attributes")
check "status after a .gitage change" "$GIT_AGE" status
check "leaves info/attributes alone" \
  bash -c '[[ $(cat "$0") == "$1" ]]' "$attributes" "$before_attributes"
check "lock refreshes it" bash -c '"$0" lock && grep -qF "*.secret" "$1"' "$GIT_AGE" "$attributes"
cp "$tmp/gitage.saved" .gitage
check "and again once .gitage is back" "$GIT_AGE" lock

section "install without Git attributes"

hooks=$(git rev-parse --git-path hooks)
check "the sync hooks are installed" \
  bash -c '[[ -x $0/post-checkout && -x $0/post-merge && -x $0/post-rewrite ]]' "$hooks"
check "--dry-run says it would remove them" \
  bash -c '"$0" -n install --no-diff --no-merge --no-filter | grep -q "would remove git-age post-checkout hook"' \
  "$GIT_AGE"
check "install --no-diff --no-merge --no-filter" \
  "$GIT_AGE" install --mode=always-lock --no-diff --no-merge --no-filter
check "it removes post-checkout and post-rewrite" \
  bash -c '[[ ! -e $0/post-checkout && ! -e $0/post-rewrite ]]' "$hooks"
check "it keeps post-merge, which warns about [recipients] changes" test -x "$hooks/post-merge"
printf '#!/bin/sh\nexit 0\n' >"$hooks/post-checkout"
check "it leaves a hook it does not own alone" \
  bash -c '"$0" install --mode=always-lock --no-diff --no-merge --no-filter && [[ -e $1 ]]' \
  "$GIT_AGE" "$hooks/post-checkout"
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
"$GIT_AGE" lock >/dev/null
git add -A && commit "add .gitage"
git checkout -q -b side
echo 'TOKEN=side' >side.env
git add side.env && commit "side: plaintext"
"$GIT_AGE" lock >/dev/null
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
audit_out=$("$GIT_AGE" audit 2>&1) || audit_status=$?
check "audit fails when it finds plaintext" test "$audit_status" -eq 1
check "a file committed before its pattern was added counts" grep -qx '  early.env' <<<"$audit_out"
check "a branch's plaintext counts" grep -qx '  side.env' <<<"$audit_out"
check "a file the rules protected then counts" grep -qx '  old.txt' <<<"$audit_out"
check "ciphertext does not count" not grep -q 'locked.env' <<<"$audit_out"
check "unprotected files do not count" not grep -q 'readme' <<<"$audit_out"
check "audit REV searches only that history" \
  bash -c '! "$0" audit main~1 2>&1 | grep -q side.env' "$GIT_AGE"
mkdir -p sub
check "-C subdir audits the whole repository" \
  bash -c '"$0" -C sub audit 2>&1 | grep -qx "  early.env"' "$GIT_AGE"

section "audit --rekey re-encrypts history"

printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
git commit -q -am "drop bob" </dev/null
before=$(git rev-parse HEAD)
refuse "without a terminal it asks for --yes" "pass --yes" "$GIT_AGE" audit --rekey
echo dirty >>readme
refuse "a dirty working tree is refused" "uncommitted changes" "$GIT_AGE" audit --rekey --yes
git checkout -q readme
refuse "it takes no revisions" "takes no revisions" "$GIT_AGE" audit --rekey --yes main
check "--dry-run rewrites nothing" \
  bash -c '"$0" -n audit --rekey | grep -q "would rewrite" && [[ $(git rev-parse HEAD) == "$1" ]]' "$GIT_AGE" "$before"

refuse "what it cannot decrypt stops it" "cannot decrypt" \
  env GIT_AGE_KEY_FILE="$tmp/keys/carol" GIT_AGE_RECIPIENT="$carol" "$GIT_AGE" audit --rekey --yes
check "and nothing moved" test "$(git rev-parse HEAD)" = "$before"

warns "audit --rekey --yes rewrites" "git-age audit -- --branches --tags" \
  "$GIT_AGE" audit --rekey --yes
check "the old refs are kept" test "$(git rev-parse refs/git-age/original/refs/heads/main)" = "$before"
check "the branch moved" test "$(git rev-parse HEAD)" != "$before"
check "audit now finds nothing" "$GIT_AGE" audit
git update-ref refs/remotes/origin/main "$before"
refuse "remote-tracking refs keep the old history" "early.env" "$GIT_AGE" audit
check "audit -- --branches --tags leaves them out" "$GIT_AGE" audit -- --branches --tags
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
check "alice can read every version" every_version alice can
check "bob, removed, can read none" every_version bob cannot
check "a file no longer protected stays as it was" \
  bash -c 'git show "HEAD~2:old.txt" | grep -qx "was protected"'
check "the tag points into the new history" git merge-base --is-ancestor "v1^{commit}" HEAD
check "so does a tag of that tag" \
  bash -c '[[ $(git cat-file -p v1-nested | sed -n "1s/^object //p") == $(git rev-parse v1) ]] &&
    git merge-base --is-ancestor "v1-nested^{commit}" HEAD'
check "every branch was rewritten" git merge-base --is-ancestor side-head HEAD
check "the working tree is clean" clean_tree
refuse "a second rewrite wants the backup gone" "previous rewrite" "$GIT_AGE" audit --rekey --yes

section "audit finds committed private keys"

keyleak=$tmp/keyleak
mkdir -p "$keyleak"
cd "$keyleak"
git init -q
git config age.keyFile "$tmp/keys/alice"
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage
echo 'hello' >readme
git add . && commit "init"
check "audit passes without leaks" "$GIT_AGE" audit
cp "$tmp/keys/alice" k.txt
git add k.txt && git commit -q --no-verify -m "key as k.txt" </dev/null
key_status=0
key_out=$("$GIT_AGE" audit 2>&1) || key_status=$?
check "a key committed as k.txt fails audit" test "$key_status" -eq 1
check "it is listed as a private key" grep -qx 'Private age keys committed to Git history:' <<<"$key_out"
check "with its path" grep -qx '  k.txt' <<<"$key_out"
check "and the commit that added it" grep -q 'in [0-9a-f]\{12\}  key as k.txt$' <<<"$key_out"
check "it says the key is compromised" grep -q 'compromised' <<<"$key_out"
check "and that --rekey does not purge it" grep -q 'git filter-repo' <<<"$key_out"
check "no plaintext group without plaintext" not grep -q 'committed as plaintext:' <<<"$key_out"
git rm -q k.txt && commit "remove k.txt"
echo 'not a key' >.gitage.key
git add -f .gitage.key && git commit -q --no-verify -m "a .gitage.key" </dev/null
echo 'TOKEN=plain' >app.env
git add app.env && git commit -q --no-verify -m "plaintext app.env" </dev/null
key_status=0
key_out=$("$GIT_AGE" audit 2>&1) || key_status=$?
check "a .gitage.key fails audit, whatever its content" test "$key_status" -eq 1
check "a removed key still counts" grep -qx '  k.txt' <<<"$key_out"
check ".gitage.key is listed" grep -qx '  .gitage.key' <<<"$key_out"
check "plaintext is listed in its own group" grep -qx 'Protected files committed as plaintext:' <<<"$key_out"
check "a plaintext secret is not a key" \
  bash -c '! sed -n "/^Private/,/^Protected/p" <<<"$0" | grep -q app.env' "$key_out"
check "unprotected files without keys do not count" not grep -q 'readme' <<<"$key_out"
echo 'not a key either' >.gitage.key
git add -f .gitage.key && git commit -q --no-verify -m "change .gitage.key" </dev/null
check "audit lists one version by default" \
  bash -c '"$0" audit 2>&1 | grep -q "and 1 more version(s); -v lists them"' "$GIT_AGE"
check "audit -v lists every version" \
  bash -c '[[ $("$0" -v audit 2>&1 | grep -c "in [0-9a-f]\{12\}  .*gitage.key") -eq 2 ]]' "$GIT_AGE"
git rm -q --cached .gitage.key && rm .gitage.key && commit "remove .gitage.key"
warns "audit --rekey warns about committed keys" "private key file(s) are in Git history" \
  "$GIT_AGE" -n audit --rekey

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
"$GIT_AGE" install --mode=always-lock >/dev/null
hooks=$(git rev-parse --git-path hooks)
check "install installs the pre-push hook" test -x "$hooks/pre-push"
git add -A && commit "init"
git remote add origin "$push_remote"
check "a clean push succeeds" git push -q origin main
remote_main() { git --git-dir="$push_remote" rev-parse main; }
pushed=$(git rev-parse HEAD)

"$GIT_AGE" unlock >/dev/null
echo 'TOKEN=two' >app.env
git add app.env && git commit -q --no-verify -m "plaintext app.env" </dev/null
refuse "a plaintext commit made with --no-verify is refused" "push aborted" \
  git push -q origin main
check "the remote did not get it" test "$(remote_main)" = "$pushed"
refuse "the refusal names the file" "  app.env" git push -q origin main
refuse "and how to push anyway" "GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push" git push -q origin main
warns "GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 allows it" \
  "by explicit choice (GIT_AGE_ALLOW_PLAINTEXT_PUSH)" \
  env GIT_AGE_ALLOW_PLAINTEXT_PUSH=1 git push -q origin main
check "the remote got it" test "$(remote_main)" = "$(git rev-parse HEAD)"
"$GIT_AGE" lock >/dev/null
git add app.env && commit "encrypt app.env"
check "what the remote has is not audited again" git push -q origin main

git switch -q -c leak
"$GIT_AGE" unlock >/dev/null
echo 'TOKEN=three' >app.env
git add app.env && git commit -q --no-verify -m "plaintext again" </dev/null
refuse "a new branch is audited too" "push aborted" git push -q origin leak
check "git push --no-verify skips the hook" git push -q --no-verify origin leak
check "deleting a remote branch is not audited" git push -q origin :leak
git switch -q main
"$GIT_AGE" lock >/dev/null

git switch -q -c rebased
git switch -q -c side main
echo 'TOKEN=side' >app.env
git commit -q --no-verify -am "plaintext on side" </dev/null
git switch -q rebased
git cherry-pick side >/dev/null
refuse "a cherry-picked plaintext commit is refused" "push aborted" git push -q origin rebased
git switch -q main
git branch -q -D rebased side
"$GIT_AGE" lock >/dev/null

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
check "pushing a branch without a .gitage succeeds, silently" \
  bash -c '[[ -z $(git push -q origin no-rules 2>&1) ]]'
check "pushed commits with their own .gitage are still audited" \
  bash -c '! git push -q origin leak 2>/dev/null && [[ -z $(git ls-remote origin refs/heads/leak) ]]'
git switch -q main
"$GIT_AGE" lock >/dev/null
back=$PWD

section "path arguments"

repo7=$tmp/repo-paths
mkdir -p "$repo7/sub" "$repo7/docs"
cd "$repo7"
git init -q
git config age.keyFile "$tmp/keys/alice"
echo a >a.env
echo b >sub/b.env
echo c >sub/c.env
echo notes >notes.txt
echo doc >docs/readme.txt
printf '[files]\n*.env\n\n[recipients]\n%s\n' "$alice" >.gitage

check "lock FILE locks only that file" "$GIT_AGE" lock a.env
check "the others stay unlocked" status_is -- 'L. a.env' 'U. sub/b.env' 'U. sub/c.env'
check "lock DIR locks the files below it" "$GIT_AGE" lock sub
check "now all are locked" status_is -- 'L. a.env' 'L. sub/b.env' 'L. sub/c.env'
check "unlock FILE unlocks only that file" "$GIT_AGE" unlock sub/b.env
check "the others stay locked" status_is -- 'L. a.env' 'U. sub/b.env' 'L. sub/c.env'
check "status PATH lists only the files under it" \
  bash -c '[[ $("$0" status --porcelain sub) == $'"'"'U. sub/b.env\nL. sub/c.env'"'"' ]]' "$GIT_AGE"
check "status takes several PATHs" \
  bash -c '[[ $("$0" status --porcelain sub/c.env a.env) == $'"'"'L. a.env\nL. sub/c.env'"'"' ]]' "$GIT_AGE"
check "PATHs are relative to -C" "$GIT_AGE" -C sub unlock c.env
check "so -C sub unlock c.env unlocks sub/c.env" \
  status_is -- 'L. a.env' 'U. sub/b.env' 'U. sub/c.env'
check "PATHs are relative to the current directory" \
  bash -c 'cd sub && "$0" lock ./b.env && [[ $("$0" status --porcelain) == $'"'"'L. b.env\nU. c.env'"'"' ]]' "$GIT_AGE"
check "rekey PATH rekeys only that file" \
  bash -c '[[ $("$0" -n rekey sub/c.env) == "would rekey: sub/c.env" ]]' "$GIT_AGE"
refuse "a PATH that .gitage does not protect is an error" "notes.txt: not protected by .gitage" \
  "$GIT_AGE" lock sub/c.env notes.txt
check "and nothing is locked, not even the matching PATH" \
  bash -c '! head -c 21 sub/c.env | grep -q "^age-encryption" && grep -qx notes notes.txt'
refuse "a missing PATH is an error" "nope.env: no such file or directory" "$GIT_AGE" unlock nope.env
refuse "a directory without protected files is an error" "docs: no file in it is protected" \
  "$GIT_AGE" status docs
refuse "a PATH outside -C is an error" "../a.env: outside" "$GIT_AGE" -C sub lock ../a.env
refuse "a PATH outside the repository is an error" "outside" "$GIT_AGE" lock "$tmp/keys/alice"
check "the refusals changed nothing" status_is -- 'L. a.env' 'L. sub/b.env' 'U. sub/c.env'

section "edit"

"$GIT_AGE" lock >/dev/null
git add -A && commit "secrets"
cat >"$tmp/append-editor" <<'EOF'
#!/bin/sh
python3 -c 'import os, sys
path = sys.argv[1]
print(oct(os.stat(os.path.dirname(path)).st_mode & 0o777)[2:], path.replace(os.sep, "/"))' "$1" \
  >"${0%/*}/edited-where"
printf 'NEW=1\n' >>"$1"
EOF
printf '#!/bin/sh\nprintf "NEW=1\\n" >>"$1"\nexit 1\n' >"$tmp/failing-editor"
chmod +x "$tmp/append-editor" "$tmp/failing-editor"
no_edit_leftovers() { [[ -z $(find .git . -name 'git-age-edit-*' -o -name '.*.git-age-*' | head -1) ]]; }

cp a.env "$tmp/a.env.before"
check "edit with an editor that changes nothing" env EDITOR=true "$GIT_AGE" edit a.env
check "leaves the file byte for byte as it was" cmp -s a.env "$tmp/a.env.before"
check "edit opens the editor and re-encrypts the change" \
  env EDITOR="$tmp/append-editor" "$GIT_AGE" edit a.env
check "the file is still locked" is_locked a.env
check "and decrypts to the edited content" decrypts_as alice a.env $'a\nNEW=1'
# git-age resolves macOS's /var symbolic link and Windows short names such
# as RUNNER~1, and gives the editor a Windows path there. Windows has no
# mode bits.
repo7_real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]).replace(os.sep, "/"))' "$repo7")
if [[ $platform == windows ]]; then
  edited_where="^[0-7]* $repo7_real"
else
  edited_where="^700 $repo7_real"
fi
check "the editor saw a private copy inside the Git directory" \
  grep -q "$edited_where/.git/git-age-edit-[^/]*/a.env\$" "$tmp/edited-where"
check "the decrypted copy is gone" no_edit_leftovers
check "edit -C sub FILE is relative to -C" \
  env EDITOR="perl -pi -e s/b/B/" "$GIT_AGE" -C sub edit b.env
check "it edited sub/b.env" decrypts_as alice sub/b.env B
check "editing it back reuses the committed ciphertext" \
  bash -c 'EDITOR="perl -pi -e s/B/b/" "$0" edit sub/b.env && git diff --quiet -- sub/b.env' "$GIT_AGE"
cp a.env "$tmp/a.env.before"
refuse "a failing editor is an error" "exit status 1; a.env was not changed" \
  env EDITOR="$tmp/failing-editor" "$GIT_AGE" edit a.env
check "and leaves the file as it was" cmp -s a.env "$tmp/a.env.before"
check "with no decrypted copy left" no_edit_leftovers
check "edit -n changes nothing" \
  bash -c '[[ $(EDITOR="$1" "$0" -n edit a.env) == "would edit: a.env" ]] && cmp -s a.env "$2"' \
  "$GIT_AGE" "$tmp/append-editor" "$tmp/a.env.before"
refuse "edit refuses a file .gitage does not protect" "notes.txt: not protected by .gitage" \
  env EDITOR="$tmp/append-editor" "$GIT_AGE" edit notes.txt
check "and does not touch it" grep -qx notes notes.txt
refuse "edit refuses a directory" "is a directory" env EDITOR=true "$GIT_AGE" edit sub
"$GIT_AGE" unlock sub/c.env >/dev/null
warns "edit opens an unlocked file in place" "sub/c.env is unlocked" \
  env EDITOR="$tmp/append-editor" "$GIT_AGE" edit sub/c.env
check "it stays plaintext, edited" bash -c '[[ $(cat sub/c.env) == $'"'"'c\nNEW=1'"'"' ]]'
cd "$back"

section "uninstall"

git rm -q .gitage
refuse "the .gitage removal refusal suggests uninstall" "git-age uninstall" \
  git commit -q -m "drop rules"
git restore --staged --worktree -- .gitage
attributes=$(git rev-parse --git-path info/attributes)
printf '#!/bin/sh\nexit 0\n' >"$hooks/post-rewrite"
chmod +x "$hooks/post-rewrite"
check "uninstall -n says what it would do" \
  bash -c '"$0" -n uninstall | grep -q "would remove git-age pre-push hook"' "$GIT_AGE"
check "and changes nothing" \
  bash -c '[[ -x $0/pre-commit && -x $0/pre-push ]] && git config filter.age.clean >/dev/null &&
    git config age.hookMode >/dev/null && grep -qF "# BEGIN git-age" "$1"' "$hooks" "$attributes"
warns "uninstall keeps a hook it did not install" "Kept post-rewrite hook" "$GIT_AGE" uninstall
check "it removes the git-age hooks" \
  bash -c 'for hook in pre-commit post-commit pre-push post-checkout post-merge; do
    [[ ! -e $0/$hook ]] || exit 1; done' "$hooks"
check "it keeps the other one" test -x "$hooks/post-rewrite"
check "it unsets the git config install set" \
  bash -c '! git config --local --get-regexp "^(diff|merge|filter)\.age\.|^age\.(hookmode|unlockaftercommit)$"'
check "it keeps age.keyFile" git config age.keyFile
check "it removes the attributes block" not grep -qF "# BEGIN git-age" "$attributes"
check "the protected file stays locked" is_locked app.env
check "a second uninstall has nothing to do" \
  bash -c '"$0" uninstall | grep -qx "git-age: nothing to uninstall"' "$GIT_AGE"
rm "$hooks/post-rewrite"
check "install works again" "$GIT_AGE" install --mode=always-lock
check "with its hooks, config and attributes" \
  bash -c '[[ -x $0/pre-commit && -x $0/pre-push ]] && git config filter.age.clean >/dev/null &&
    grep -qF "# BEGIN git-age" "$1"' "$hooks" "$attributes"

section "help"
check "help prints the whole manual" \
  bash -c 'out=$("$0" help) && grep -qx "QUICK START" <<<"$out" && grep -qx "SHELL COMPLETION" <<<"$out"' "$GIT_AGE"
check "help TOPIC prints just that section" \
  bash -c 'out=$("$0" help hooks) && [[ $(head -1 <<<"$out") == "GIT HOOKS" ]] && ! grep -qx "KEYS" <<<"$out"' "$GIT_AGE"
check "a word of a section's name finds it" \
  bash -c '[[ $("$0" help trust | head -1) == "RECIPIENT TRUST" ]]' "$GIT_AGE"
check "so does a unique prefix, in any case" \
  bash -c '[[ $("$0" help INTEG | head -1) == "GIT INTEGRATION" ]]' "$GIT_AGE"
check "help .gitage finds the .gitage section" \
  bash -c '[[ $("$0" help .gitage | head -1) == .GITAGE ]]' "$GIT_AGE"
check "help COMMAND prints the command's options" \
  bash -c '"$0" help lock | grep -q "^usage: git-age lock"' "$GIT_AGE"
refuse "an unknown topic lists the topics" "topics are: quick-start, everyday-use, commands" "$GIT_AGE" help nonsense
refuse "an ambiguous prefix is refused" "ambiguous help topic 'g'" "$GIT_AGE" help g
refuse "internal commands are not help topics" "unknown help topic 'textconv'" "$GIT_AGE" help textconv
check "--help points to the manual" bash -c '"$0" --help | grep -qF "git-age help"' "$GIT_AGE"
check "help needs no repository or key" "$GIT_AGE" -C "$tmp" help keys
pages_help() {
  GIT_PAGER="sed s/^/paged:/" on_terminal "$(printf %q "$GIT_AGE") help" </dev/null |
    tr -d "\r" | grep -x "paged:QUICK START" >/dev/null
}
if has_terminal; then
  check "on a terminal, the manual goes through Git's pager" pages_help
else
  echo "  skip  the pager (no terminal on Windows)"
fi
check "without a terminal, it is printed plainly" \
  bash -c 'GIT_PAGER="sed s/^/paged:/" "$0" help | grep -qx "QUICK START"' "$GIT_AGE"

section "shell completion"
for shell in bash zsh fish; do
  check "completion $shell mentions the commands" \
    bash -c 'out=$("$0" completion "$1") && for command in lock unlock rekey audit help completion; do
      grep -qw -- "$command" <<<"$out" || exit 1; done' "$GIT_AGE" "$shell"
done
refuse "an unknown shell is refused" "invalid choice: 'tcsh'" "$GIT_AGE" completion tcsh
check "the bash script parses" bash -c 'bash -n <("$0" completion bash)' "$GIT_AGE"
if command -v zsh >/dev/null; then
  check "the zsh script parses" bash -c '"$0" completion zsh | zsh -n' "$GIT_AGE"
  check "the zsh script defines _git-age, which git's completion calls" \
    bash -c '"$0" completion zsh | head -1 | grep -qx "#compdef git-age"' "$GIT_AGE"
else
  echo "  skip  zsh is not installed"
fi
if command -v fish >/dev/null; then
  check "the fish script parses" bash -c '"$0" completion fish | fish --no-config -n' "$GIT_AGE"
else
  echo "  skip  fish is not installed"
fi

# bash_complete WORD...: what bash completes for the last WORD.
bash_complete() {
  bash -c 'source <("$0" completion bash)
    COMP_WORDS=("$@") COMP_CWORD=$(($# - 1))
    if [[ $1 == git ]]; then
      # As Git'"'"'s completion sets them.
      words=("$@") cword=$COMP_CWORD __git_cmd_idx=1
      _git_age
    else
      _git_age_main
    fi
    printf "%s\n" "${COMPREPLY[@]}"' "$GIT_AGE" "$@"
}
# completes EXPECTED WORD...: bash completes the last WORD as exactly EXPECTED.
completes() { [[ $(bash_complete "${@:2}") == "$1" ]]; }
# offers_public_commands WORD...: bash offers lock but no internal command for the last WORD.
offers_public_commands() {
  local out
  out=$(bash_complete "$@") && grep -qx lock <<<"$out" &&
    ! grep -qxE "textconv|clean|merge|hook" <<<"$out"
}
check "bash completes the commands" completes lock git-age lo
check "but not the internal ones" offers_public_commands git-age ""
check "after global options" completes unlock git-age -C . -n unl
check "a command's options" completes --no-reuse git-age lock --no
check "choices" completes always-lock git-age install --mode al
check "also after =" completes always-lock git-age install --mode = al
check "files for --identity" completes "$tmp/keys/alice" git-age unlock -i "$tmp/keys/al"
check "help topics" completes git-hooks git-age help git-ho
check "and git age, through _git_age" completes rekey git age rek
check "where internal commands are hidden too" offers_public_commands git age ""
if command -v fish >/dev/null; then
  check "fish completes the commands but not the internal ones" \
    bash -c 'out=$(fish --no-config -c "source (\"$0\" completion fish | psub); complete -C \"git-age \"") &&
      grep -q "^lock" <<<"$out" && ! grep -qE "^(textconv|clean|merge|hook)\b" <<<"$out"' "$GIT_AGE"
  check "fish completes choices" \
    bash -c '[[ $(fish --no-config -c "source (\"$0\" completion fish | psub); complete -C \"git-age install --mode=al\"" | cut -f1) == --mode=always-lock ]]' "$GIT_AGE"
fi

# --- summary -------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[[ $failed -eq 0 ]]
