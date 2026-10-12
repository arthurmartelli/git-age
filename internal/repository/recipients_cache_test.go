package repository

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cacheGit(t *testing.T, root string, input []byte, args ...string) string {
	t.Helper()
	output, err := gitWithInput(root, input, args...)
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}

func cacheFile(t *testing.T, directory, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecipientCachePruning(t *testing.T) {
	root := identityTestRepo(t)
	cacheGit(t, root, nil, "config", "user.name", "Test")
	cacheGit(t, root, nil, "config", "user.email", "test@example.com")
	cacheGit(t, root, nil, "config", "commit.gpgsign", "false")
	cacheFile(t, root, ".gitage", []byte("[files]\n*.env\n"))
	ciphertexts := map[string][]byte{}
	for _, name := range []string{"head", "index", "base", "ours", "theirs", "working", "unreachable", "recent"} {
		ciphertexts[name] = []byte("age-encryption.org/v1\n" + name + "\n")
	}
	// Armored ciphertext must be retained by its stored bytes too.
	ciphertexts["theirs"] = []byte("-----BEGIN AGE ENCRYPTED FILE-----\ntheirs\n-----END AGE ENCRYPTED FILE-----\n")
	cacheFile(t, root, "head.env", ciphertexts["head"])
	cacheGit(t, root, nil, "add", ".gitage", "head.env")
	cacheGit(t, root, nil, "commit", "-qm", "HEAD ciphertext")
	cacheGit(t, root, nil, "rm", "-q", "head.env")
	cacheFile(t, root, "index.env", ciphertexts["index"])
	cacheGit(t, root, nil, "add", "index.env")
	cacheFile(t, root, "index.env", []byte("unlocked working copy"))
	var conflict strings.Builder
	for stage, name := range []string{"base", "ours", "theirs"} {
		oid := cacheGit(t, root, ciphertexts[name], "hash-object", "-w", "--stdin")
		fmt.Fprintf(&conflict, "100644 %s %d\tconflict.env%c", oid, stage+1, 0)
	}
	cacheGit(t, root, []byte(conflict.String()), "update-index", "-z", "--index-info")
	cacheFile(t, root, "working.env", ciphertexts["working"])
	cacheFile(t, root, "unprotected.txt", ciphertexts["unreachable"])
	directory, err := gitPath(root, "git-age/recipients")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-recipientCacheGrace - time.Hour)
	for name, ciphertext := range ciphertexts {
		path := cacheFile(t, directory, ciphertextHash(ciphertext), []byte("fingerprint"))
		modified := old
		if name == "recent" {
			modified = now.Add(-recipientCacheGrace + time.Hour)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	unknown := cacheFile(t, directory, "unrelated", []byte("keep"))
	sentinel := cacheFile(t, t.TempDir(), "sentinel", []byte("keep"))
	symlink := filepath.Join(directory, strings.Repeat("e", 64))
	hasSymlink := os.Symlink(sentinel, symlink) == nil
	index, err := git(root, "ls-files", "--stage", "-z")
	if err != nil {
		t.Fatal(err)
	}
	if err := pruneRecipientCache(root, directory, now); err != nil {
		t.Fatal(err)
	}
	for name, ciphertext := range ciphertexts {
		info, err := os.Stat(filepath.Join(directory, ciphertextHash(ciphertext)))
		if name == "unreachable" {
			if !os.IsNotExist(err) {
				t.Fatalf("expired unreachable record retained: %v", err)
			}
		} else if err != nil {
			t.Errorf("lost %s ciphertext fingerprint: %v", name, err)
		} else {
			want := now
			if name == "recent" {
				want = now.Add(-recipientCacheGrace + time.Hour)
			}
			if difference := info.ModTime().Sub(want); difference < -time.Second || difference > time.Second {
				t.Errorf("%s record mtime = %v, want %v", name, info.ModTime(), want)
			}
		}
	}
	for _, path := range []string{unknown, sentinel} {
		if content, err := os.ReadFile(path); err != nil || string(content) != "keep" {
			t.Fatalf("unrelated file changed: %s, %v", path, err)
		}
	}
	if hasSymlink {
		if _, err := os.Lstat(symlink); err != nil {
			t.Fatal("prune removed a symlink")
		}
	}
	if after, err := git(root, "ls-files", "--stage", "-z"); err != nil || string(index) != string(after) {
		t.Fatal("prune changed index or conflict stages")
	}
	// Malformed working rules would fail another retention scan. All old live
	// records have been refreshed, so the next encryption needn't scan at all.
	cacheFile(t, root, ".gitage", []byte("[unknown]\n"))
	if err := pruneRecipientCache(root, directory, now.Add(time.Minute)); err != nil {
		t.Fatalf("rescanned despite refreshing all expired live records: %v", err)
	}
}

func TestRecipientCachePruningProtectedHEADPaths(t *testing.T) {
	root := identityTestRepo(t)
	cacheGit(t, root, nil, "config", "user.name", "Test")
	cacheGit(t, root, nil, "config", "user.email", "test@example.com")
	cacheGit(t, root, nil, "config", "commit.gpgsign", "false")
	cacheFile(t, root, ".gitage", []byte("[files]\n*.env\n!excluded.env\nnested/*\n"))
	cacheFile(t, root, "nested/.gitage", []byte("[files]\n!*.txt\n"))
	ciphertexts := map[string][]byte{}
	unprotected := map[string]bool{"excluded.env": true, "nested/public.txt": true}
	for _, path := range []string{"head.env", "excluded.env", "nested/secret\t\n.env", "nested/public.txt"} {
		ciphertexts[path] = []byte("age-encryption.org/v1\n" + path + "\n")
		cacheFile(t, root, path, ciphertexts[path])
	}
	cacheGit(t, root, nil, "add", ".")
	cacheGit(t, root, nil, "commit", "-qm", "HEAD protection rules")
	cacheGit(t, root, nil, "rm", "-qr", ".")
	// The index and working tree now protect different paths. Retention of
	// HEAD-only ciphertext must use HEAD's rules, including nested negations.
	cacheFile(t, root, ".gitage", []byte("[files]\nworking.env\n"))
	cacheGit(t, root, nil, "add", ".gitage")
	directory, err := gitPath(root, "git-age/recipients")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-recipientCacheGrace - time.Hour)
	for path, ciphertext := range ciphertexts {
		record := cacheFile(t, directory, ciphertextHash(ciphertext), []byte("fingerprint"))
		if err := os.Chtimes(record, old, old); err != nil {
			t.Fatal(err)
		}
		if unprotected[path] {
			// Make these blobs unavailable to prove pruning never reads them.
			oid := cacheGit(t, root, ciphertext, "hash-object", "--stdin")
			object, err := gitPath(root, "objects/"+oid[:2]+"/"+oid[2:])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(object); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := pruneRecipientCache(root, directory, now); err != nil {
		t.Fatal(err)
	}
	for path, ciphertext := range ciphertexts {
		_, err := os.Stat(filepath.Join(directory, ciphertextHash(ciphertext)))
		if unprotected[path] {
			if !os.IsNotExist(err) {
				t.Errorf("unprotected HEAD record %q retained: %v", path, err)
			}
		} else if err != nil {
			t.Errorf("lost protected HEAD record %q: %v", path, err)
		}
	}
}

func TestRecipientCachePruningProtectedIndexPaths(t *testing.T) {
	for _, scenario := range []string{"staged rules", "conflicted rules"} {
		t.Run(scenario, func(t *testing.T) {
			root := identityTestRepo(t)
			cacheFile(t, root, ".gitage", []byte("[files]\nroot.env\n"))
			cacheGit(t, root, nil, "add", ".gitage")
			var index strings.Builder
			if scenario == "staged rules" {
				cacheFile(t, root, "nested/.gitage", []byte("[files]\n*.env\n"))
				cacheGit(t, root, nil, "add", "nested/.gitage")
			} else {
				for stage, name := range []string{"base", "ours", "theirs"} {
					oid := cacheGit(t, root, []byte("[files]\n"+name+".env\n"), "hash-object", "-w", "--stdin")
					fmt.Fprintf(&index, "100644 %s %d\tnested/.gitage%c", oid, stage+1, 0)
				}
			}
			// Working rules disagree with the staged rules. No working files
			// can supply the retention hashes for these indexed ciphertexts.
			cacheFile(t, root, ".gitage", []byte("[files]\nworking.env\n"))
			directory, err := gitPath(root, "git-age/recipients")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			old := now.Add(-recipientCacheGrace - time.Hour)
			records := map[string]bool{}
			for _, path := range []string{"root.env", "nested/base.env", "nested/ours.env", "nested/theirs.env", "public.txt"} {
				stages := []int{0}
				if scenario == "conflicted rules" {
					stages = []int{1, 2, 3}
				}
				for _, stage := range stages {
					ciphertext := []byte(fmt.Sprintf("age-encryption.org/v1\n%s stage %d\n", path, stage))
					oid := cacheGit(t, root, ciphertext, "hash-object", "-w", "--stdin")
					fmt.Fprintf(&index, "100644 %s %d\t%s%c", oid, stage, path, 0)
					record := cacheFile(t, directory, ciphertextHash(ciphertext), []byte("fingerprint"))
					if err := os.Chtimes(record, old, old); err != nil {
						t.Fatal(err)
					}
					records[record] = path != "public.txt"
					if path == "public.txt" {
						object, err := gitPath(root, "objects/"+oid[:2]+"/"+oid[2:])
						if err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(object); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			cacheGit(t, root, []byte(index.String()), "update-index", "-z", "--index-info")
			if err := pruneRecipientCache(root, directory, now); err != nil {
				t.Fatal(err)
			}
			for record, protected := range records {
				_, err := os.Stat(record)
				if protected && err != nil {
					t.Errorf("lost protected stage record: %v", err)
				} else if !protected && !os.IsNotExist(err) {
					t.Errorf("unprotected index record retained: %v", err)
				}
			}
		})
	}
}

func TestRecipientCachePruningUnbornAndReadFailure(t *testing.T) {
	for _, scenario := range []string{"unborn", "no rules", "malformed rules"} {
		t.Run(scenario, func(t *testing.T) {
			root := identityTestRepo(t)
			directory, err := gitPath(root, "git-age/recipients")
			if err != nil {
				t.Fatal(err)
			}
			if err := pruneRecipientCache(root, directory, time.Now()); err != nil {
				t.Fatal(err)
			}
			if scenario != "no rules" {
				content := "[files]\n*.env\n"
				if scenario == "malformed rules" {
					content = "[unknown]\n"
				}
				cacheFile(t, root, ".gitage", []byte(content))
			}
			ciphertext := []byte("age-encryption.org/v1\nworking copy\n")
			cacheFile(t, root, "working.env", ciphertext)
			record := cacheFile(t, directory, ciphertextHash(ciphertext), []byte("fingerprint"))
			old := time.Now().Add(-recipientCacheGrace - time.Hour)
			if err := os.Chtimes(record, old, old); err != nil {
				t.Fatal(err)
			}
			err = pruneRecipientCache(root, directory, time.Now())
			if (err != nil) != (scenario == "malformed rules") {
				t.Fatalf("prune: %v", err)
			}
			_, err = os.Stat(record)
			if scenario == "no rules" {
				if !os.IsNotExist(err) {
					t.Fatal("unprotected working file retained its expired fingerprint")
				}
			} else if err != nil {
				t.Fatalf("lost live record or pruned after a read failure: %v", err)
			}
		})
	}
}
