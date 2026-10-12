package main

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStaticExecutable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("static ELF check is Linux-only")
	}

	binary := os.Getenv("GIT_AGE")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "git-age")
		build := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")

		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	}

	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("not an executable file: %s", binary)
	}

	file, err := elf.Open(binary)
	if err != nil {
		t.Fatalf("open ELF executable: %v", err)
	}
	defer file.Close()

	if (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) || file.Entry == 0 {
		t.Fatal("ELF file is not an executable")
	}

	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			t.Fatal("executable requires a dynamic interpreter")
		}
	}

	libraries, err := file.ImportedLibraries()
	if err != nil {
		t.Fatal(err)
	}
	if len(libraries) != 0 {
		t.Fatalf("executable requires shared libraries: %v", libraries)
	}
}
