package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b.yaml")
	for _, want := range []string{"one", "two"} { // second write replaces the first
		if err := Write(p, []byte(want), 0o700); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != want {
			t.Fatalf("got %q want %q", b, want)
		}
	}
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}
