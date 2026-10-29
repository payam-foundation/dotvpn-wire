// Package atomicfile writes secret-bearing files (configs, keys) so a crash
// never leaves a half-written or world-readable file.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write creates path's directory with dirMode, writes data to a 0600 temp file
// next to path and renames it into place. Rename is atomic on one filesystem.
func Write(path string, data []byte, dirMode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
