// Package skills carries the agent skill inside the sec binary, so
// `sec skill install` works on any machine — including one sec was just
// streamed onto — without the source tree.
package skills

import (
	"bytes"
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed sec
var files embed.FS

// Marker is written next to the files so a later install knows sec owns the folder.
const Marker = ".sec-managed"

// Write puts the whole skill (SKILL.md, scenarios.md, references/) into dst.
func Write(dst string) error {
	err := fs.WalkDir(files, "sec", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out := filepath.Join(dst, filepath.FromSlash(p[len("sec"):]))
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, _ := files.ReadFile(p)
		return os.WriteFile(out, b, 0o644)
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dst, Marker), nil, 0o644)
}

// Current reports whether dst already holds exactly this build's skill files.
func Current(dst string) bool {
	ok := true
	_ = fs.WalkDir(files, "sec", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !ok {
			return err
		}
		want, _ := files.ReadFile(p)
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(p[len("sec"):])))
		ok = err == nil && bytes.Equal(got, want)
		return nil
	})
	return ok
}

// Owns reports whether a top-level entry name in an installed skill folder is
// one sec writes (current files, the marker, or the lone legacy SKILL.md).
func Owns(name string) bool {
	if name == Marker {
		return true
	}
	_, err := fs.Stat(files, "sec/"+name)
	return err == nil
}
