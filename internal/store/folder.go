package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A folder (the git repo root, else the working directory) remembers the
// project its .env was imported into, so coming back to it later resolves
// bare names in that project without `sec use` or --project.

func foldersPath() string { return filepath.Join(Home(), "folders.json") }

// FolderRoot is the git repo root above the working directory, else the
// working directory itself. "" for $HOME and / — too broad to own a project.
func FolderRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	wd, _ = filepath.EvalSymlinks(wd)
	root := wd
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			root = d
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	home, _ := os.UserHomeDir()
	home, _ = filepath.EvalSymlinks(home)
	if root == home || filepath.Dir(root) == root {
		return ""
	}
	return root
}

var notProjectChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// FolderProjectName turns a folder's base name into a valid project name.
func FolderProjectName(root string) string {
	n := notProjectChars.ReplaceAllString(strings.ToLower(filepath.Base(root)), "-")
	n = strings.TrimLeft(n, "._-")
	if ValidProject(n) != nil {
		return ""
	}
	return n
}

func loadFolders() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(foldersPath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

// FolderProject is the project remembered for the current folder ("" none).
func FolderProject() string {
	root := FolderRoot()
	if root == "" {
		return ""
	}
	return loadFolders()[root]
}

// RememberFolder ties the current folder to project p.
func RememberFolder(p string) error {
	root := FolderRoot()
	if root == "" || p == "" {
		return nil
	}
	if err := ValidProject(p); err != nil {
		return err
	}
	m := loadFolders()
	if m[root] == p {
		return nil
	}
	m[root] = p
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(foldersPath(), append(b, '\n'), 0o600)
}
