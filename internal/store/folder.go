package store

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A repo (or folder) names its vault project in a `.sec` file at its root:
//
//	project = billing
//	env = dev        # optional
//
// A bare first line (`billing`) also works. `sec import .env` writes one when
// none exists, named after the repo root / folder; edit it to rename. Inside
// that repo — any subfolder — bare names resolve in that project first.
// The file holds no secret: commit it. SEC_NO_DOTSEC=1 ignores .sec files.

// SecFile is the name of the per-repo project file.
const SecFile = ".sec"

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
	if tooBroad(root) {
		return ""
	}
	return root
}

func tooBroad(d string) bool {
	home, _ := os.UserHomeDir()
	home, _ = filepath.EvalSymlinks(home)
	return d == home || filepath.Dir(d) == d
}

var notProjectChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// FolderProjectName turns a folder's base name into a valid project name.
func FolderProjectName(root string) string {
	if root == "" {
		return ""
	}
	n := notProjectChars.ReplaceAllString(strings.ToLower(filepath.Base(root)), "-")
	n = strings.TrimLeft(n, "._-")
	if ValidProject(n) != nil {
		return ""
	}
	return n
}

// FindSecFile walks up from the working directory to the repo root (or, out
// of a repo, up to but not into $HOME) and returns the first .sec file.
func FindSecFile() string {
	if os.Getenv("SEC_NO_DOTSEC") != "" {
		return ""
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	wd, _ = filepath.EvalSymlinks(wd)
	for d := wd; !tooBroad(d); d = filepath.Dir(d) {
		p := filepath.Join(d, SecFile)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Size() < 4096 {
			return p
		}
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			break // the repo root is as far as a repo's .sec reaches
		}
	}
	return ""
}

// ReadSecFile parses a .sec file into a Context. Unknown keys are ignored.
func ReadSecFile(path string) (Context, error) {
	var c Context
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			k, v, ok = strings.Cut(line, ":")
		}
		if !ok {
			if c.Project == "" {
				c.Project = line
			}
			continue
		}
		switch strings.TrimSpace(k) {
		case "project":
			c.Project = strings.TrimSpace(v)
		case "env":
			c.Env = strings.TrimSpace(v)
		}
	}
	if c.Project != "" {
		if err := ValidProject(c.Project); err != nil {
			return Context{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	if c.Env != "" {
		if err := ValidEnv(c.Env); err != nil {
			return Context{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	return c, nil
}

// FolderContext is the context the nearest .sec file names (zero if none or invalid).
func FolderContext() Context {
	p := FindSecFile()
	if p == "" {
		return Context{}
	}
	c, _ := ReadSecFile(p)
	return c
}

// FolderProject is the project the nearest .sec file names ("" none).
func FolderProject() string { return FolderContext().Project }

// RememberFolder writes a .sec naming project p at the repo root / folder,
// unless a .sec is already in reach (that file is the owner's to edit).
// It returns the path written ("" when nothing was written).
func RememberFolder(p string) (string, error) {
	if p == "" || FindSecFile() != "" || os.Getenv("SEC_NO_DOTSEC") != "" {
		return "", nil
	}
	root := FolderRoot()
	if root == "" {
		return "", nil
	}
	if err := ValidProject(p); err != nil {
		return "", err
	}
	path := filepath.Join(root, SecFile)
	body := "# sec: the vault project this repo uses — bare names resolve here first. No secrets; commit it.\nproject = " + p + "\n"
	return path, os.WriteFile(path, []byte(body), 0o644)
}
