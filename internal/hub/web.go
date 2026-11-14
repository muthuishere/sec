package hub

// The hub's web UI. It has no listening port of its own: it answers only
// ssh port-forwards (direct-tcpip channels) made over the hub's ssh server,
// so a person needs a key the hub already knows just to load the page. Then
// Google sign-in (Firebase Auth, identity only) says which person it is; the
// signed-in email must be the one bound to that key. What anyone may do is
// still decided here, by users.json — Firebase never grants anything.
//
// The UI shows names, grants and the log. It never shows a value.

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/muthuishere/sec/internal/store"
)

//go:embed web/index.html
var webFS embed.FS

// WebConfig is DIR/web.json. The Firebase web API key is public by design
// (it identifies the project, it grants nothing).
type WebConfig struct {
	FirebaseProject string   `json:"firebase_project"`
	FirebaseAPIKey  string   `json:"firebase_api_key"`
	AdminEmails     []string `json:"admin_emails,omitempty"`
}

func (s *Server) webPath() string { return filepath.Join(s.Dir, "web.json") }

// WebEnabled reports whether the UI is configured.
func (s *Server) WebEnabled() bool { return s.web != nil && s.web.FirebaseProject != "" }

// ConfigureWeb merges non-empty fields into DIR/web.json and turns the UI on.
func (s *Server) ConfigureWeb(c WebConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := WebConfig{}
	if s.web != nil {
		cur = *s.web
	}
	if c.FirebaseProject != "" {
		cur.FirebaseProject = c.FirebaseProject
	}
	if c.FirebaseAPIKey != "" {
		cur.FirebaseAPIKey = c.FirebaseAPIKey
	}
	if len(c.AdminEmails) > 0 {
		cur.AdminEmails = nil
		for _, e := range c.AdminEmails {
			if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
				cur.AdminEmails = append(cur.AdminEmails, e)
			}
		}
	}
	if cur.FirebaseProject == "" || cur.FirebaseAPIKey == "" {
		return errors.New("the UI needs --firebase-project and --firebase-api-key")
	}
	b, _ := json.MarshalIndent(cur, "", "  ")
	if err := os.WriteFile(s.webPath(), append(b, '\n'), 0o600); err != nil {
		return err
	}
	s.web = &cur
	return nil
}

func (s *Server) loadWeb() error {
	b, err := os.ReadFile(s.webPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var c WebConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("%s: %w", s.webPath(), err)
	}
	s.web = &c
	return nil
}

func (s *Server) adminEmail(e string) bool {
	if s.web == nil {
		return false
	}
	for _, a := range s.web.AdminEmails {
		if a == e {
			return true
		}
	}
	return false
}

// ---- serving over ssh channels -------------------------------------------

type ctxKey struct{}

// serveUI answers one forwarded connection as HTTP, as sshUser.
func (s *Server) serveUI(sshUser string, ch ssh.Channel) {
	c := &chanConn{Channel: ch}
	l := &oneConnListener{c: c, done: make(chan struct{})}
	srv := &http.Server{
		Handler:           s.uiHandler(sshUser),
		ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(_ net.Conn, st http.ConnState) {
			if st == http.StateClosed || st == http.StateHijacked {
				l.Close()
			}
		},
	}
	srv.Serve(l)
}

type chanConn struct{ ssh.Channel }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "ssh" }
func (fakeAddr) String() string  { return "ssh-forward" }

func (c *chanConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *chanConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *chanConn) SetDeadline(t time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(t time.Time) error { return nil }

type oneConnListener struct {
	c    net.Conn
	once sync.Once
	gave bool
	mu   sync.Mutex
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.gave {
		l.gave = true
		l.mu.Unlock()
		return l.c, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}
func (l *oneConnListener) Addr() net.Addr { return fakeAddr{} }

// ---- sessions -------------------------------------------------------------

const sessionTTL = 12 * time.Hour

func (s *Server) sessionKey() []byte {
	s.skOnce.Do(func() {
		p := filepath.Join(s.Dir, "session.key")
		if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
			s.sk = b
			return
		}
		b := make([]byte, 32)
		rand.Read(b)
		os.WriteFile(p, b, 0o600)
		s.sk = b
	})
	return s.sk
}

func (s *Server) makeSession(user, email string, now time.Time) string {
	payload := user + "|" + email + "|" + strconv.FormatInt(now.Add(sessionTTL).Unix(), 10)
	m := hmac.New(sha256.New, s.sessionKey())
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + hex.EncodeToString(m.Sum(nil))
}

func (s *Server) readSession(v string, now time.Time) (user, email string, ok bool) {
	p, sig, found := strings.Cut(v, ".")
	if !found {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", "", false
	}
	m := hmac.New(sha256.New, s.sessionKey())
	m.Write(raw)
	want := hex.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return "", "", false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", "", false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || now.Unix() > exp {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// ---- Firebase ID token verification (stdlib only) -------------------------

const googleCerts = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

type certCache struct {
	mu    sync.Mutex
	keys  map[string]*rsa.PublicKey
	until time.Time
}

func (c *certCache) get(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok && time.Now().Before(c.until) {
		return k, nil
	}
	cl := &http.Client{Timeout: 10 * time.Second}
	resp, err := cl.Get(googleCerts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, err
	}
	c.keys = map[string]*rsa.PublicKey{}
	for id, p := range m {
		blk, _ := pem.Decode([]byte(p))
		if blk == nil {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		if k, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			c.keys[id] = k
		}
	}
	c.until = time.Now().Add(time.Hour)
	k, ok := c.keys[kid]
	if !ok {
		return nil, errors.New("unknown signing key")
	}
	return k, nil
}

// verifyFirebase checks a Firebase ID token and returns its verified Google email.
func (s *Server) verifyFirebase(tok string, now time.Time) (string, error) {
	if s.VerifyToken != nil {
		return s.VerifyToken(tok)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", errors.New("malformed token")
	}
	var h struct{ Alg, Kid string }
	if json.Unmarshal(hb, &h) != nil || h.Alg != "RS256" || h.Kid == "" {
		return "", errors.New("token is not RS256")
	}
	key, err := s.certs.get(h.Kid)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return "", errors.New("bad token signature")
	}
	var c struct {
		Aud           string `json:"aud"`
		Iss           string `json:"iss"`
		Sub           string `json:"sub"`
		Exp           int64  `json:"exp"`
		Iat           int64  `json:"iat"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Firebase      struct {
			Provider string `json:"sign_in_provider"`
		} `json:"firebase"`
	}
	if err := json.Unmarshal(cb, &c); err != nil {
		return "", errors.New("malformed claims")
	}
	p := s.web.FirebaseProject
	switch {
	case c.Aud != p || c.Iss != "https://securetoken.google.com/"+p:
		return "", errors.New("token is for another project")
	case c.Sub == "":
		return "", errors.New("token has no subject")
	case now.Unix() > c.Exp || c.Iat > now.Add(5*time.Minute).Unix():
		return "", errors.New("token expired")
	case c.Firebase.Provider != "google.com":
		return "", errors.New("only Google sign-in is accepted")
	case !c.EmailVerified || c.Email == "":
		return "", errors.New("email not verified")
	}
	return strings.ToLower(c.Email), nil
}

// ---- HTTP handlers --------------------------------------------------------

type uiUser struct {
	User
	SignedIn string // google email
	IsAdmin  bool
}

func (s *Server) uiHandler(sshUser string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(b)
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{
			"apiKey":     s.web.FirebaseAPIKey,
			"authDomain": s.web.FirebaseProject + ".firebaseapp.com",
			"projectId":  s.web.FirebaseProject,
			"sshUser":    sshUser,
		})
	})
	mux.HandleFunc("POST /api/session", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ IDToken string }
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in) != nil {
			httpErr(w, 400, "want {idToken}")
			return
		}
		email, err := s.verifyFirebase(in.IDToken, time.Now())
		if err != nil {
			httpErr(w, 401, err.Error())
			return
		}
		if err := s.bindEmail(sshUser, email); err != nil {
			s.uiLog(sshUser, "ui.login", nil, err)
			httpErr(w, 403, err.Error())
			return
		}
		s.uiLog(sshUser, "ui.login", []string{email}, nil)
		http.SetCookie(w, &http.Cookie{Name: "sec_hub", Value: s.makeSession(sshUser, email, time.Now()),
			Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL / time.Second)})
		writeJSON(w, map[string]string{"email": email})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sec_hub", Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, map[string]bool{"ok": true})
	})
	authed := func(admin bool, f func(http.ResponseWriter, *http.Request, uiUser)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Header.Get("X-Sec-UI") != "1" {
				httpErr(w, 403, "missing X-Sec-UI header")
				return
			}
			ck, err := r.Cookie("sec_hub")
			if err != nil {
				httpErr(w, 401, "sign in with Google")
				return
			}
			u, email, ok := s.readSession(ck.Value, time.Now())
			if !ok || u != sshUser {
				httpErr(w, 401, "sign in with Google")
				return
			}
			s.mu.Lock()
			us, err := s.loadUsers()
			s.mu.Unlock()
			if err != nil {
				httpErr(w, 500, err.Error())
				return
			}
			i, found := find(us, sshUser)
			if !found || us[i].Email != email {
				httpErr(w, 401, "this key's user changed — sign in again")
				return
			}
			uu := uiUser{User: us[i], SignedIn: email, IsAdmin: us[i].Admin && (s.adminEmail(email) || len(s.web.AdminEmails) == 0)}
			if admin && !uu.IsAdmin {
				httpErr(w, 403, "admins only")
				return
			}
			f(w, r, uu)
		}
	}
	mux.HandleFunc("GET /api/me", authed(false, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		writeJSON(w, map[string]any{"user": u.Name, "email": u.SignedIn, "admin": u.IsAdmin,
			"grants": u.Grants, "key": fingerprint(u.Key)})
	}))
	mux.HandleFunc("GET /api/projects", authed(false, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		out, err := s.projects(u)
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		writeJSON(w, out)
	}))
	mux.HandleFunc("GET /api/log", authed(false, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		lu := u.User
		lu.Admin = u.IsAdmin
		ents, err := s.readLog(lu, 300)
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		for i, j := 0, len(ents)-1; i < j; i, j = i+1, j-1 {
			ents[i], ents[j] = ents[j], ents[i]
		}
		writeJSON(w, ents)
	}))
	mux.HandleFunc("GET /api/users", authed(true, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		s.mu.Lock()
		us, err := s.loadUsers()
		s.mu.Unlock()
		if err != nil {
			httpErr(w, 500, err.Error())
			return
		}
		type row struct {
			Name   string  `json:"name"`
			Email  string  `json:"email,omitempty"`
			Admin  bool    `json:"admin,omitempty"`
			Key    string  `json:"key,omitempty"`
			Grants []Grant `json:"grants,omitempty"`
		}
		out := []row{}
		for _, x := range us {
			out = append(out, row{x.Name, x.Email, x.Admin, fingerprint(x.Key), x.Grants})
		}
		writeJSON(w, out)
	}))
	mux.HandleFunc("POST /api/users", authed(true, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		var in struct{ Name, Email, Key, Role, Project, Env string }
		if json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&in) != nil {
			httpErr(w, 400, "bad json")
			return
		}
		err := s.uiAddUser(in.Name, strings.ToLower(strings.TrimSpace(in.Email)), in.Key, in.Role, in.Project, in.Env)
		s.uiLog(u.Name, "ui.user.add", []string{in.Name}, err)
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/users/revoke", authed(true, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		var in struct{ Name, Project, Env string }
		if json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in) != nil {
			httpErr(w, 400, "bad json")
			return
		}
		err := s.updateUsers(func(us []User) ([]User, error) {
			i, ok := find(us, in.Name)
			if !ok {
				return nil, fmt.Errorf("no user %s", in.Name)
			}
			var keep []Grant
			for _, g := range us[i].Grants {
				if !(g.Project == in.Project && g.Env == in.Env) {
					keep = append(keep, g)
				}
			}
			us[i].Grants = keep
			return us, nil
		})
		s.uiLog(u.Name, "ui.grant.revoke", []string{in.Name}, err)
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/users/remove", authed(true, func(w http.ResponseWriter, r *http.Request, u uiUser) {
		var in struct{ Name string }
		if json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in) != nil {
			httpErr(w, 400, "bad json")
			return
		}
		err := s.updateUsers(func(us []User) ([]User, error) {
			i, ok := find(us, in.Name)
			if !ok {
				return nil, fmt.Errorf("no user %s", in.Name)
			}
			if in.Name == u.Name {
				return nil, errors.New("an admin may not remove themselves")
			}
			return append(us[:i], us[i+1:]...), nil
		})
		s.uiLog(u.Name, "ui.user.rm", []string{in.Name}, err)
		if err != nil {
			httpErr(w, 400, err.Error())
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// bindEmail ties a Google email to the ssh user that opened the forward. A
// user with an email already must sign in with that email; a user without
// one is bound on first sign-in. An admin email listed in web.json makes the
// key's user an admin (the key alone got them here, Google says who).
func (s *Server) bindEmail(sshUser, email string) error {
	return s.updateUsers(func(us []User) ([]User, error) {
		i, ok := find(us, sshUser)
		if !ok {
			return nil, errors.New("unknown user")
		}
		if us[i].Email != "" && us[i].Email != email {
			return nil, fmt.Errorf("this key belongs to %s, not %s", us[i].Email, email)
		}
		for j, x := range us {
			if j != i && x.Email == email {
				return nil, fmt.Errorf("%s is already bound to user %s", email, x.Name)
			}
		}
		us[i].Email = email
		if s.adminEmail(email) {
			us[i].Admin = true
		}
		return us, nil
	})
}

func (s *Server) updateUsers(f func([]User) ([]User, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	us, err := s.loadUsers()
	if err != nil {
		return err
	}
	us, err = f(us)
	if err != nil {
		return err
	}
	return s.saveUsers(us)
}

func (s *Server) uiAddUser(name, email, key, role, project, env string) error {
	if name == "" {
		name = email
	}
	if err := validUser(name); err != nil {
		return err
	}
	if email != "" && !strings.Contains(email, "@") {
		return fmt.Errorf("bad email %q", email)
	}
	var g *Grant
	if project != "" {
		if role != "read" && role != "write" {
			return fmt.Errorf("role must be read or write")
		}
		if err := store.ValidProject(project); err != nil {
			return err
		}
		if env != "" {
			if err := store.ValidEnv(env); err != nil {
				return err
			}
		}
		g = &Grant{Project: project, Env: env, Role: role}
	}
	var line string
	if strings.TrimSpace(key) != "" {
		l, err := normKey([]byte(key))
		if err != nil {
			return fmt.Errorf("ssh public key: %w", err)
		}
		line = l
	}
	return s.updateUsers(func(us []User) ([]User, error) {
		for _, x := range us {
			if x.Name == name {
				continue
			}
			if line != "" && x.Key != "" && sameKeyLines(x.Key, line) {
				return nil, fmt.Errorf("that key already belongs to %s", x.Name)
			}
			if email != "" && x.Email == email {
				return nil, fmt.Errorf("%s is already user %s", email, x.Name)
			}
		}
		i, ok := find(us, name)
		if !ok {
			if line == "" {
				return nil, errors.New("a new person needs their ssh public key (cat ~/.ssh/id_ed25519.pub) — it is how they reach the hub")
			}
			us = append(us, User{Name: name, Email: email, Key: line})
			i = len(us) - 1
		} else {
			if line != "" {
				us[i].Key = line
			}
			if email != "" {
				us[i].Email = email
			}
		}
		if g != nil {
			replaced := false
			for j, x := range us[i].Grants {
				if x.Project == g.Project && x.Env == g.Env {
					us[i].Grants[j], replaced = *g, true
				}
			}
			if !replaced {
				us[i].Grants = append(us[i].Grants, *g)
			}
		}
		return us, nil
	})
}

type projEnv struct {
	Project string    `json:"project"`
	Env     string    `json:"env"`
	Names   []string  `json:"names"`
	Updated time.Time `json:"updated"`
	Write   bool      `json:"write"`
}

// projects lists every project@env the user may read, with its NAMES only.
func (s *Server) projects(u uiUser) ([]projEnv, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	root := filepath.Join(s.Dir, "data")
	lu := u.User
	lu.Admin = u.IsAdmin
	out := []projEnv{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".age") {
			return nil
		}
		base := strings.TrimSuffix(d.Name(), ".age")
		if strings.Contains(base, ".") { // ENV.<unix>.age: an old copy
			return nil
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		proj := filepath.ToSlash(rel)
		if !allowed(lu, proj, base, false) {
			return nil
		}
		m, err := s.readEnv(proj, base)
		if err != nil {
			return nil
		}
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		info, _ := d.Info()
		pe := projEnv{Project: proj, Env: base, Names: names, Write: allowed(lu, proj, base, true)}
		if info != nil {
			pe.Updated = info.ModTime().UTC()
		}
		out = append(out, pe)
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return out, err
}

func (s *Server) uiLog(user, action string, names []string, err error) {
	e := LogEntry{User: user, Action: action, Names: names, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	s.mu.Lock()
	s.log(e)
	s.mu.Unlock()
}

func fingerprint(line string) string {
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil {
		return ssh.FingerprintSHA256(k)
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
