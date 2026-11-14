package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// sec hub ui: the hub's web UI has no web port. This opens an ssh
// port-forward over the hub's own ssh (your key must be one the hub knows)
// and the browser on http://localhost:PORT. Google sign-in then says who you
// are. Ctrl-C closes it.
func hubUI(args []string) error {
	fs := flags("hub ui")
	port := fs.Int("port", 8091, "local port for the forward")
	noOpen := fs.Bool("no-browser", false, "print the URL instead of opening it")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	u := hubURL()
	if !strings.HasPrefix(u, "ssh://") {
		return errors.New("the hub UI is reached only over the hub's ssh: run `sec login ssh://host:2222` first")
	}
	dest, err := sshArgs(u)
	if err != nil {
		return err
	}
	local := "127.0.0.1:" + strconv.Itoa(*port)
	a := []string{"-N", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-L", local + ":hub:80"}
	c := exec.Command("ssh", append(a, dest...)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	for i := 0; i < 50; i++ { // wait until the forward listens
		if conn, err := net.DialTimeout("tcp", local, 200*time.Millisecond); err == nil {
			conn.Close()
			break
		}
		select {
		case err := <-done:
			return fmt.Errorf("ssh forward to %s failed: %v", u, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	// localhost, not 127.0.0.1: it is a Firebase authorized domain by default
	url := "http://localhost:" + strconv.Itoa(*port) + "/"
	fmt.Printf("sec hub UI: %s  (through %s — Ctrl-C to close)\n", url, u)
	if !*noOpen {
		openBrowser(url)
	}
	return <-done
}

func openBrowser(url string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		c = exec.Command("xdg-open", url)
	}
	c.Start()
}
