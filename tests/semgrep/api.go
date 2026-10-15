// Semgrep rule tests for skills/sk-api/rules/api.yml (Go).
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: sk-ssrf-go
	resp, _ := http.Get(target)
	_ = resp
	// ok: sk-ssrf-go
	http.Get("https://api.example.com")

	host := r.FormValue("host")
	// ruleid: sk-command-injection-go
	exec.Command("sh", "-c", "ping "+host).Run()
	// ok: sk-command-injection-go
	exec.Command("ping", "-c", "1", host).Run()

	// ruleid: sk-tls-verify-disabled
	_ = &tls.Config{InsecureSkipVerify: true}

	// ruleid: sk-sql-string-building
	q := fmt.Sprintf("SELECT * FROM users WHERE id = %s", r.FormValue("id"))
	_ = q
}

// ruleid: sk-hardcoded-secret-go-java
var jwtSecret = "go-hardcoded-signing-secret"

func parse(tok string) {
	// ruleid: sk-jwt-decode-without-verify-go
	parser.ParseUnverified(tok, claims)
}
