package main

import (
	"embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed lists/discord.txt lists/youtube.txt
var listFS embed.FS

// Matcher решает, нужно ли применять обход к имени сайта (SNI).
type Matcher struct {
	domains []string
	all     bool
	apps    map[string]bool // имена exe выбранных программ
}

func readList(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" && l != "domain.example.abc" {
			out = append(out, l)
		}
	}
	return out
}

func newMatcher(base string, s Settings) *Matcher {
	m := &Matcher{all: s.AllSites, apps: map[string]bool{}}
	for _, a := range s.Apps {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			m.apps[a] = true
		}
	}
	add := func(name string) {
		if b, err := listFS.ReadFile("lists/" + name); err == nil {
			m.domains = append(m.domains, readList(string(b))...)
		}
	}
	if s.Discord {
		add("discord.txt")
	}
	if s.YouTube {
		add("youtube.txt")
	}
	if b, err := os.ReadFile(filepath.Join(base, "lists", "list-user.txt")); err == nil {
		m.domains = append(m.domains, readList(string(b))...)
	}
	return m
}

func (m *Matcher) Match(host string) bool {
	if m.all {
		return true
	}
	for _, d := range m.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
