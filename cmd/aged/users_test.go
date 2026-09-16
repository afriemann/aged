package main

// spec: openspec/changes/multi-user-support/specs/aged/spec.md

import (
	"strings"
	"testing"
)

func TestValidUserName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"alice", true},
		{"ci-runner", true},
		{"a.b_c-9", true},
		{"", false},
		{".", false},
		{"..", false},
		{"-rf", false},
		{"a/b", false},
		{"has space", false},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
	}
	for _, c := range cases {
		if got := validUserName(c.name); got != c.want {
			t.Errorf("validUserName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestValidTokenFormat(t *testing.T) {
	valid := strings.Repeat("a", 64)
	cases := []struct {
		token string
		want  bool
	}{
		{valid, true},
		{"", false},
		{strings.Repeat("a", 63), false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("A", 64), false}, // uppercase not allowed
		{strings.Repeat("g", 64), false}, // non-hex char
	}
	for _, c := range cases {
		if got := validTokenFormat(c.token); got != c.want {
			t.Errorf("validTokenFormat(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}

func tok(b byte) string {
	return strings.Repeat(string(rune(b)), 64)
}

func TestResolveUsers(t *testing.T) {
	tA := tok('a')
	tB := tok('b')

	t.Run("single user via config file", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: tA}}}
		users, problems, err := resolveUsers(cfg)
		if err != nil || len(problems) != 0 {
			t.Fatalf("got users=%v problems=%v err=%v, want success", users, problems, err)
		}
		if len(users) != 1 || users[0].Name != "alice" {
			t.Errorf("got %+v, want single alice user", users)
		}
	})

	t.Run("multiple users via config file", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: tA}, {Name: "bob", Token: tB}}}
		users, problems, err := resolveUsers(cfg)
		if err != nil || len(problems) != 0 {
			t.Fatalf("got problems=%v err=%v, want success", problems, err)
		}
		if len(users) != 2 {
			t.Errorf("got %d users, want 2", len(users))
		}
	})

	t.Run("single user via environment pair", func(t *testing.T) {
		cfg := Config{envToken: tA, envUsername: "laptop"}
		users, problems, err := resolveUsers(cfg)
		if err != nil || len(problems) != 0 {
			t.Fatalf("got problems=%v err=%v, want success", problems, err)
		}
		if len(users) != 1 || users[0].Name != "laptop" || users[0].Token != tA {
			t.Errorf("got %+v, want single laptop user", users)
		}
	})

	t.Run("environment pair appended after config-file users", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: tA}}, envToken: tB, envUsername: "bob"}
		users, problems, err := resolveUsers(cfg)
		if err != nil || len(problems) != 0 {
			t.Fatalf("got problems=%v err=%v, want success", problems, err)
		}
		if len(users) != 2 || users[0].Name != "alice" || users[1].Name != "bob" {
			t.Errorf("got %+v, want alice then bob (env appended last)", users)
		}
	})

	t.Run("no users configured", func(t *testing.T) {
		cfg := Config{}
		_, problems, err := resolveUsers(cfg)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if len(problems) == 0 {
			t.Fatal("want a structural problem when no users are configured")
		}
	})

	t.Run("AGED_USERNAME without AGED_TOKEN refused", func(t *testing.T) {
		cfg := Config{envUsername: "laptop"}
		_, _, err := resolveUsers(cfg)
		if err == nil || !strings.Contains(err.Error(), "AGED_TOKEN") {
			t.Fatalf("got err=%v, want an error naming AGED_TOKEN as missing", err)
		}
	})

	t.Run("AGED_TOKEN without AGED_USERNAME refused", func(t *testing.T) {
		cfg := Config{envToken: tA}
		_, _, err := resolveUsers(cfg)
		if err == nil || !strings.Contains(err.Error(), "AGED_USERNAME") {
			t.Fatalf("got err=%v, want an error naming AGED_USERNAME as missing", err)
		}
	})

	t.Run("duplicate token rejected", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: tA}, {Name: "bob", Token: tA}}}
		_, problems, err := resolveUsers(cfg)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if !hasProblemMentioning(problems, "alice") || !hasProblemMentioning(problems, "bob") {
			t.Fatalf("got problems=%v, want a problem naming both alice and bob", problems)
		}
	})

	t.Run("duplicate name rejected", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: tA}, {Name: "alice", Token: tB}}}
		_, problems, err := resolveUsers(cfg)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if !hasProblemMentioning(problems, "alice") {
			t.Fatalf("got problems=%v, want a problem naming alice", problems)
		}
	})

	t.Run("case-insensitive duplicate name rejected", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: tA}, {Name: "Alice", Token: tB}}}
		_, problems, err := resolveUsers(cfg)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if len(problems) == 0 {
			t.Fatal("want a problem for case-insensitive duplicate names")
		}
	})

	t.Run("invalid name rejected", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "-bad", Token: tA}}}
		_, problems, err := resolveUsers(cfg)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if !hasProblemMentioning(problems, "-bad") {
			t.Fatalf("got problems=%v, want a problem naming -bad", problems)
		}
	})

	t.Run("malformed token rejected", func(t *testing.T) {
		cfg := Config{Users: []UserConfig{{Name: "alice", Token: "short"}}}
		_, problems, err := resolveUsers(cfg)
		if err != nil {
			t.Fatalf("unexpected hard error: %v", err)
		}
		if len(problems) == 0 || problems[0].category != problemTokenFormat {
			t.Fatalf("got problems=%v, want a tokenFormat problem", problems)
		}
	})
}

func hasProblemMentioning(problems []userProblem, s string) bool {
	for _, p := range problems {
		if strings.Contains(p.message, s) {
			return true
		}
	}
	return false
}
