package store

import (
	"strings"
	"testing"
)

func TestDefaultTeamDisplayName(t *testing.T) {
	cases := []struct {
		name  string
		email string
		want  string
	}{
		{"simple", "zw4rder@gmail.com", "zw4rder's team"},
		{"dotted local part kept", "john.doe@example.com", "john.doe's team"},
		{"plus tag stripped", "alice+spam@example.com", "alice's team"},
		{"uppercase preserved", "Bob@example.com", "Bob's team"},
		{"no at sign uses whole string", "bob", "bob's team"},
		{"empty local part", "@example.com", ""},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultTeamDisplayName(tc.email); got != tc.want {
				t.Fatalf("defaultTeamDisplayName(%q) = %q, want %q", tc.email, got, tc.want)
			}
		})
	}
}

func TestDefaultTeamDisplayNameClampsTo64Runes(t *testing.T) {
	got := defaultTeamDisplayName(strings.Repeat("a", 80) + "@example.com")
	if n := len([]rune(got)); n > 64 {
		t.Fatalf("display name = %d runes, want <= 64", n)
	}
	if !strings.HasSuffix(got, "'s team") {
		t.Fatalf("want suffix \"'s team\", got %q", got)
	}
}
