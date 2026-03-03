package middleware

import "testing"

func TestMatchSkipPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		skip     string
		expected bool
	}{
		{"exact_match", "/api/v1/auth/login", "/api/v1/auth/login", true},
		{"trailing_slash_allowed", "/api/v1/auth/login/", "/api/v1/auth/login", true},
		{"no_prefix_match", "/api/v1/auth/loginxxx", "/api/v1/auth/login", false},
		{"subpath_not_skipped_by_default", "/api/v1/auth/login/extra", "/api/v1/auth/login", false},
		{"explicit_prefix_opt_in", "/api/v1/auth/login/extra", "/api/v1/auth/login/", true},
		{"empty_skip", "/api/v1/auth/login", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSkipPath(tt.path, tt.skip); got != tt.expected {
				t.Fatalf("matchSkipPath(%q, %q) = %v, expected %v", tt.path, tt.skip, got, tt.expected)
			}
		})
	}
}
