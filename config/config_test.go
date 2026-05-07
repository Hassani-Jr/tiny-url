package config

import "testing"

func TestValidateBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"http with host", "http://localhost:8080", false},
		{"https with host", "https://short.example.com", false},
		{"https with path", "https://example.com/proxy", false},
		{"empty", "", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"file scheme", "file:///etc/passwd", true},
		{"protocol-relative", "//evil.com", true},
		{"missing scheme", "localhost:8080", true},
		{"no host", "http://", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBaseURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBaseURL(%q) err=%v, wantErr=%v", tt.raw, err, tt.wantErr)
			}
		})
	}
}
