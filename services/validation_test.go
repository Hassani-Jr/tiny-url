package services

import (
	"testing"
)

func TestValidateDestinationURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Valid URLs — IP literals so the test is independent of /etc/hosts
		// and the local resolver. example.com on dev machines often points at
		// 127.0.0.1 via a hosts entry, which would (correctly) fail the SSRF
		// guard and fail the test for an unrelated reason.
		{
			name:    "valid https url",
			url:     "https://1.1.1.1",
			wantErr: false,
		},
		{
			name:    "valid http url",
			url:     "http://8.8.8.8",
			wantErr: false,
		},
		{
			name:    "valid url with path",
			url:     "https://1.1.1.1/path/to/page",
			wantErr: false,
		},
		{
			name:    "valid url with query",
			url:     "https://1.1.1.1/page?foo=bar&baz=qux",
			wantErr: false,
		},
		{
			name:    "valid url with fragment",
			url:     "https://1.1.1.1/page#section",
			wantErr: false,
		},
		{
			name:    "valid public ip",
			url:     "https://8.8.8.8",
			wantErr: false,
		},

		// Invalid schemes
		{
			name:    "javascript scheme",
			url:     "javascript:alert(1)",
			wantErr: true,
			errMsg:  "scheme",
		},
		{
			name:    "data scheme",
			url:     "data:text/html,<script>alert(1)</script>",
			wantErr: true,
			errMsg:  "scheme",
		},
		{
			name:    "ftp scheme",
			url:     "ftp://example.com",
			wantErr: true,
			errMsg:  "scheme",
		},
		{
			name:    "file scheme",
			url:     "file:///etc/passwd",
			wantErr: true,
			errMsg:  "scheme",
		},

		// SSRF: Loopback
		{
			name:    "loopback 127.0.0.1",
			url:     "http://127.0.0.1/admin",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "loopback 127.0.0.2",
			url:     "http://127.0.0.2",
			wantErr: true,
			errMsg:  "loopback",
		},
		{
			name:    "localhost hostname",
			url:     "http://localhost/admin",
			wantErr: true,
			errMsg:  "loopback",
		},

		// SSRF: Private ranges
		{
			name:    "private 10.0.0.0/8",
			url:     "http://10.0.0.1",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "private 10.255.255.255",
			url:     "http://10.255.255.255",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "private 172.16.0.0/12",
			url:     "http://172.16.0.1",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "private 172.31.255.255",
			url:     "http://172.31.255.255",
			wantErr: true,
			errMsg:  "private",
		},
		{
			name:    "private 192.168.0.0/16",
			url:     "http://192.168.0.1",
			wantErr: true,
			errMsg:  "private",
		},

		// SSRF: Link-local (169.254.0.0/16)
		{
			name:    "link-local 169.254.0.1",
			url:     "http://169.254.0.1",
			wantErr: true,
			errMsg:  "link-local",
		},
		{
			name:    "AWS metadata 169.254.169.254",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
			errMsg:  "link-local",
		},

		// SSRF: Multicast (224.0.0.0/4)
		{
			name:    "multicast 224.0.0.1",
			url:     "http://224.0.0.1",
			wantErr: true,
			errMsg:  "multicast",
		},

		// SSRF: CGNAT (100.64.0.0/10)
		{
			name:    "cgnat 100.64.0.1",
			url:     "http://100.64.0.1",
			wantErr: true,
			errMsg:  "cgnat",
		},

		// Length validation
		{
			name:    "url too long",
			url:     "https://example.com/" + string(make([]byte, 2100)),
			wantErr: true,
			errMsg:  "length",
		},

		// Credentials in URL — IP literal so userinfo check fires before
		// host resolution would have a chance to also reject the host.
		{
			name:    "url with embedded username",
			url:     "http://user@1.1.1.1",
			wantErr: true,
			errMsg:  "credentials",
		},
		{
			name:    "url with embedded credentials",
			url:     "http://user:pass@1.1.1.1",
			wantErr: true,
			errMsg:  "credentials",
		},

		// Malformed URLs
		{
			name:    "missing scheme",
			url:     "example.com",
			wantErr: true,
			errMsg:  "scheme",
		},
		{
			name:    "empty url",
			url:     "",
			wantErr: true,
			errMsg:  "scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDestinationURL(tt.url, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDestinationURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !containsSubstring(err.Error(), tt.errMsg) {
					t.Errorf("ValidateDestinationURL() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestValidateCustomCode(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantErr bool
		errMsg  string
	}{
		// Valid codes
		{
			name:    "simple alphanumeric",
			code:    "abc123",
			wantErr: false,
		},
		{
			name:    "with underscore",
			code:    "my_link",
			wantErr: false,
		},
		{
			name:    "with hyphen",
			code:    "my-link",
			wantErr: false,
		},
		{
			name:    "mixed case",
			code:    "MyLink123",
			wantErr: false,
		},
		{
			name:    "minimum length",
			code:    "abc",
			wantErr: false,
		},
		{
			name:    "maximum length",
			code:    "abcdefghijklmnopqrstuvwxyz123456", // 32 chars
			wantErr: false,
		},
		{
			name:    "all numbers",
			code:    "123456",
			wantErr: false,
		},
		{
			name:    "all underscores and hyphens",
			code:    "___---",
			wantErr: false,
		},

		// Invalid: Too short
		{
			name:    "too short 1 char",
			code:    "a",
			wantErr: true,
			errMsg:  "3-32",
		},
		{
			name:    "too short 2 chars",
			code:    "ab",
			wantErr: true,
			errMsg:  "3-32",
		},

		// Invalid: Too long
		{
			name:    "too long 33 chars",
			code:    "abcdefghijklmnopqrstuvwxyz1234567",
			wantErr: true,
			errMsg:  "3-32",
		},

		// Invalid: Invalid characters
		{
			name:    "contains space",
			code:    "my link",
			wantErr: true,
			errMsg:  "alphanumeric",
		},
		{
			name:    "contains special char @",
			code:    "my@link",
			wantErr: true,
			errMsg:  "alphanumeric",
		},
		{
			name:    "contains special char .",
			code:    "my.link",
			wantErr: true,
			errMsg:  "alphanumeric",
		},
		{
			name:    "contains special char /",
			code:    "my/link",
			wantErr: true,
			errMsg:  "alphanumeric",
		},
		{
			name:    "contains unicode",
			code:    "mycafé",
			wantErr: true,
			errMsg:  "alphanumeric",
		},

		// Invalid: Reserved words
		{
			name:    "reserved api",
			code:    "api",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "reserved API uppercase",
			code:    "API",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "reserved static",
			code:    "static",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "reserved healthz",
			code:    "healthz",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "reserved favicon.ico",
			code:    "favicon.ico",
			wantErr: true,
			errMsg:  "reserved",
		},
		{
			name:    "reserved robots.txt",
			code:    "robots.txt",
			wantErr: true,
			errMsg:  "reserved",
		},

		// Edge: Empty
		{
			name:    "empty string",
			code:    "",
			wantErr: true,
			errMsg:  "3-32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCustomCode(tt.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCustomCode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !containsSubstring(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCustomCode() error = %q, want substring %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// Helper to check if error message contains substring (case-insensitive)
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
