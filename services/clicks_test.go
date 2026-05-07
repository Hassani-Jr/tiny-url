package services

import (
	"strings"
	"testing"
)

func TestClassifyUserAgent(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want string
	}{
		{"empty", "", "unknown"},
		{"googlebot", "Googlebot/2.1 (+http://www.google.com/bot.html)", "bot"},
		{"curl", "curl/7.86.0", "bot"},
		{"python", "python-requests/2.28.1", "bot"},
		{"iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1.15", "mobile"},
		{"android mobile", "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile Safari/537.36", "mobile"},
		{"ipad", "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15", "tablet"},
		{"firefox desktop", "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0", "desktop"},
		{"unknown junk", "totally-made-up-agent/1.0", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyUserAgent(tc.ua); got != tc.want {
				t.Errorf("ClassifyUserAgent(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

func TestHashIPDeterministicWithSameSalt(t *testing.T) {
	SetClickSalt("fixed-salt-for-test")
	a := HashIP("203.0.113.5")
	b := HashIP("203.0.113.5")
	if a != b {
		t.Errorf("hash should be stable for same input+salt: %s vs %s", a, b)
	}
	if HashIP("") != "" {
		t.Errorf("HashIP(\"\") must return \"\"")
	}
}

func TestHashIPDifferentSaltDifferentHash(t *testing.T) {
	SetClickSalt("salt-A")
	a := HashIP("203.0.113.5")
	SetClickSalt("salt-B")
	b := HashIP("203.0.113.5")
	if a == b {
		t.Errorf("hashes under different salts must differ")
	}
}

func TestTruncateReferer(t *testing.T) {
	long := strings.Repeat("x", MaxRefererLength+50)
	got := TruncateReferer(long)
	if len(got) != MaxRefererLength {
		t.Errorf("len = %d, want %d", len(got), MaxRefererLength)
	}
	short := "https://example.com/"
	if TruncateReferer(short) != short {
		t.Errorf("short input must be returned unchanged")
	}
}
