package services

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDenyListContains(t *testing.T) {
	dl := NewDenyList([]string{
		"evil.com",
		"  Phishing.NET ",     // mixed case + whitespace → normalised
		"*.lookalike.example", // common feed format → "lookalike.example"
		".badtld",             // dotted prefix → "badtld"
		"# this is a comment", // skipped
		"",                    // skipped
		"203.0.113.7",         // IP literal
	})

	cases := []struct {
		host string
		want bool
	}{
		{"evil.com", true},
		{"sub.evil.com", true},
		{"deep.sub.evil.com", true},
		{"EVIL.COM", true}, // case-insensitive
		{"phishing.net", true},
		{"a.phishing.net", true},
		{"lookalike.example", true},
		{"www.lookalike.example", true},
		{"badtld", true},
		{"x.badtld", true},
		{"203.0.113.7", true},
		// Negatives
		{"good.com", false},
		{"example.com", false},
		{"notevil.com", false},
		{"prefix-evil.com", false}, // not a subdomain — must follow a literal '.'
		{"", false},
		{"203.0.113.8", false},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got := dl.Contains(tc.host)
			if got != tc.want {
				t.Errorf("Contains(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestDenyListNilSafe(t *testing.T) {
	var dl *DenyList
	if dl.Contains("anything.com") {
		t.Errorf("nil deny-list must report Contains=false")
	}
	if dl.Size() != 0 {
		t.Errorf("nil deny-list must report Size=0")
	}
}

func TestNewDenyListEmptyReturnsNil(t *testing.T) {
	if NewDenyList(nil) != nil {
		t.Errorf("NewDenyList(nil) must return nil so callers can short-circuit")
	}
	if NewDenyList([]string{"", "  ", "# comment"}) != nil {
		t.Errorf("NewDenyList of all-skip entries must return nil")
	}
}

func TestLoadDenyListFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "deny.txt")
	body := "# malware feed\nevil.com\n\n*.phishy.example\n   spaced.com  \n"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	dl, err := LoadDenyListFile(tmp)
	if err != nil {
		t.Fatalf("LoadDenyListFile: %v", err)
	}
	if !dl.Contains("evil.com") || !dl.Contains("a.phishy.example") || !dl.Contains("spaced.com") {
		t.Errorf("expected entries missing: size=%d", dl.Size())
	}
}

func TestLoadDenyListFileEmptyPath(t *testing.T) {
	dl, err := LoadDenyListFile("")
	if err != nil {
		t.Errorf("empty path should not error, got %v", err)
	}
	if dl != nil {
		t.Errorf("empty path should return nil deny-list, got size=%d", dl.Size())
	}
}

func TestLoadDenyListFileMissing(t *testing.T) {
	_, err := LoadDenyListFile(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Errorf("missing file should error so misconfiguration fails loud")
	}
}

func TestMergeDenyLists(t *testing.T) {
	a := NewDenyList([]string{"a.com"})
	b := NewDenyList([]string{"b.com"})
	merged := MergeDenyLists(a, nil, b)
	if !merged.Contains("a.com") || !merged.Contains("b.com") {
		t.Errorf("merged list missing entries: size=%d", merged.Size())
	}
	if MergeDenyLists(nil, nil) != nil {
		t.Errorf("merge of all-nil must return nil")
	}
}

func TestValidateDestinationURLDeniesListedHost(t *testing.T) {
	dl := NewDenyList([]string{"evil.com"})
	// Use a subdomain so the IP check doesn't trigger first
	err := ValidateDestinationURL("https://sub.evil.com/path", dl)
	if err == nil {
		t.Fatal("expected denial, got nil error")
	}
	if !errorIsDeniedHost(err) {
		t.Errorf("error %v should wrap ErrDeniedHost", err)
	}
}

// helper avoids importing errors here
func errorIsDeniedHost(err error) bool {
	for e := err; e != nil; {
		if e == ErrDeniedHost {
			return true
		}
		type wrapped interface{ Unwrap() error }
		if w, ok := e.(wrapped); ok {
			e = w.Unwrap()
			continue
		}
		break
	}
	return false
}
