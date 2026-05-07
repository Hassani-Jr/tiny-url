package services

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrDeniedHost is returned when a destination URL's host (or any of its
// parent domains) appears on the configured deny-list. Callers map this to
// a 400 at create time and a 451 at redirect time.
var ErrDeniedHost = errors.New("URL host is on the deny list")

// DenyList is an immutable set of hostnames whose presence blocks a URL.
// Matches are case-insensitive and apply to subdomains too — an entry
// "evil.com" blocks "evil.com", "a.evil.com" and "deep.b.a.evil.com". This
// is the conservative default that operators want when they paste a phishing
// feed: blocking only the apex while leaving subdomains open would defeat
// the purpose, since attackers spin up disposable subdomains continuously.
//
// A nil *DenyList Contains() always returns false so handlers can be wired
// uniformly whether or not the operator configured a list.
type DenyList struct {
	set map[string]struct{}
}

// NewDenyList builds a DenyList from a slice of hosts. Empty entries and
// lines starting with '#' (comment lines from text files) are ignored.
// Hosts are normalised to lowercase and stripped of leading "*." and "."
// so operators can paste from common feed formats without surprises.
func NewDenyList(entries []string) *DenyList {
	if len(entries) == 0 {
		return nil
	}
	dl := &DenyList{set: make(map[string]struct{})}
	for _, raw := range entries {
		h := normalizeHost(raw)
		if h == "" {
			continue
		}
		dl.set[h] = struct{}{}
	}
	if len(dl.set) == 0 {
		return nil
	}
	return dl
}

// LoadDenyListFile reads a text file with one host per line. Blank lines and
// '#' comment lines are skipped. Returned list is nil-safe (no entries → nil).
// File errors are propagated so a misconfigured path fails loudly at startup
// rather than silently disabling the protection.
func LoadDenyListFile(path string) (*DenyList, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("deny-list file: %w", err)
	}
	defer f.Close()

	var entries []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		entries = append(entries, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("deny-list file: %w", err)
	}
	return NewDenyList(entries), nil
}

// MergeDenyLists returns a new DenyList containing every entry from any of
// the inputs. Nil inputs are skipped. Returns nil if all inputs were nil/empty.
func MergeDenyLists(lists ...*DenyList) *DenyList {
	merged := &DenyList{set: make(map[string]struct{})}
	for _, dl := range lists {
		if dl == nil {
			continue
		}
		for h := range dl.set {
			merged.set[h] = struct{}{}
		}
	}
	if len(merged.set) == 0 {
		return nil
	}
	return merged
}

// Contains reports whether host (or any parent domain of host) is on the
// list. Walking up the labels is O(label-count) per check — typical hosts
// have ≤4 labels — and the per-label lookup is O(1) so a large list of
// thousands of entries stays cheap.
func (d *DenyList) Contains(host string) bool {
	if d == nil || len(d.set) == 0 {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if _, ok := d.set[host]; ok {
		return true
	}
	for {
		idx := strings.Index(host, ".")
		if idx == -1 {
			return false
		}
		host = host[idx+1:]
		if _, ok := d.set[host]; ok {
			return true
		}
	}
}

// Size returns the number of unique entries; useful for startup logging.
func (d *DenyList) Size() int {
	if d == nil {
		return 0
	}
	return len(d.set)
}

func normalizeHost(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" || strings.HasPrefix(h, "#") {
		return ""
	}
	h = strings.ToLower(h)
	// Tolerate common feed formats: "*.evil.com", ".evil.com", "evil.com".
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimPrefix(h, ".")
	return h
}
