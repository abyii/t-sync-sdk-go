package storage_clients

import (
	"fmt"
	"slices"
	"strings"
)

// ParseAuthString splits an auth string of the form
//
//	BASE[;key=value[;key=value...]]
//
// into its base auth part and its options. Options may appear in any order;
// keys are case-insensitive (returned lower-cased) and surrounding whitespace is
// trimmed. A ';' inside the base's bracketed argument (e.g. "DEFAULT[...]") does
// not split. Only keys listed in allowed are accepted; malformed segments,
// duplicate keys and unknown keys return ErrInvalidConfig.
func ParseAuthString(auth string, allowed ...string) (base string, opts map[string]string, err error) {
	split := len(auth)
	depth := 0
scan:
	for i := range len(auth) {
		switch auth[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				split = i
				break scan
			}
		}
	}
	base = strings.TrimSpace(auth[:split])
	opts = map[string]string{}
	if split == len(auth) {
		return base, opts, nil
	}
	for _, seg := range strings.Split(auth[split+1:], ";") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		k, v, ok := strings.Cut(seg, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || k == "" {
			return "", nil, fmt.Errorf("%w: malformed auth option %q (want key=value)", ErrInvalidConfig, seg)
		}
		if !slices.Contains(allowed, k) {
			return "", nil, fmt.Errorf("%w: unknown auth option %q", ErrInvalidConfig, k)
		}
		if _, dup := opts[k]; dup {
			return "", nil, fmt.Errorf("%w: duplicate auth option %q", ErrInvalidConfig, k)
		}
		opts[k] = v
	}
	return base, opts, nil
}
