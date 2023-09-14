// Package filter provides helpers for applying all kinds of rules.
package filter

import "github.com/IGLOU-EU/go-wildcard"

// MatchWildcards checks if the string str matches any of the specified
// wildcards.
func MatchWildcards(str string, wildcards []string) (ok bool) {
	for _, w := range wildcards {
		if wildcard.MatchSimple(w, str) {
			return true
		}
	}

	return false
}
