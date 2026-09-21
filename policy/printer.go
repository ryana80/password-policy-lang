package policy

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Format renders a Policy back into its canonical textual form: one
// directive per line, in a fixed order, with require's classes and the
// forbid rules sorted. Two documents that parse to the same Policy always
// format identically, which makes the output diff-friendly.
func Format(pol *Policy) string {
	var b strings.Builder

	if pol.MinLength > 0 {
		fmt.Fprintf(&b, "min_length %d\n", pol.MinLength)
	}
	if pol.MaxLength > 0 {
		fmt.Fprintf(&b, "max_length %d\n", pol.MaxLength)
	}
	if pol.Symbols != "" {
		fmt.Fprintf(&b, "symbols %s\n", quoteString(pol.Symbols))
	}
	if len(pol.Require) > 0 {
		classes := make([]string, len(pol.Require))
		for i, c := range pol.Require {
			classes[i] = string(c)
		}
		sort.Strings(classes)
		fmt.Fprintf(&b, "require %s\n", strings.Join(classes, ", "))
	}

	rules := make([]string, len(pol.Forbid))
	for i, r := range pol.Forbid {
		rules[i] = string(r)
	}
	sort.Strings(rules)
	for _, r := range rules {
		fmt.Fprintf(&b, "forbid %s\n", r)
	}

	return b.String()
}

// quoteString renders s as a policy-language string literal, escaping the
// characters that would otherwise end the literal early or need decoding.
func quoteString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Violation describes one way a password fails to satisfy a policy.
type Violation struct {
	Reason string
}

// Check validates a password against a policy and returns every violation
// found, in a fixed order (length, then required classes, then forbidden
// rules). A nil result means the password satisfies the policy.
func Check(pol *Policy, password string) []Violation {
	var violations []Violation
	runes := []rune(password)

	if pol.MinLength > 0 && len(runes) < pol.MinLength {
		violations = append(violations, Violation{
			Reason: fmt.Sprintf("must be at least %d characters (got %d)", pol.MinLength, len(runes)),
		})
	}
	if pol.MaxLength > 0 && len(runes) > pol.MaxLength {
		violations = append(violations, Violation{
			Reason: fmt.Sprintf("must be at most %d characters (got %d)", pol.MaxLength, len(runes)),
		})
	}

	var symbolSet map[rune]bool
	if pol.Symbols != "" {
		symbolSet = make(map[rune]bool, len(pol.Symbols))
		for _, r := range pol.Symbols {
			symbolSet[r] = true
		}
	}

	present := map[CharClass]bool{}
	for _, r := range runes {
		switch {
		case unicode.IsUpper(r):
			present[ClassUpper] = true
		case unicode.IsLower(r):
			present[ClassLower] = true
		case unicode.IsDigit(r):
			present[ClassDigit] = true
		case unicode.IsSpace(r):
			// whitespace is its own forbid rule, not a required class
		default:
			if symbolSet == nil || symbolSet[r] {
				present[ClassSymbol] = true
			}
		}
	}
	for _, c := range pol.Require {
		if !present[c] {
			violations = append(violations, Violation{
				Reason: fmt.Sprintf("must contain at least one %s character", c),
			})
		}
	}

	for _, r := range pol.Forbid {
		switch r {
		case RuleWhitespace:
			for _, c := range runes {
				if unicode.IsSpace(c) {
					violations = append(violations, Violation{Reason: "must not contain whitespace"})
					break
				}
			}
		case RuleRepeat:
			if hasRepeat(runes, 3) {
				violations = append(violations, Violation{Reason: "must not repeat the same character 3 or more times in a row"})
			}
		case RuleSequence:
			if hasSequence(runes, 3) {
				violations = append(violations, Violation{Reason: `must not contain a run of 3 or more characters in order, such as "abc" or "321"`})
			}
		}
	}

	return violations
}

func hasRepeat(runes []rune, n int) bool {
	run := 1
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

func hasSequence(runes []rune, n int) bool {
	ascending, descending := 1, 1
	for i := 1; i < len(runes); i++ {
		switch runes[i] {
		case runes[i-1] + 1:
			ascending++
			descending = 1
		case runes[i-1] - 1:
			descending++
			ascending = 1
		default:
			ascending, descending = 1, 1
		}
		if ascending >= n || descending >= n {
			return true
		}
	}
	return false
}
