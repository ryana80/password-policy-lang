package policy

import (
	"math"
	"unicode"
)

// Strength is a human-readable bucket for an entropy estimate. The
// boundaries follow the widely used rule of thumb that below 28 bits a
// password falls to an offline brute-force attempt in seconds on
// commodity hardware, and above 128 bits it's effectively unguessable.
type Strength int

const (
	StrengthVeryWeak Strength = iota
	StrengthWeak
	StrengthFair
	StrengthStrong
	StrengthVeryStrong
)

func (s Strength) String() string {
	switch s {
	case StrengthVeryWeak:
		return "very weak"
	case StrengthWeak:
		return "weak"
	case StrengthFair:
		return "fair"
	case StrengthStrong:
		return "strong"
	case StrengthVeryStrong:
		return "very strong"
	default:
		return "unknown"
	}
}

// Score is an entropy-based estimate of a password's resistance to
// brute-force guessing, independent of whether it satisfies any policy.
type Score struct {
	// Entropy is bits of entropy, computed as length * log2(pool size),
	// where pool size is the size of the character set a brute-force
	// attacker would have to search given the classes actually present
	// (lowercase, uppercase, digit, or everything else). This assumes the
	// password was drawn uniformly from that pool, so it does not catch
	// low-entropy-in-practice passwords built from dictionary words or
	// predictable substitutions; it only bounds the size of the search
	// space implied by the alphabet and length.
	Entropy float64

	Strength Strength
}

// EstimateStrength scores a password by entropy. A short password can
// still land in a "strong" bucket if it draws from a large pool, and a
// long one built from a single character class can land in "weak", which
// is why this is reported separately from Check's pass/fail rules rather
// than folded into them.
func EstimateStrength(password string) Score {
	runes := []rune(password)
	if len(runes) == 0 {
		return Score{Entropy: 0, Strength: StrengthVeryWeak}
	}

	pool := passwordPoolSize(runes)
	entropy := float64(len(runes)) * math.Log2(float64(pool))
	return Score{Entropy: entropy, Strength: rateEntropy(entropy)}
}

func passwordPoolSize(runes []rune) int {
	var hasUpper, hasLower, hasDigit, hasOther bool
	for _, r := range runes {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}

	pool := 0
	if hasLower {
		pool += 26
	}
	if hasUpper {
		pool += 26
	}
	if hasDigit {
		pool += 10
	}
	if hasOther {
		// printable ASCII punctuation and space; an undercount for
		// passwords that lean on non-ASCII characters, but treating those
		// as part of the same catch-all bucket keeps the estimate simple
		// and still conservative for the common case.
		pool += 33
	}
	if pool == 0 {
		pool = 1
	}
	return pool
}

func rateEntropy(bits float64) Strength {
	switch {
	case bits < 28:
		return StrengthVeryWeak
	case bits < 36:
		return StrengthWeak
	case bits < 60:
		return StrengthFair
	case bits < 128:
		return StrengthStrong
	default:
		return StrengthVeryStrong
	}
}
