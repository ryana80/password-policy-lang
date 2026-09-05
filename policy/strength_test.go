package policy

import (
	"math"
	"testing"
)

func TestEstimateStrengthEmpty(t *testing.T) {
	s := EstimateStrength("")
	if s.Entropy != 0 {
		t.Errorf("Entropy = %v, want 0", s.Entropy)
	}
	if s.Strength != StrengthVeryWeak {
		t.Errorf("Strength = %v, want %v", s.Strength, StrengthVeryWeak)
	}
}

func TestEstimateStrengthPoolGrowsWithClasses(t *testing.T) {
	lower := EstimateStrength("abcdefgh")
	mixed := EstimateStrength("abcdefG1")
	if mixed.Entropy <= lower.Entropy {
		t.Errorf("mixed-class entropy %v should exceed single-class entropy %v at equal length", mixed.Entropy, lower.Entropy)
	}
}

func TestEstimateStrengthLongerIsStronger(t *testing.T) {
	short := EstimateStrength("abcdef")
	long := EstimateStrength("abcdefabcdef")
	if long.Entropy <= short.Entropy {
		t.Errorf("longer password entropy %v should exceed shorter %v", long.Entropy, short.Entropy)
	}
}

func TestEstimateStrengthMatchesFormula(t *testing.T) {
	// "abcdefgh" is 8 lowercase-only characters: pool size 26.
	got := EstimateStrength("abcdefgh").Entropy
	want := 8 * math.Log2(26)
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("Entropy = %v, want %v", got, want)
	}
}

func TestRateEntropyBuckets(t *testing.T) {
	tests := []struct {
		bits float64
		want Strength
	}{
		{0, StrengthVeryWeak},
		{27.9, StrengthVeryWeak},
		{28, StrengthWeak},
		{35.9, StrengthWeak},
		{36, StrengthFair},
		{59.9, StrengthFair},
		{60, StrengthStrong},
		{127.9, StrengthStrong},
		{128, StrengthVeryStrong},
	}
	for _, tt := range tests {
		if got := rateEntropy(tt.bits); got != tt.want {
			t.Errorf("rateEntropy(%v) = %v, want %v", tt.bits, got, tt.want)
		}
	}
}

func TestStrengthString(t *testing.T) {
	tests := map[Strength]string{
		StrengthVeryWeak:   "very weak",
		StrengthWeak:       "weak",
		StrengthFair:       "fair",
		StrengthStrong:     "strong",
		StrengthVeryStrong: "very strong",
		Strength(99):       "unknown",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("Strength(%d).String() = %q, want %q", s, got, want)
		}
	}
}
