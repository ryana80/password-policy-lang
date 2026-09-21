package policy

import "testing"

func TestFormatCanonicalOrder(t *testing.T) {
	pol := &Policy{
		MinLength: 12,
		MaxLength: 128,
		Require:   []CharClass{ClassSymbol, ClassUpper, ClassLower}, // deliberately unsorted
		Forbid:    []Rule{RuleWhitespace, RuleSequence, RuleRepeat}, // deliberately unsorted
	}
	want := "min_length 12\nmax_length 128\nrequire lower, symbol, upper\nforbid repeat\nforbid sequence\nforbid whitespace\n"
	if got := Format(pol); got != want {
		t.Errorf("Format() = %q, want %q", got, want)
	}
}

func TestFormatOmitsUnsetFields(t *testing.T) {
	pol := &Policy{MinLength: 8}
	want := "min_length 8\n"
	if got := Format(pol); got != want {
		t.Errorf("Format() = %q, want %q", got, want)
	}
}

func TestFormatQuotesSymbols(t *testing.T) {
	pol := &Policy{Symbols: `a"b\c`}
	want := "symbols \"a\\\"b\\\\c\"\n"
	if got := Format(pol); got != want {
		t.Errorf("Format() = %q, want %q", got, want)
	}
}

func TestFormatSymbolsIsIdempotentThroughParse(t *testing.T) {
	src := `symbols "!@#$%^&*()"` + "\nrequire symbol\n"
	pol, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	formatted := Format(pol)

	reparsed, err := Parse(formatted)
	if err != nil {
		t.Fatalf("Parse(Format(pol)): %v", err)
	}
	if reparsed.Symbols != pol.Symbols {
		t.Errorf("Symbols = %q, want %q", reparsed.Symbols, pol.Symbols)
	}
	if Format(reparsed) != formatted {
		t.Errorf("formatting is not idempotent: %q != %q", Format(reparsed), formatted)
	}
}

func TestFormatIsIdempotentThroughParse(t *testing.T) {
	src := "require symbol, upper\nforbid whitespace\nforbid repeat\nmin_length 10\n"
	pol, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	formatted := Format(pol)

	reparsed, err := Parse(formatted)
	if err != nil {
		t.Fatalf("Parse(Format(pol)): %v", err)
	}
	if Format(reparsed) != formatted {
		t.Errorf("formatting is not idempotent: %q != %q", Format(reparsed), formatted)
	}
}

func TestCheckAccepts(t *testing.T) {
	pol, err := Parse("min_length 8\nrequire upper, lower, digit, symbol\nforbid whitespace\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if v := Check(pol, "Tr0ub4dor&3"); len(v) != 0 {
		t.Errorf("Check() = %v, want no violations", v)
	}
}

func TestCheckLength(t *testing.T) {
	pol := &Policy{MinLength: 8, MaxLength: 10}

	if v := Check(pol, "short"); len(v) != 1 || v[0].Reason != "must be at least 8 characters (got 5)" {
		t.Errorf("too short: got %v", v)
	}
	if v := Check(pol, "way too long!"); len(v) != 1 || v[0].Reason != "must be at most 10 characters (got 13)" {
		t.Errorf("too long: got %v", v)
	}
	if v := Check(pol, "just right"); len(v) != 0 {
		t.Errorf("in range: got %v, want none", v)
	}
}

func TestCheckRequiredClasses(t *testing.T) {
	pol := &Policy{Require: []CharClass{ClassUpper, ClassLower, ClassDigit, ClassSymbol}}

	v := Check(pol, "password")
	want := map[string]bool{
		"must contain at least one upper character":  true,
		"must contain at least one digit character":  true,
		"must contain at least one symbol character": true,
	}
	if len(v) != 3 {
		t.Fatalf("Check(%q) = %v, want 3 violations", "password", v)
	}
	for _, got := range v {
		if !want[got.Reason] {
			t.Errorf("unexpected violation %q", got.Reason)
		}
	}

	if v := Check(pol, "Passw0rd!"); len(v) != 0 {
		t.Errorf("Check() = %v, want no violations", v)
	}
}

func TestCheckForbidWhitespace(t *testing.T) {
	pol := &Policy{Forbid: []Rule{RuleWhitespace}}

	if v := Check(pol, "has a space"); len(v) != 1 || v[0].Reason != "must not contain whitespace" {
		t.Errorf("got %v", v)
	}
	if v := Check(pol, "nospaces"); len(v) != 0 {
		t.Errorf("got %v, want none", v)
	}
}

func TestCheckForbidRepeat(t *testing.T) {
	pol := &Policy{Forbid: []Rule{RuleRepeat}}

	if v := Check(pol, "aaabbb"); len(v) != 1 {
		t.Errorf("got %v, want one violation", v)
	}
	if v := Check(pol, "aabbcc"); len(v) != 0 {
		t.Errorf("got %v, want none (runs of 2 are fine)", v)
	}
}

func TestCheckForbidSequence(t *testing.T) {
	pol := &Policy{Forbid: []Rule{RuleSequence}}

	if v := Check(pol, "userabc123"); len(v) != 1 {
		t.Errorf("ascending: got %v, want one violation", v)
	}
	if v := Check(pol, "user321"); len(v) != 1 {
		t.Errorf("descending: got %v, want one violation", v)
	}
	if v := Check(pol, "userxzq"); len(v) != 0 {
		t.Errorf("no run: got %v, want none", v)
	}
}

func TestCheckRequireSymbolWithCustomSet(t *testing.T) {
	pol := &Policy{Symbols: "!@#", Require: []CharClass{ClassSymbol}}

	if v := Check(pol, "pass!word"); len(v) != 0 {
		t.Errorf("'!' is in the symbol set: got %v, want none", v)
	}
	if v := Check(pol, "pass/word"); len(v) != 1 || v[0].Reason != "must contain at least one symbol character" {
		t.Errorf("'/' is not in the symbol set: got %v", v)
	}
}

func TestCheckReportsAllViolationsTogether(t *testing.T) {
	pol := &Policy{
		MinLength: 12,
		Require:   []CharClass{ClassUpper, ClassDigit, ClassSymbol},
		Forbid:    []Rule{RuleWhitespace},
	}
	v := Check(pol, "bad pass")
	if len(v) != 5 {
		t.Fatalf("Check() = %v, want 5 violations (length, upper, digit, symbol, whitespace)", v)
	}
}
