package policy

import (
	"strings"
	"testing"
)

func TestParseFullPolicy(t *testing.T) {
	src := `min_length 12
max_length 128
require upper, lower, digit, symbol
forbid sequence
forbid repeat
forbid whitespace
`
	pol, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pol.MinLength != 12 {
		t.Errorf("MinLength = %d, want 12", pol.MinLength)
	}
	if pol.MaxLength != 128 {
		t.Errorf("MaxLength = %d, want 128", pol.MaxLength)
	}
	wantClasses := []CharClass{ClassDigit, ClassLower, ClassSymbol, ClassUpper}
	if !equalClasses(pol.Require, wantClasses) {
		t.Errorf("Require = %v, want %v", pol.Require, wantClasses)
	}
	wantRules := []Rule{RuleRepeat, RuleSequence, RuleWhitespace}
	if !equalRules(pol.Forbid, wantRules) {
		t.Errorf("Forbid = %v, want %v", pol.Forbid, wantRules)
	}
}

func TestParseEmptySource(t *testing.T) {
	pol, err := Parse("")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pol.MinLength != 0 || pol.MaxLength != 0 || len(pol.Require) != 0 || len(pol.Forbid) != 0 {
		t.Errorf("Parse(\"\") = %+v, want zero value", pol)
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	src := `# baseline account policy

min_length 8   # inline comment doesn't matter, whole line does
# another comment

require lower
`
	pol, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pol.MinLength != 8 {
		t.Errorf("MinLength = %d, want 8", pol.MinLength)
	}
	if !equalClasses(pol.Require, []CharClass{ClassLower}) {
		t.Errorf("Require = %v, want [lower]", pol.Require)
	}
}

func TestParseDirectiveOrderDoesNotMatterForOutput(t *testing.T) {
	src := "require symbol, upper\nforbid whitespace\nforbid repeat\n"
	pol, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !equalClasses(pol.Require, []CharClass{ClassSymbol, ClassUpper}) {
		t.Errorf("Require = %v, want sorted [symbol upper]", pol.Require)
	}
	if !equalRules(pol.Forbid, []Rule{RuleRepeat, RuleWhitespace}) {
		t.Errorf("Forbid = %v, want sorted [repeat whitespace]", pol.Forbid)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		wantLine int
		wantCol  int
		wantMsg  string
	}{
		{
			name:     "unexpected character",
			src:      "$\n",
			wantLine: 1, wantCol: 1,
			wantMsg: `unexpected character '$'`,
		},
		{
			name:     "unknown directive",
			src:      "foo 1\n",
			wantLine: 1, wantCol: 1,
			wantMsg: `unknown directive "foo"`,
		},
		{
			name:     "min_length wants a number",
			src:      "min_length ten\n",
			wantLine: 1, wantCol: 12,
			wantMsg: `expected a number, found identifier`,
		},
		{
			name:     "unknown character class",
			src:      "min_length 12\nrequire upper, lowr, digit\n",
			wantLine: 2, wantCol: 16,
			wantMsg: `unknown character class "lowr" (want upper, lower, digit, or symbol)`,
		},
		{
			name:     "trailing comma in require list",
			src:      "require upper,\n",
			wantLine: 1, wantCol: 15,
			wantMsg: `expected a character class, found newline`,
		},
		{
			name:     "unknown forbid rule",
			src:      "forbid nonsense\n",
			wantLine: 1, wantCol: 8,
			wantMsg: `unknown rule "nonsense" (want sequence, repeat, or whitespace)`,
		},
		{
			name:     "duplicate min_length",
			src:      "min_length 8\nmin_length 10\n",
			wantLine: 2, wantCol: 1,
			wantMsg: `"min_length" was already set at 1:1`,
		},
		{
			name:     "duplicate require",
			src:      "require upper\nrequire lower\n",
			wantLine: 2, wantCol: 1,
			wantMsg: `"require" was already set at 1:1`,
		},
		{
			name:     "duplicate forbid rule",
			src:      "forbid repeat\nforbid repeat\n",
			wantLine: 2, wantCol: 8,
			wantMsg: `forbid "repeat" was already set at 1:8`,
		},
		{
			name:     "trailing tokens after directive",
			src:      "min_length 12 13\n",
			wantLine: 1, wantCol: 15,
			wantMsg: `expected end of line, found number`,
		},
		{
			name:     "min_length greater than max_length",
			src:      "min_length 20\nmax_length 10\n",
			wantLine: 1, wantCol: 1,
			wantMsg: `min_length (20) is greater than max_length (10)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.src)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", tt.src)
			}
			perr, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error is %T, want *ParseError", err)
			}
			if perr.Line != tt.wantLine || perr.Col != tt.wantCol {
				t.Errorf("position = %d:%d, want %d:%d", perr.Line, perr.Col, tt.wantLine, tt.wantCol)
			}
			if perr.Msg != tt.wantMsg {
				t.Errorf("message = %q, want %q", perr.Msg, tt.wantMsg)
			}
		})
	}
}

func TestParseErrorExplainRendersCaret(t *testing.T) {
	src := "min_length 12\nrequire upper, lowr, digit\n"
	_, err := Parse(src)
	perr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error is %T, want *ParseError", err)
	}

	got := perr.Explain(src)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("Explain produced %d lines, want 3:\n%s", len(lines), got)
	}
	if lines[1] != "    require upper, lowr, digit" {
		t.Errorf("source line = %q", lines[1])
	}
	wantCaret := "    " + strings.Repeat(" ", perr.Col-1) + "^"
	if lines[2] != wantCaret {
		t.Errorf("caret line = %q, want %q", lines[2], wantCaret)
	}
}

func equalClasses(a, b []CharClass) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalRules(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
