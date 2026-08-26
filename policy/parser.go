// Package policy implements a small language for describing password
// policies, a recursive-descent parser for it that reports errors with
// exact line and column numbers, a canonical pretty printer, and a
// checker that validates passwords against a parsed policy.
package policy

import (
	"fmt"
	"sort"
)

// CharClass is a category of character a policy can require.
type CharClass string

const (
	ClassUpper  CharClass = "upper"
	ClassLower  CharClass = "lower"
	ClassDigit  CharClass = "digit"
	ClassSymbol CharClass = "symbol"
)

var allClasses = map[CharClass]bool{
	ClassUpper:  true,
	ClassLower:  true,
	ClassDigit:  true,
	ClassSymbol: true,
}

// Rule is a pattern a policy can forbid.
type Rule string

const (
	RuleSequence   Rule = "sequence"
	RuleRepeat     Rule = "repeat"
	RuleWhitespace Rule = "whitespace"
)

var allRules = map[Rule]bool{
	RuleSequence:   true,
	RuleRepeat:     true,
	RuleWhitespace: true,
}

// Policy is the parsed, validated form of a password policy document.
type Policy struct {
	MinLength int
	MaxLength int
	Require   []CharClass
	Forbid    []Rule
}

type parser struct {
	lex *lexer
	tok Token
}

// Parse reads a policy document and returns its AST, or the first error
// encountered. Errors are *ParseError and carry line and column
// information; use (*ParseError).Explain to render them against source.
//
// Grammar, one directive per line, blank lines and # comments allowed:
//
//	min_length N
//	max_length N
//	require CLASS[, CLASS...]      upper | lower | digit | symbol
//	forbid RULE                    sequence | repeat | whitespace
func Parse(source string) (*Policy, error) {
	p := &parser{lex: newLexer(source)}
	if err := p.step(); err != nil {
		return nil, err
	}

	pol := &Policy{}
	seen := map[string]Token{}
	seenRules := map[Rule]Token{}

	for p.tok.Kind != TokEOF {
		if p.tok.Kind == TokNewline {
			if err := p.step(); err != nil {
				return nil, err
			}
			continue
		}
		if p.tok.Kind != TokIdent {
			return nil, &ParseError{Line: p.tok.Line, Col: p.tok.Col,
				Msg: fmt.Sprintf("expected a directive name, found %s", p.tok.Kind)}
		}

		name := p.tok.Text
		nameTok := p.tok
		if name != "forbid" {
			if prev, ok := seen[name]; ok {
				return nil, &ParseError{Line: nameTok.Line, Col: nameTok.Col,
					Msg: fmt.Sprintf("%q was already set at %d:%d", name, prev.Line, prev.Col)}
			}
		}
		if err := p.step(); err != nil {
			return nil, err
		}

		switch name {
		case "min_length":
			n, err := p.number()
			if err != nil {
				return nil, err
			}
			pol.MinLength = n
			seen[name] = nameTok
		case "max_length":
			n, err := p.number()
			if err != nil {
				return nil, err
			}
			pol.MaxLength = n
			seen[name] = nameTok
		case "require":
			classes, err := p.classList()
			if err != nil {
				return nil, err
			}
			pol.Require = classes
			seen[name] = nameTok
		case "forbid":
			ruleTok := p.tok
			rule, err := p.rule()
			if err != nil {
				return nil, err
			}
			if prev, ok := seenRules[rule]; ok {
				return nil, &ParseError{Line: ruleTok.Line, Col: ruleTok.Col,
					Msg: fmt.Sprintf("forbid %q was already set at %d:%d", rule, prev.Line, prev.Col)}
			}
			seenRules[rule] = ruleTok
			pol.Forbid = append(pol.Forbid, rule)
		default:
			return nil, &ParseError{Line: nameTok.Line, Col: nameTok.Col,
				Msg: fmt.Sprintf("unknown directive %q", name)}
		}

		if err := p.endOfLine(); err != nil {
			return nil, err
		}
	}

	if pol.MaxLength != 0 && pol.MinLength > pol.MaxLength {
		at := seen["min_length"]
		return nil, &ParseError{Line: at.Line, Col: at.Col,
			Msg: fmt.Sprintf("min_length (%d) is greater than max_length (%d)", pol.MinLength, pol.MaxLength)}
	}

	sort.Slice(pol.Require, func(i, j int) bool { return pol.Require[i] < pol.Require[j] })
	sort.Slice(pol.Forbid, func(i, j int) bool { return pol.Forbid[i] < pol.Forbid[j] })

	return pol, nil
}

func (p *parser) step() error {
	tok, err := p.lex.next()
	if err != nil {
		return err
	}
	p.tok = tok
	return nil
}

func (p *parser) number() (int, error) {
	if p.tok.Kind != TokNumber {
		return 0, &ParseError{Line: p.tok.Line, Col: p.tok.Col,
			Msg: fmt.Sprintf("expected a number, found %s", p.tok.Kind)}
	}
	n := 0
	for _, r := range p.tok.Text {
		n = n*10 + int(r-'0')
	}
	if err := p.step(); err != nil {
		return 0, err
	}
	return n, nil
}

func (p *parser) classList() ([]CharClass, error) {
	var out []CharClass
	for {
		if p.tok.Kind != TokIdent {
			return nil, &ParseError{Line: p.tok.Line, Col: p.tok.Col,
				Msg: fmt.Sprintf("expected a character class, found %s", p.tok.Kind)}
		}
		c := CharClass(p.tok.Text)
		if !allClasses[c] {
			return nil, &ParseError{Line: p.tok.Line, Col: p.tok.Col,
				Msg: fmt.Sprintf("unknown character class %q (want upper, lower, digit, or symbol)", p.tok.Text)}
		}
		out = append(out, c)
		if err := p.step(); err != nil {
			return nil, err
		}
		if p.tok.Kind != TokComma {
			break
		}
		if err := p.step(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (p *parser) rule() (Rule, error) {
	if p.tok.Kind != TokIdent {
		return "", &ParseError{Line: p.tok.Line, Col: p.tok.Col,
			Msg: fmt.Sprintf("expected a rule name, found %s", p.tok.Kind)}
	}
	r := Rule(p.tok.Text)
	if !allRules[r] {
		return "", &ParseError{Line: p.tok.Line, Col: p.tok.Col,
			Msg: fmt.Sprintf("unknown rule %q (want sequence, repeat, or whitespace)", p.tok.Text)}
	}
	if err := p.step(); err != nil {
		return "", err
	}
	return r, nil
}

func (p *parser) endOfLine() error {
	if p.tok.Kind != TokNewline && p.tok.Kind != TokEOF {
		return &ParseError{Line: p.tok.Line, Col: p.tok.Col,
			Msg: fmt.Sprintf("expected end of line, found %s", p.tok.Kind)}
	}
	return nil
}
