package policy

import (
	"fmt"
	"strings"
)

// TokenKind identifies the lexical class of a Token.
type TokenKind int

const (
	TokEOF TokenKind = iota
	TokIdent
	TokNumber
	TokString
	TokComma
	TokNewline
)

func (k TokenKind) String() string {
	switch k {
	case TokEOF:
		return "end of input"
	case TokIdent:
		return "identifier"
	case TokNumber:
		return "number"
	case TokString:
		return "quoted string"
	case TokComma:
		return "comma"
	case TokNewline:
		return "newline"
	default:
		return "unknown token"
	}
}

// Token is a single lexical unit from a policy document, tagged with the
// 1-based line and column of its first rune.
type Token struct {
	Kind TokenKind
	Text string
	Line int
	Col  int
}

// ParseError reports a problem found while lexing or parsing a policy
// document. Line and Col are 1-based and point at the rune at fault.
type ParseError struct {
	Line int
	Col  int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%d:%d: %s", e.Line, e.Col, e.Msg)
}

// Explain renders the error together with the offending source line and a
// caret under the exact column, the way a compiler diagnostic would.
func (e *ParseError) Explain(source string) string {
	lines := strings.Split(source, "\n")
	if e.Line < 1 || e.Line > len(lines) {
		return e.Error()
	}
	line := lines[e.Line-1]
	pad := e.Col - 1
	if pad < 0 {
		pad = 0
	}
	if pad > len(line) {
		pad = len(line)
	}
	caret := strings.Repeat(" ", pad) + "^"
	return fmt.Sprintf("%d:%d: %s\n    %s\n    %s", e.Line, e.Col, e.Msg, line, caret)
}

// lexer turns policy source text into a stream of tokens. It tracks line
// and column by hand rather than counting bytes after the fact, so every
// token (and every lexical error) carries an exact position.
type lexer struct {
	src  []rune
	pos  int
	line int
	col  int
}

func newLexer(source string) *lexer {
	return &lexer{src: []rune(source), pos: 0, line: 1, col: 1}
}

func (l *lexer) peek() rune {
	if l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}

func (l *lexer) advance() rune {
	r := l.src[l.pos]
	l.pos++
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

func isIdentStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || (r >= '0' && r <= '9')
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// stringToken scans a double-quoted string starting after the opening
// quote has been peeked but not yet consumed. It recognizes \", \\, \n,
// and \t; any other backslash escape is an error. A string may not span
// a newline, so an unterminated string is always caught before it can
// swallow the rest of the document.
func (l *lexer) stringToken(line, col int) (Token, error) {
	l.advance() // opening quote
	var sb strings.Builder
	for {
		c := l.peek()
		if c == 0 || c == '\n' {
			return Token{}, &ParseError{Line: line, Col: col, Msg: "unterminated string"}
		}
		if c == '"' {
			l.advance()
			return Token{Kind: TokString, Text: sb.String(), Line: line, Col: col}, nil
		}
		if c == '\\' {
			escLine, escCol := l.line, l.col
			l.advance()
			esc := l.peek()
			if esc == 0 || esc == '\n' {
				return Token{}, &ParseError{Line: line, Col: col, Msg: "unterminated string"}
			}
			switch esc {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			default:
				return Token{}, &ParseError{Line: escLine, Col: escCol, Msg: fmt.Sprintf("unknown escape sequence \\%c", esc)}
			}
			l.advance()
			continue
		}
		sb.WriteRune(c)
		l.advance()
	}
}

// next returns the next token, or an error if the input contains a
// character that cannot begin any valid token. Comments (# to end of
// line) and horizontal whitespace are skipped; newlines are significant,
// since each directive occupies exactly one line.
func (l *lexer) next() (Token, error) {
	for {
		r := l.peek()
		if r == ' ' || r == '\t' || r == '\r' {
			l.advance()
			continue
		}
		if r == '#' {
			for l.peek() != '\n' && l.peek() != 0 {
				l.advance()
			}
			continue
		}
		break
	}

	line, col := l.line, l.col
	r := l.peek()

	switch {
	case r == 0:
		return Token{Kind: TokEOF, Line: line, Col: col}, nil
	case r == '\n':
		l.advance()
		return Token{Kind: TokNewline, Text: "\n", Line: line, Col: col}, nil
	case r == ',':
		l.advance()
		return Token{Kind: TokComma, Text: ",", Line: line, Col: col}, nil
	case isDigit(r):
		start := l.pos
		for isDigit(l.peek()) {
			l.advance()
		}
		return Token{Kind: TokNumber, Text: string(l.src[start:l.pos]), Line: line, Col: col}, nil
	case isIdentStart(r):
		start := l.pos
		for isIdentPart(l.peek()) {
			l.advance()
		}
		return Token{Kind: TokIdent, Text: string(l.src[start:l.pos]), Line: line, Col: col}, nil
	case r == '"':
		return l.stringToken(line, col)
	default:
		l.advance()
		return Token{}, &ParseError{Line: line, Col: col, Msg: fmt.Sprintf("unexpected character %q", r)}
	}
}
