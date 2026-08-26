# password-policy-lang

Password policies usually live as prose: a paragraph in a wiki page, a bullet
list in a security review, a comment in an onboarding doc. That's fine until
someone has to implement it, or two teams end up with policies that read the
same but check different things. This is a small text format for writing a
password policy down unambiguously, plus the tools to work with it:

- a parser that validates a policy document and reports errors with exact
  line and column numbers, and a caret pointing at the source
- a pretty printer that reformats any valid policy into one canonical form,
  so two policies that mean the same thing produce the same text
- a checker that runs a password against a parsed policy and explains every
  way it fails, not just the first one

## The language

One directive per line. Blank lines and `#` comments are ignored.

```
# baseline account policy
min_length 12
max_length 128
require upper, lower, digit, symbol
forbid sequence
forbid repeat
forbid whitespace
```

- `min_length N` / `max_length N` — length bounds, each may appear once
- `require CLASS[, CLASS...]` — `upper`, `lower`, `digit`, `symbol`
- `forbid RULE` — `sequence` (e.g. `abc`, `321`), `repeat` (e.g. `aaa`),
  or `whitespace`; may appear multiple times, once per rule

## Usage

```
go build -o passpolicy ./cmd/passpolicy

./passpolicy policy.txt 'Tr0ub4dor&3'
ok

./passpolicy policy.txt 'password'
rejected:
  - must be at least 12 characters (got 8)
  - must contain at least one upper character
  - must contain at least one digit character
  - must contain at least one symbol character

./passpolicy -pretty policy.txt
min_length 12
max_length 128
require digit, lower, symbol, upper
forbid repeat
forbid sequence
forbid whitespace
```

A broken policy document gets a precise, compiler-style error instead of a
generic parse failure:

```
$ cat bad-policy.txt
min_length 12
require upper, lowr, digit

$ ./passpolicy bad-policy.txt secret
bad-policy.txt:2:16: unknown character class "lowr" (want upper, lower, digit, or symbol)
    require upper, lowr, digit
                   ^
```

## Library

The `policy` package has no dependency on the `passpolicy` binary and can be
used directly:

```go
pol, err := policy.Parse(source)
if err != nil {
	if perr, ok := err.(*policy.ParseError); ok {
		fmt.Println(perr.Explain(source))
	}
	return
}

for _, v := range policy.Check(pol, candidate) {
	fmt.Println(v.Reason)
}
```

## Status

Early. The grammar covers length, required character classes, and a handful
of forbidden patterns; there's no notion of password strength scoring yet,
just pass/fail against explicit rules. See the issues for what's planned.

## License

MIT, see [LICENSE](LICENSE).
