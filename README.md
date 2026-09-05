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
- an entropy-based strength estimate, reported alongside the pass/fail
  result, independent of any specific policy

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

## Strength scoring

Alongside pass/fail against a policy, `passpolicy` reports an entropy
estimate: bits = length * log2(pool size), where pool size is the sum of
the character classes actually present (lowercase, uppercase, digit, or
everything else). This bounds the size of the search space a brute-force
attacker faces given the alphabet and length; it does not know that
`password1` is a common credential-stuffing target rather than a random
draw from a 36-character pool, so treat it as a floor on effort, not a
guess at how quickly a real attacker would get in. The estimate is
independent of any policy and is reported even when a password fails one.

| bits    | rating      |
|---------|-------------|
| < 28    | very weak   |
| 28–35   | weak        |
| 36–59   | fair        |
| 60–127  | strong      |
| 128+    | very strong |

## Usage

```
go build -o passpolicy ./cmd/passpolicy

./passpolicy policy.txt 'Tr0ub4dor&3'
ok
strength: 72.3 bits (strong)

./passpolicy policy.txt 'password'
rejected:
  - must be at least 12 characters (got 8)
  - must contain at least one upper character
  - must contain at least one digit character
  - must contain at least one symbol character
strength: 37.6 bits (fair)

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

score := policy.EstimateStrength(candidate)
fmt.Printf("%.1f bits (%s)\n", score.Entropy, score.Strength)
```

## Status

Early. The grammar covers length, required character classes, and a handful
of forbidden patterns, plus an entropy-based strength estimate reported
alongside the pass/fail result. See the issues for what's planned.

## License

MIT, see [LICENSE](LICENSE).
