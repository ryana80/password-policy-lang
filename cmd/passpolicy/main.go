// Command passpolicy parses a password policy document, optionally
// pretty-prints it in canonical form, and checks a password against it.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ryana80/password-policy-lang/policy"
)

// jsonError is the -json error shape, used for both file and parse errors
// so a script never has to branch on which one it got.
type jsonError struct {
	Error string `json:"error"`
	Line  int    `json:"line,omitempty"`
	Col   int    `json:"col,omitempty"`
}

type jsonStrength struct {
	Bits   float64 `json:"bits"`
	Rating string  `json:"rating"`
}

type jsonResult struct {
	OK         bool         `json:"ok"`
	Violations []string     `json:"violations"`
	Strength   jsonStrength `json:"strength"`
}

func main() {
	pretty := flag.Bool("pretty", false, "print the policy back in its canonical form and exit")
	jsonOut := flag.Bool("json", false, "emit machine-readable JSON instead of text")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-pretty] [-json] <policy-file> [password]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		if *jsonOut {
			fail(jsonError{Error: fmt.Sprintf("%s: %v", path, err)})
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		os.Exit(1)
	}
	source := string(data)

	pol, err := policy.Parse(source)
	if err != nil {
		if perr, ok := err.(*policy.ParseError); ok {
			if *jsonOut {
				fail(jsonError{Error: fmt.Sprintf("%s: %s", path, perr.Msg), Line: perr.Line, Col: perr.Col})
			}
			fmt.Fprintf(os.Stderr, "%s:%s\n", path, perr.Explain(source))
			os.Exit(1)
		}
		if *jsonOut {
			fail(jsonError{Error: fmt.Sprintf("%s: %v", path, err)})
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		os.Exit(1)
	}

	if *pretty {
		formatted := policy.Format(pol)
		if *jsonOut {
			printJSON(struct {
				Policy string `json:"policy"`
			}{formatted})
			return
		}
		fmt.Print(formatted)
		return
	}

	var password string
	if len(args) >= 2 {
		password = args[1]
	} else {
		fmt.Fprint(os.Stderr, "password: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			password = scanner.Text()
		}
	}

	score := policy.EstimateStrength(password)
	violations := policy.Check(pol, password)

	if *jsonOut {
		reasons := make([]string, len(violations))
		for i, v := range violations {
			reasons[i] = v.Reason
		}
		printJSON(jsonResult{
			OK:         len(violations) == 0,
			Violations: reasons,
			Strength:   jsonStrength{Bits: score.Entropy, Rating: score.Strength.String()},
		})
		if len(violations) != 0 {
			os.Exit(1)
		}
		return
	}

	if len(violations) == 0 {
		fmt.Println("ok")
		fmt.Printf("strength: %.1f bits (%s)\n", score.Entropy, score.Strength)
		return
	}

	fmt.Println("rejected:")
	for _, v := range violations {
		fmt.Printf("  - %s\n", v.Reason)
	}
	fmt.Printf("strength: %.1f bits (%s)\n", score.Entropy, score.Strength)
	os.Exit(1)
}

// fail writes e as JSON to stderr and exits 1. Errors are always reported
// on stderr regardless of output format, so stdout only ever carries the
// success payload a caller asked for.
func fail(e jsonError) {
	enc := json.NewEncoder(os.Stderr)
	enc.SetIndent("", "  ")
	enc.Encode(e)
	os.Exit(1)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
