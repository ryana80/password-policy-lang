// Command passpolicy parses a password policy document, optionally
// pretty-prints it in canonical form, and checks a password against it.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/ryana80/password-policy-lang/policy"
)

func main() {
	pretty := flag.Bool("pretty", false, "print the policy back in its canonical form and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-pretty] <policy-file> [password]\n", os.Args[0])
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
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		os.Exit(1)
	}
	source := string(data)

	pol, err := policy.Parse(source)
	if err != nil {
		if perr, ok := err.(*policy.ParseError); ok {
			fmt.Fprintf(os.Stderr, "%s:%s\n", path, perr.Explain(source))
		} else {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		}
		os.Exit(1)
	}

	if *pretty {
		fmt.Print(policy.Format(pol))
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

	violations := policy.Check(pol, password)
	if len(violations) == 0 {
		fmt.Println("ok")
		return
	}

	fmt.Println("rejected:")
	for _, v := range violations {
		fmt.Printf("  - %s\n", v.Reason)
	}
	os.Exit(1)
}
