package main

import (
	"fmt"
	"os"

	"depsec/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "depsec: %v\n", err)
		os.Exit(1)
	}
}
