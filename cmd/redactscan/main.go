package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

func run(args []string, out io.Writer) {
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintln(out, version)
		return
	}
	fmt.Fprintln(out, "redactscan")
}

func main() {
	run(os.Args[1:], os.Stdout)
}
